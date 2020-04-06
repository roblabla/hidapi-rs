use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winnt::*;
use winapi::um::winbase::*;
use winapi::um::fileapi::*;
use winapi::um::ioapiset::*;
use winapi::um::handleapi::*;
use winapi::um::synchapi::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::setupapi::*;
use winapi::shared::minwindef::*;
use winapi::shared::guiddef::GUID;
use winapi::shared::hidsdi::*;
use winapi::shared::hidclass::*;
use winapi::shared::hidpi::*;
use winapi::shared::winerror::*;
use winapi::ctypes::wchar_t;

use core::cmp::min;
use core::ptr;
use core::mem::{size_of, align_of};

use std::alloc;
use std::ffi::CStr;
use std::io::Error as IoError;

use widestring::U16String;

use scopeguard::{ScopeGuard, defer};

use crate::{HidResult, HidError};

/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
const MAX_STRING_WCHARS: usize = 0xFFF;
/* Windows objects for interacting with the driver. */
const INTERFACE_CLASS_GUID: GUID = GUID {Data1: 0x4d1e55b2, Data2: 0xf16f, Data3: 0x11cf, Data4: [0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30] };

const _ENSURE_WCHAR_T_IS_U16: [wchar_t; 1] = [0u16; 1];

pub struct HidDevice {
    device_handle: HANDLE,
    blocking: bool,
    output_report_length: u16,
    input_report_length: usize,
    read_pending: bool,
    read_buf: Box<[u8]>,
    ol: OVERLAPPED,
}

impl HidDevice {
    pub fn write(&self, data: &[u8]) -> HidResult<usize> {
        let mut ol: OVERLAPPED = unsafe {
            std::mem::zeroed()
        };

        let mut buf_backing;

        /* Make sure the right number of bytes are passed to WriteFile. Windows
           expects the number of bytes which are in the _longest_ report (plus
           one for the report number) bytes even if the data is a report
           which is shorter than that. Windows gives us this value in
           caps.OutputReportByteLength. If a user passes in fewer bytes than this,
           create a temporary buffer which is the proper size. */
        let buf = if data.len() >= self.output_report_length as usize {
            /* The user passed the right number of bytes. Use the buffer as-is. */
            data
        } else {
            /* Create a temporary buffer and copy the user's data
               into it, padding the rest with zeros. */
            buf_backing = vec![0; self.output_report_length as usize];
            buf_backing[..data.len()].copy_from_slice(data);
            &buf_backing[..]
        };

        let res = unsafe { WriteFile(self.device_handle, buf.as_ptr() as _, buf.len() as u32, ptr::null_mut(), &mut ol) };

        if res == 0 {
            if unsafe { GetLastError() } != ERROR_IO_PENDING {
                return Err(HidError::HidApiErrorWithCause {
                    cause: Box::new(IoError::last_os_error()),
                    message: "WriteFile".to_string()
                });
            }
        }

        /* Wait here until the write is done. This makes
           hid_write() synchronous. */
        let mut bytes_written = 0;
        let res = unsafe { GetOverlappedResult(self.device_handle, &mut ol, &mut bytes_written, TRUE/*wait*/) };
        if res == 0 {
            /* The Write operation failed. */
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "WriteFile".to_string()
            });
        }

        return Ok(bytes_written as usize);
    }

    pub fn read_timeout(&mut self, data: &mut [u8], milliseconds: u32) -> HidResult<usize> {
        /* Copy the handle for convenience. */
        let ev = self.ol.hEvent;

        if !self.read_pending {
            /* Start an Overlapped I/O read. */
            self.read_pending = true;
            for i in &mut self.read_buf[..] { *i = 0 }
            unsafe { ResetEvent(ev) };
            let mut bytes_read = 0;
            let res = unsafe { ReadFile(self.device_handle, self.read_buf.as_mut_ptr() as _, self.input_report_length as u32, &mut bytes_read, &mut self.ol) };

            if res == 0 {
                if unsafe { GetLastError() } != ERROR_IO_PENDING {
                    /* ReadFile() has failed.
                       Clean up and return error. */
                    unsafe { CancelIo(self.device_handle) };
                    self.read_pending = false;
                    return Err(HidError::HidApiErrorWithCause {
                        cause: Box::new(IoError::last_os_error()),
                        message: "GetOverlappedResult".to_string()
                    });
                }
            }
        }

        if milliseconds != INFINITE {
            /* See if there is any data yet. */
            let res = unsafe { WaitForSingleObject(ev, milliseconds) };
            if res != WAIT_OBJECT_0 {
                /* There was no data this time. Return zero bytes available,
                   but leave the Overlapped I/O running. */
                return Ok(0)
            }
        }

        /* Either WaitForSingleObject() told us that ReadFile has completed, or
           we are in non-blocking mode. Get the number of bytes read. The actual
           data has been copied to the data[] array which was passed to ReadFile(). */
        let mut bytes_read = 0;
        let res = unsafe { GetOverlappedResult(self.device_handle, &mut self.ol, &mut bytes_read, TRUE/*wait*/) };

        let bytes_read = bytes_read as usize;

        /* Set pending back to false, even if GetOverlappedResult() returned error. */
        self.read_pending = false;

        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "GetOverlappedResult".to_string()
            });
        }

        let mut copy_len = 0;
        if bytes_read > 0 {
            if self.read_buf[0] == 0x0 {
                /* If report numbers aren't being used, but Windows sticks a report
                   number (0x0) on the beginning of the report anyway. To make this
                   work like the other platforms, and to make it work more like the
                   HID spec, we'll skip over this byte. */
                let bytes_read = bytes_read - 1;
                copy_len = std::cmp::min(data.len(), bytes_read);
                data[..copy_len].copy_from_slice(&self.read_buf[1..1 + copy_len]);
            } else {
                /* Copy the whole buffer, report number and all. */
                copy_len = std::cmp::min(data.len(), bytes_read);
                data[..copy_len].copy_from_slice(&self.read_buf[..copy_len]);
            }
        }

        return Ok(copy_len);
    }

    /// Send a Feature report to the device.
    ///
    /// Feature reports are sent over the Control endpoint as a
    /// Set_Report transfer. The first byte of `data` must contain the
    /// 'Report ID'. For devices which only support a single report, this must
    /// be set to 0x0. The remaining bytes contain the report data. Since the
    /// 'Report ID' is mandatory, calls to `send_feature_report()` will always
    /// contain one more byte than the report contains. For example, if a hid
    /// report is 16 bytes long, 17 bytes must be passed to
    /// `send_feature_report()`: 'the Report ID' (or 0x0, for devices which
    /// do not use numbered reports), followed by the report data (16 bytes).
    /// In this example, the length passed in would be 17.
    pub fn send_feature_report(&self, data: &[u8]) -> HidResult<usize> {
        let res = unsafe {
            HidD_SetFeature(self.device_handle, data.as_ptr() as _, data.len() as u32)
        };
        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                message: "HidD_SetFeature".to_string(),
                cause: Box::new(IoError::last_os_error()),
            });
        }

        return Ok(data.len());
    }

    pub fn get_feature_report(&self, data: &mut [u8]) -> HidResult<usize> {
        let mut ol: OVERLAPPED = unsafe {
            std::mem::zeroed()
        };

        let mut bytes_returned = 0;
        let data_ptr = data.as_mut_ptr() as *mut _;
        let res = unsafe {
            DeviceIoControl(self.device_handle,
                IOCTL_HID_GET_FEATURE,
                data_ptr, data.len() as u32,
                data_ptr, data.len() as u32,
                &mut bytes_returned, &mut ol)
        };

        if res == 0 {
            if unsafe { GetLastError() } != ERROR_IO_PENDING {
                /* DeviceIoControl() failed. Return error. */
                return Err(HidError::HidApiErrorWithCause {
                    cause: Box::new(IoError::last_os_error()),
                    message: "Send Feature Report DeviceIoControl".to_string()
                });
            }
        }

        /* Wait here until the write is done. This makes
           hid_get_feature_report() synchronous. */
        let res = unsafe {
            GetOverlappedResult(self.device_handle, &mut ol, &mut bytes_returned, TRUE/*wait*/)
        };
        if res == 0 {
            /* The operation failed. */
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "Send Feature Report GetOverlappedResult".to_string()
            });
        }

        /* bytes_returned does not include the first byte which contains the
           report ID. The data buffer actually contains one more byte than
           bytes_returned. */
        bytes_returned += 1;

        return Ok(bytes_returned as usize);
    }

    pub fn is_nonblocking(&mut self) -> bool {
        !self.blocking
    }

    pub fn set_nonblocking(&mut self, nonblock: bool) {
        self.blocking = !nonblock;
    }

    pub fn get_manufacturer_string(&self, string: &mut [u16]) -> HidResult<()> {
        let res = unsafe {
            HidD_GetManufacturerString(self.device_handle, string.as_ptr() as _, (size_of::<u16>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
        };
        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "HidD_GetManufacturerString".to_string()
            });
        }

        Ok(())
    }

    pub fn get_product_string(&self, string: &mut [u16]) -> HidResult<()> {
        let res = unsafe {
            HidD_GetProductString(self.device_handle, string.as_ptr() as _, (size_of::<u16>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
        };
        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "HidD_GetProductString".to_string()
            });
        }

        Ok(())
    }

    pub fn get_serial_number_string(&self, string: &mut [u16]) -> HidResult<()>
    {
        let res = unsafe {
            HidD_GetSerialNumberString(self.device_handle, string.as_ptr() as _, (size_of::<u16>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
        };
        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "HidD_GetSerialNumberString".to_string()
            });
        }

        Ok(())
    }

    pub fn get_indexed_string(&self, string_index: i32, string: &mut [u16]) -> HidResult<()>
    {
        let res = unsafe {
            HidD_GetIndexedString(self.device_handle, string_index as u32, string.as_ptr() as _, (size_of::<u16>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
        };
        if res == 0 {
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "HidD_GetIndexedString".to_string()
            });
        }

        Ok(())
    }
}

impl Drop for HidDevice {
    fn drop(&mut self) {
        unsafe {
            CancelIo(self.device_handle);
            CloseHandle(self.ol.hEvent);
            CloseHandle(self.device_handle);
        }
    }
}

/// Opens the given path to a HID device.
///
/// ## Safety
///
/// The path pointer must be valid and end with a `\0`.
unsafe fn open_device(path: LPCSTR, enumerate: bool) -> HANDLE {
    let desired_access = if enumerate { 0 } else { GENERIC_WRITE | GENERIC_READ };
    let share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;

    CreateFileA(path,
        desired_access,
        share_mode,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
        ptr::null_mut())
}

/// Align downwards. Returns the greatest x with alignment `align`
/// so that x <= addr. The alignment must be a power of 2.
fn align_down(addr: u32, align: u32) -> u32 {
    if align.is_power_of_two() {
        addr & !(align - 1)
    } else if align == 0 {
        addr
    } else {
        panic!("`align` must be a power of 2");
    }
}

/// Align upwards. Returns the smallest x with alignment `align`
/// so that x >= addr. The alignment must be a power of 2.
fn align_up(addr: u32, align: u32) -> u32 {
    align_down(addr + align - 1, align)
}

struct HidDeviceIterator {
    device_info_set: HDEVINFO,
    vendor_id: u16,
    product_id: u16,
    device_index: u32
}

impl HidDeviceIterator {
    fn get_device_from_iface_data(&self, device_interface_data: &mut SP_DEVICE_INTERFACE_DATA) -> Option<crate::DeviceInfo> {
        let mut required_size = 0;
        /* Call with 0-sized detail size, and let the function
           tell us how long the detail struct needs to be. The
           size is put in &required_size. */
        let _res = unsafe {
            SetupDiGetDeviceInterfaceDetailA(self.device_info_set,
                device_interface_data,
                ptr::null_mut(),
                0,
                &mut required_size,
                ptr::null_mut())
        };

        /* Allocate a long enough structure for device_interface_detail_data. */
        let align = align_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_A>();
        let required_size = align_up(required_size, align as u32);
        let alloc_layout = alloc::Layout::from_size_align(required_size as usize, align).unwrap();
        // TODO: Check return value from alloc_zeroed.
        let mut device_interface_detail_data = unsafe {
            Box::from_raw(alloc::alloc_zeroed(alloc_layout) as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_A)
        };
        device_interface_detail_data.cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_A>() as u32;

        /* Get the detailed data for this device. The detail data gives us
           the device path for this device, which is then passed into
           CreateFile() to get a handle to the device. */
        let res = unsafe {
            SetupDiGetDeviceInterfaceDetailA(self.device_info_set,
                device_interface_data,
                &mut *device_interface_detail_data,
                required_size,
                ptr::null_mut(),
                ptr::null_mut())
        };

        if res == 0 {
            /* register_error(dev, "Unable to call SetupDiGetDeviceInterfaceDetail");
               Continue to the next device. */
            return None
        }

        /* Make sure this device is of Setup Class "HIDClass" and has a
           driver bound to it. */
        for i in 0.. {
            if i == u32::max_value() {
                return None;
            }

            let mut driver_name_buf = [0u8; 256];

            /* Populate devinfo_data. This function will return failure
               when there are no more interfaces left. */
            /* Initialize the Windows objects. */
            let mut devinfo_data: SP_DEVINFO_DATA = unsafe {
                std::mem::zeroed()
            };
            devinfo_data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            let res = unsafe {
                SetupDiEnumDeviceInfo(self.device_info_set, i, &mut devinfo_data)
            };
            if res == 0 {
                return None;
            }

            let res = unsafe {
                SetupDiGetDeviceRegistryPropertyA(self.device_info_set, &mut devinfo_data,
                           SPDRP_CLASS, ptr::null_mut(), driver_name_buf.as_mut_ptr(), driver_name_buf.len() as u32, ptr::null_mut())
            };
            if res == 0 {
                return None;
            }

            let driver_name_len = driver_name_buf.iter().position(|v| *v == 0).unwrap_or(driver_name_buf.len());
            let driver_name = &driver_name_buf[..driver_name_len];

            if driver_name == b"HIDClass" {
                /* See if there's a driver bound. */
                let res = unsafe {
                    SetupDiGetDeviceRegistryPropertyA(self.device_info_set, &mut devinfo_data,
                           SPDRP_DRIVER, ptr::null_mut(), driver_name_buf.as_mut_ptr(), driver_name_buf.len() as u32, ptr::null_mut())
                };
                if res != 0 {
                    break;
                }
            }
        }


        /* Open a handle to the device */
        let write_handle = unsafe {
            // Safety: DevicePath is guaranteed to be valid and end with a \0,
            // since it comes from windows api.
            open_device(device_interface_detail_data.DevicePath.as_ptr(), true)
        };

        defer! {
            unsafe { CloseHandle(write_handle) };
        }

        /* Check validity of write_handle. */
        if write_handle == INVALID_HANDLE_VALUE {
            /* Unable to open the device. */
            //register_error(dev, "CreateFile");
            return None
        }

        /* Get the Vendor ID and Product ID for this device. */
        let mut attrib: HIDD_ATTRIBUTES = unsafe { std::mem::zeroed() };
        attrib.Size = size_of::<HIDD_ATTRIBUTES>() as u32;
        unsafe {
            HidD_GetAttributes(write_handle, &mut attrib as _)
        };
        //wprintf(L"Product/Vendor: %x %x\n", attrib.ProductID, attrib.VendorID);

        /* Check the VID/PID to see if we should add this
           device to the enumeration list. */
        if !(self.vendor_id == 0x0 || attrib.VendorID == self.vendor_id) &&
            (self.product_id == 0x0 || attrib.ProductID == self.product_id) {
            return None;
        }

        const WSTR_LEN: usize = 512;
        let mut wstr = [0; WSTR_LEN]; /* TODO: Determine Size */

        /* VID/PID match. Create the record. */
        let mut cur_dev = crate::DeviceInfo::new();

        /* Get the Usage Page and Usage for this device. */
        let mut pp_data: PHIDP_PREPARSED_DATA = ptr::null_mut();
        let res = unsafe {
            HidD_GetPreparsedData(write_handle, &mut pp_data)
        };
        if res != 0 {
            let mut caps = unsafe { std::mem::zeroed() };
            let nt_res = unsafe { HidP_GetCaps(pp_data, &mut caps) };
            if nt_res == HIDP_STATUS_SUCCESS {
                cur_dev.usage_page = caps.UsagePage;
                cur_dev.usage = caps.Usage;
            }

            unsafe { HidD_FreePreparsedData(pp_data) };
        }

        /* Fill out the record */
        let s = device_interface_detail_data.DevicePath.as_mut_ptr() as *mut u8;
        let raw_str = unsafe { core::slice::from_raw_parts_mut(s, required_size as usize - 4) };
        let raw_str_end_idx = raw_str.iter().position(|v| *v == 0)
            .unwrap_or_else(|| {
                raw_str[raw_str.len() - 1] = 0;
                raw_str.len() - 1
            });
        cur_dev.path = CStr::from_bytes_with_nul(&raw_str[..=raw_str_end_idx]).unwrap().into();

        /* Serial Number */
        let res = unsafe { HidD_GetSerialNumberString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
        if res != 0 {
            let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
            cur_dev.serial_number = U16String::from_vec(&wstr[..end_pos]);
        }

        /* Manufacturer String */
        let res = unsafe { HidD_GetManufacturerString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
        if res != 0 {
            let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
            cur_dev.manufacturer_string = U16String::from_vec(&wstr[..end_pos]);
        }

        /* Product String */
        let res = unsafe { HidD_GetProductString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
        if res != 0 {
            let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
            cur_dev.product_string = U16String::from_vec(&wstr[..end_pos]);
        }

        /* VID/PID */
        cur_dev.vendor_id = attrib.VendorID;
        cur_dev.product_id = attrib.ProductID;

        /* Release Number */
        cur_dev.release_number = attrib.VersionNumber;

        /* Interface Number. It can sometimes be parsed out of the path
           on Windows if a device has multiple interfaces. See
           http://msdn.microsoft.com/en-us/windows/hardware/gg487473 or
           search for "Hardware IDs for HID Devices" at MSDN. If it's not
           in the path, it's set to -1. */

        fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            haystack.windows(needle.len()).position(|window| window == needle)
        }
        cur_dev.interface_number = -1;
        let interface_component = find_subsequence(cur_dev.path.to_bytes(), b"&mi_");
        if let Some(interface_component) = interface_component {
            let hex_str_idx = interface_component + 4;
            let hex_str_len = cur_dev.path.to_bytes().iter().skip(hex_str_idx)
                .position(|v| match v {
                    b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9' => false,
                    _ => true
                }).unwrap_or(cur_dev.path.to_bytes().len() - hex_str_idx);
            if let Ok(iface_num) = i32::from_str_radix(std::str::from_utf8(&cur_dev.path.to_bytes()[hex_str_idx..hex_str_idx + hex_str_len]).unwrap(), 16) {
                cur_dev.interface_number = iface_num;
            }
        }

        Some(cur_dev)
    }
}

impl Iterator for HidDeviceIterator {
    type Item = crate::DeviceInfo;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.device_index == u32::max_value() {
                return None;
            }

            let mut device_interface_data: SP_DEVICE_INTERFACE_DATA = unsafe {
                std::mem::zeroed()
            };
            device_interface_data.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;

            let res = unsafe {
                SetupDiEnumDeviceInterfaces(self.device_info_set,
                    ptr::null_mut(),
                    &INTERFACE_CLASS_GUID,
                    self.device_index,
                    &mut device_interface_data)
            };

            if res == 0 {
                /* A return of FALSE from this function means that
                   there are no more devices. */
                self.device_index = u32::max_value();
                return None;
            }


            let result = self.get_device_from_iface_data(&mut device_interface_data);
            self.device_index += 1;

            if let Some(device) = result {
                return Some(device)
            }
        }
    }
}

impl Drop for HidDeviceIterator {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.device_info_set);
            self.device_info_set = ptr::null_mut();
        }
    }
}

// TODO: Safety
pub fn hid_enumerate(vendor_id: u16, product_id: u16) -> impl Iterator<Item = crate::DeviceInfo> {
    /* Get information for all the devices belonging to the HID class. */
    let device_info_set = unsafe {
        SetupDiGetClassDevsA(&INTERFACE_CLASS_GUID, ptr::null_mut(), ptr::null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    };

    HidDeviceIterator {
        device_info_set: device_info_set,
        vendor_id: vendor_id,
        product_id: product_id,
        device_index: 0
    }
}

pub fn hid_open_path(path: &CStr) -> HidResult<HidDevice> {
    let ol_guard = {
        let mut ol: OVERLAPPED = unsafe {
            std::mem::zeroed()
        };
        ol.hEvent = unsafe { CreateEventW(ptr::null_mut(), FALSE, FALSE/* initial state f=nonsignaled*/, ptr::null_mut()) };
        if ol.hEvent.is_null() {
            /* Unable to create event. */
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "CreateEventW".to_string()
            });
        }

        scopeguard::guard(ol, |ol| {
            unsafe { CloseHandle(ol.hEvent); }
        })
    };

    /* Open a handle to the device */
    let device_handle = {
        let device_handle = unsafe { open_device(path.as_ptr() as LPCSTR, false) };

        /* Check validity of write_handle. */
        if device_handle == INVALID_HANDLE_VALUE {
            /* Unable to open the device. */
            return Err(HidError::HidApiErrorWithCause {
                cause: Box::new(IoError::last_os_error()),
                message: "open_device".to_string()
            });
        }

        scopeguard::guard(device_handle, |device_handle| {
            unsafe { CloseHandle(device_handle); }
        })
    };

    /* Set the Input Report buffer size to 64 reports. */
    let res = unsafe { HidD_SetNumInputBuffers(*device_handle, 64) };
    if res == 0 {
        return Err(HidError::HidApiErrorWithCause {
            cause: Box::new(IoError::last_os_error()),
            message: "HidD_SetNumInputBuffers".to_string()
        });
    }

    /* Get the Input Report length for the device. */
    let mut pp_data = ptr::null_mut();
    let res = unsafe { HidD_GetPreparsedData(*device_handle, &mut pp_data) };
    if res == 0 {
        return Err(HidError::HidApiErrorWithCause {
            cause: Box::new(IoError::last_os_error()),
            message: "HidD_GetPreparsedData".to_string()
        });
    }

    defer! {
        unsafe {
            HidD_FreePreparsedData(pp_data);
        }
    }

    let mut caps: HIDP_CAPS = unsafe { std::mem::zeroed() };
    let nt_res = unsafe { HidP_GetCaps(pp_data, &mut caps) };

    if nt_res != HIDP_STATUS_SUCCESS {
        return Err(HidError::HidApiErrorWithCause {
            cause: Box::new(IoError::last_os_error()),
            message: "HidP_GetCaps".to_string()
        });
    }

    Ok(HidDevice {
        device_handle: ScopeGuard::into_inner(device_handle),
        blocking: true,
        output_report_length: caps.OutputReportByteLength,
        input_report_length: caps.InputReportByteLength as usize,
        read_pending: false,
        read_buf: vec![0; caps.InputReportByteLength as usize].into_boxed_slice(),
        ol: ScopeGuard::into_inner(ol_guard)
    })
}