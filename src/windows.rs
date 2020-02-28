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
use std::path::Path;
use std::io::Error as IoError;

use scopeguard::{ScopeGuard, defer};

use super::{HidDeviceInfo, Error};

/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
const MAX_STRING_WCHARS: usize = 0xFFF;

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
    pub fn send_feature_report(&self, data: &[u8]) -> Result<usize, Error> {
        hid_send_feature_report(self, data)
    }

    pub fn get_feature_report(&self, data: &mut [u8]) -> Result<usize, Error> {
        hid_get_feature_report(self, data)
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

fn open_device_ansi(path: LPCSTR, enumerate: bool) -> HANDLE {
    let desired_access = if enumerate { 0 } else { GENERIC_WRITE | GENERIC_READ };
    let share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;

    unsafe {
        CreateFileA(path,
            desired_access,
            share_mode,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
            ptr::null_mut())
    }
}

fn open_device(path: &Path, enumerate: bool) -> HANDLE {
    use std::os::windows::ffi::OsStrExt;
    let desired_access = if enumerate { 0 } else { GENERIC_WRITE | GENERIC_READ };
    let share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;

    let path = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();

    unsafe {
        CreateFileW(path.as_ptr(),
            desired_access,
            share_mode,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
            ptr::null_mut())
    }
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


pub fn hid_init() -> Result<(), Error> { Ok(()) }

pub fn hid_exit() -> Result<(), i32> { Ok(()) }

// TODO: Safety
pub fn hid_enumerate(vendor_id: u16, product_id: u16) -> Result<Vec<HidDeviceInfo>, Error> {
    let mut hid_devices = Vec::new();

    hid_init()?;

    /* Windows objects for interacting with the driver. */
    let interface_class_guid = GUID {Data1: 0x4d1e55b2, Data2: 0xf16f, Data3: 0x11cf, Data4: [0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30] };


    /* Initialize the Windows objects. */
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe {
        std::mem::zeroed()
    };
    devinfo_data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
    let mut device_interface_data: SP_DEVICE_INTERFACE_DATA = unsafe {
        std::mem::zeroed()
    };
    device_interface_data.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;

    /* Get information for all the devices belonging to the HID class. */
    let device_info_set = unsafe {
        SetupDiGetClassDevsA(&interface_class_guid, ptr::null_mut(), ptr::null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    };

    defer! {
        /* Close the device information handle. */
        unsafe { SetupDiDestroyDeviceInfoList(device_info_set) };
    }

    /* Iterate over each device in the HID class, looking for the right one. */

    'big_loop: for device_index in 0.. {
        let mut required_size = 0;

        let res = unsafe {
            SetupDiEnumDeviceInterfaces(device_info_set,
                ptr::null_mut(),
                &interface_class_guid,
                device_index,
                &mut device_interface_data)
        };

        if res == 0 {
            /* A return of FALSE from this function means that
               there are no more devices. */
            break;
        }

        /* Call with 0-sized detail size, and let the function
           tell us how long the detail struct needs to be. The
           size is put in &required_size. */
        let _res = unsafe {
            SetupDiGetDeviceInterfaceDetailA(device_info_set,
                &mut device_interface_data,
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
            SetupDiGetDeviceInterfaceDetailA(device_info_set,
                &mut device_interface_data,
                &mut *device_interface_detail_data,
                required_size,
                ptr::null_mut(),
                ptr::null_mut())
        };

        if res == 0 {
            /* register_error(dev, "Unable to call SetupDiGetDeviceInterfaceDetail");
               Continue to the next device. */
            continue
        }

        /* Make sure this device is of Setup Class "HIDClass" and has a
           driver bound to it. */
        for i in 0.. {
            let mut driver_name_buf = [0u8; 256];

            /* Populate devinfo_data. This function will return failure
               when there are no more interfaces left. */
            let res = unsafe {
                SetupDiEnumDeviceInfo(device_info_set, i, &mut devinfo_data)
            };
            if res == 0 {
                continue 'big_loop;
            }

            let res = unsafe {
                SetupDiGetDeviceRegistryPropertyA(device_info_set, &mut devinfo_data,
                           SPDRP_CLASS, ptr::null_mut(), driver_name_buf.as_mut_ptr(), driver_name_buf.len() as u32, ptr::null_mut())
            };
            if res == 0 {
                continue 'big_loop;
            }

            let driver_name_len = driver_name_buf.iter().position(|v| *v == 0).unwrap_or(driver_name_buf.len());
            let driver_name = &driver_name_buf[..driver_name_len];

            if driver_name == b"HIDClass" {
                /* See if there's a driver bound. */
                let res = unsafe {
                    SetupDiGetDeviceRegistryPropertyA(device_info_set, &mut devinfo_data,
                           SPDRP_DRIVER, ptr::null_mut(), driver_name_buf.as_mut_ptr(), driver_name_buf.len() as u32, ptr::null_mut())
                };
                if res != 0 {
                    break;
                }
            }
        }

        //wprintf(L"HandleName: %s\n", device_interface_detail_data->DevicePath);

        /* Open a handle to the device */
        let write_handle = open_device_ansi(device_interface_detail_data.DevicePath.as_ptr(), true);

        defer! {
            unsafe { CloseHandle(write_handle) };
        }

        /* Check validity of write_handle. */
        if write_handle == INVALID_HANDLE_VALUE {
            /* Unable to open the device. */
            //register_error(dev, "CreateFile");
            continue
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
        if (vendor_id == 0x0 || attrib.VendorID == vendor_id) &&
            (product_id == 0x0 || attrib.ProductID == product_id) {

            const WSTR_LEN: usize = 512;
            let mut wstr = [0; WSTR_LEN]; /* TODO: Determine Size */

            /* VID/PID match. Create the record. */
            let mut cur_dev = HidDeviceInfo::default();

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
            cur_dev.path = CStr::from_bytes_with_nul(&raw_str[..=raw_str_end_idx]).unwrap().to_string_lossy().into_owned();

            /* Serial Number */
            let res = unsafe { HidD_GetSerialNumberString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
            if res != 0 {
                let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
                cur_dev.serial_number = Some(String::from_utf16_lossy(&wstr[..end_pos]));
            }

            /* Manufacturer String */
            let res = unsafe { HidD_GetManufacturerString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
            if res != 0 {
                let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
                cur_dev.manufacturer_string = Some(String::from_utf16_lossy(&wstr[..end_pos]));
            }

            /* Product String */
            let res = unsafe { HidD_GetProductString(write_handle, wstr.as_mut_ptr() as _, wstr.len() as u32 * 2) };
            if res != 0 {
                let end_pos = wstr.iter().position(|v| *v == 0).unwrap_or(wstr.len());
                cur_dev.product_string = Some(String::from_utf16_lossy(&wstr[..end_pos]));
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
            cur_dev.interface_number = -1;
            let interface_component = cur_dev.path.find("&mi_");
            if let Some(interface_component) = interface_component {
                let hex_str_idx = interface_component + 4;
                let hex_str_len = cur_dev.path.bytes().skip(hex_str_idx)
                    .position(|v| match v {
                        b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9' => false,
                        _ => true
                    }).unwrap_or(cur_dev.path.len() - hex_str_idx);
                if let Ok(iface_num) = i32::from_str_radix(&cur_dev.path[hex_str_idx..hex_str_idx + hex_str_len], 16) {
                    cur_dev.interface_number = iface_num;
                }
            }

            hid_devices.push(cur_dev);
        }
    }

    return Ok(hid_devices);
}

pub fn hid_open_path<T: AsRef<Path>>(path: T) -> Result<Box<HidDevice>, Error> {
    hid_init()?;

    let ol_guard = {
        let mut ol: OVERLAPPED = unsafe {
            std::mem::zeroed()
        };
        ol.hEvent = unsafe { CreateEventW(ptr::null_mut(), FALSE, FALSE/* initial state f=nonsignaled*/, ptr::null_mut()) };
        if ol.hEvent.is_null() {
            /* Unable to create event. */
            return Err(Error::IoError {
                source: IoError::last_os_error(),
                fnname: "CreateEventW"
            });
        }

        scopeguard::guard(ol, |ol| {
            unsafe { CloseHandle(ol.hEvent); }
        })
    };

    /* Open a handle to the device */
    let device_handle = {
        let device_handle = open_device(path.as_ref(), false);

        /* Check validity of write_handle. */
        if device_handle == INVALID_HANDLE_VALUE {
            /* Unable to open the device. */
            return Err(Error::IoError {
                source: IoError::last_os_error(),
                fnname: "open_device"
            });
        }

        scopeguard::guard(device_handle, |device_handle| {
            unsafe { CloseHandle(device_handle); }
        })
    };

    /* Set the Input Report buffer size to 64 reports. */
    let res = unsafe { HidD_SetNumInputBuffers(*device_handle, 64) };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_SetNumInputBuffers"
        });
    }

    /* Get the Input Report length for the device. */
    let mut pp_data = ptr::null_mut();
    let res = unsafe { HidD_GetPreparsedData(*device_handle, &mut pp_data) };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_GetPreparsedData"
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
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidP_GetCaps"
        });
    }

    Ok(Box::new(HidDevice {
        device_handle: ScopeGuard::into_inner(device_handle),
        blocking: true,
        output_report_length: caps.OutputReportByteLength,
        input_report_length: caps.InputReportByteLength as usize,
        read_pending: false,
        read_buf: vec![0; caps.InputReportByteLength as usize].into_boxed_slice(),
        ol: ScopeGuard::into_inner(ol_guard)
    }))
}

pub fn hid_write(dev: &mut HidDevice, data: &[u8]) -> Result<usize, Error> {
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
    let buf = if data.len() >= dev.output_report_length as usize {
        /* The user passed the right number of bytes. Use the buffer as-is. */
        data
    } else {
        /* Create a temporary buffer and copy the user's data
           into it, padding the rest with zeros. */
        buf_backing = vec![0; dev.output_report_length as usize];
        buf_backing[..data.len()].copy_from_slice(data);
        &buf_backing[..]
    };

    let res = unsafe { WriteFile(dev.device_handle, buf.as_ptr() as _, buf.len() as u32, ptr::null_mut(), &mut ol) };

    if res == 0 {
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(Error::IoError {
                source: IoError::last_os_error(),
                fnname: "WriteFile"
            });
        }
    }

    /* Wait here until the write is done. This makes
       hid_write() synchronous. */
    let mut bytes_written = 0;
    let res = unsafe { GetOverlappedResult(dev.device_handle, &mut ol, &mut bytes_written, TRUE/*wait*/) };
    if res == 0 {
        /* The Write operation failed. */
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "WriteFile"
        });
    }

    return Ok(bytes_written as usize);
}


pub fn hid_read_timeout(dev: &mut HidDevice, data: &mut [u8], milliseconds: u32) -> Result<usize, Error> {
    /* Copy the handle for convenience. */
    let ev = dev.ol.hEvent;

    if !dev.read_pending {
        /* Start an Overlapped I/O read. */
        dev.read_pending = true;
        for i in &mut dev.read_buf[..] { *i = 0 }
        unsafe { ResetEvent(ev) };
        let mut bytes_read = 0;
        let res = unsafe { ReadFile(dev.device_handle, dev.read_buf.as_mut_ptr() as _, dev.input_report_length as u32, &mut bytes_read, &mut dev.ol) };

        if res == 0 {
            if unsafe { GetLastError() } != ERROR_IO_PENDING {
                /* ReadFile() has failed.
                   Clean up and return error. */
                unsafe { CancelIo(dev.device_handle) };
                dev.read_pending = false;
                return Err(Error::IoError {
                    source: IoError::last_os_error(),
                    fnname: "GetOverlappedResult"
                });
            }
        }
    }

    if milliseconds >= 0 {
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
    let res = unsafe { GetOverlappedResult(dev.device_handle, &mut dev.ol, &mut bytes_read, TRUE/*wait*/) };

    let bytes_read = bytes_read as usize;

    /* Set pending back to false, even if GetOverlappedResult() returned error. */
    dev.read_pending = false;

    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "GetOverlappedResult"
        });
    }

    let mut copy_len = 0;
    if bytes_read > 0 {
        if dev.read_buf[0] == 0x0 {
            /* If report numbers aren't being used, but Windows sticks a report
               number (0x0) on the beginning of the report anyway. To make this
               work like the other platforms, and to make it work more like the
               HID spec, we'll skip over this byte. */
            let bytes_read = bytes_read - 1;
            copy_len = if data.len() > bytes_read { bytes_read } else { data.len() };
            data.copy_from_slice(&dev.read_buf[1..1 + copy_len]);
        } else {
            /* Copy the whole buffer, report number and all. */
            copy_len = if data.len() > bytes_read { bytes_read } else { data.len() };
            data.copy_from_slice(&dev.read_buf[..copy_len]);
        }
    }

    return Ok(copy_len);
}

pub fn hid_read(dev: &mut HidDevice, data: &mut [u8]) -> Result<usize, Error> {
    let timeout = if dev.blocking { INFINITE } else { 0 };
    return hid_read_timeout(dev, data, timeout);
}

pub fn hid_set_nonblocking(dev: &mut HidDevice, nonblock: bool) {
    dev.blocking = !nonblock;
}

pub fn hid_send_feature_report(dev: &HidDevice, data: &[u8]) -> Result<usize, Error>
{
    let res = unsafe {
        HidD_SetFeature(dev.device_handle, data.as_ptr() as _, data.len() as u32)
    };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_SetFeature"
        });
    }

    return Ok(data.len());
}


pub fn hid_get_feature_report(dev: &HidDevice, data: &mut [u8]) -> Result<usize, Error> {
    let mut ol: OVERLAPPED = unsafe {
        std::mem::zeroed()
    };

    let mut bytes_returned = 0;
    let data_ptr = data.as_mut_ptr() as *mut _;
    let res = unsafe {
        DeviceIoControl(dev.device_handle,
            IOCTL_HID_GET_FEATURE,
            data_ptr, data.len() as u32,
            data_ptr, data.len() as u32,
            &mut bytes_returned, &mut ol)
    };

    if res == 0 {
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            /* DeviceIoControl() failed. Return error. */
            return Err(Error::IoError {
                source: IoError::last_os_error(),
                fnname: "Send Feature Report DeviceIoControl"
            });
        }
    }

    /* Wait here until the write is done. This makes
       hid_get_feature_report() synchronous. */
    let res = unsafe {
        GetOverlappedResult(dev.device_handle, &mut ol, &mut bytes_returned, TRUE/*wait*/)
    };
    if res == 0 {
        /* The operation failed. */
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "Send Feature Report GetOverlappedResult"
        });
    }

    /* bytes_returned does not include the first byte which contains the
       report ID. The data buffer actually contains one more byte than
       bytes_returned. */
    bytes_returned += 1;

    return Ok(bytes_returned as usize);
}

pub fn hid_get_manufacturer_string(dev: &mut HidDevice, string: &mut [wchar_t]) -> Result<(), Error>
{
    let res = unsafe {
        HidD_GetManufacturerString(dev.device_handle, string.as_ptr() as _, (size_of::<wchar_t>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
    };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_GetManufacturerString"
        });
    }

    Ok(())
}

pub fn hid_get_product_string(dev: &mut HidDevice, string: &mut [wchar_t]) -> Result<(), Error>
{
    let res = unsafe {
        HidD_GetProductString(dev.device_handle, string.as_ptr() as _, (size_of::<wchar_t>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
    };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_GetProductString"
        });
    }

    Ok(())
}

pub fn hid_get_serial_number_string(dev: &mut HidDevice, string: &mut [wchar_t]) -> Result<(), Error>
{
    let res = unsafe {
        HidD_GetSerialNumberString(dev.device_handle, string.as_ptr() as _, (size_of::<wchar_t>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
    };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_GetSerialNumberString"
        });
    }

    Ok(())
}

pub fn hid_get_indexed_string(dev: &mut HidDevice, string_index: u32, string: &mut [wchar_t]) -> Result<(), Error>
{
    let res = unsafe {
        HidD_GetIndexedString(dev.device_handle, string_index, string.as_ptr() as _, (size_of::<wchar_t>() * min(string.len(), MAX_STRING_WCHARS)) as u32)
    };
    if res == 0 {
        return Err(Error::IoError {
            source: IoError::last_os_error(),
            fnname: "HidD_GetIndexedString"
        });
    }

    Ok(())
}