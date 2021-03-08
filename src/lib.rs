mod error;
pub use error::*;

mod os;

use std::fmt;
use std::ffi::{CString, CStr};
use widestring::U16String;

const STRING_BUF_LEN: usize = 128;
/*
mod internal_api {
    trait DeviceInfo {
        type HidApi: HidApi;
        type HidDevice: HidDevice;
        fn path(&self) -> &CStr;
        fn vendor_id(&self) -> u16;
        fn product_id(&self) -> u16;
        fn serial_number_raw(&self) -> Option<&[wchar_t]>;
        fn release_number(&self) -> u16;
        fn manufacturer_string_raw(&self) -> Option<&[wchar_t]>;
        fn product_string_raw(&self) -> Option<&[wchar_t]>;
        fn usage_page(&self) -> u16;
        fn usage(&self) -> u16;
        fn interface_number(&self) -> i32;
        fn open_device(&self, hidapi: &HidApi) -> HidResult<HidDevice>;
    }

    trait HidDevice {
        fn check_error(&self) -> HidResult<HidError>;
        fn write(&self, data: &[u8]) -> HidResult<usize>;
        fn read(&self, buf: &mut [u8]) -> HidResult<usize>;
        fn read_timeout(&self, buf: &mut [u8], timeout: i32) -> HidResult<usize>;
        fn send_feature_report(&self, data: &[u8]) -> HidResult<()>;
        fn get_feature_report(&self, buf: &mut [u8]) -> HidResult<usize>;
        fn is_nonblocking(&self) -> bool;
        fn set_nonblocking(&self, nonblock: bool) -> HidResult<()>;
        fn get_manufacturer_string(&self) -> HidResult<Option<String>>;
        fn get_product_string(&self) -> HidResult<Option<String>>;
        fn get_serial_number_string(&self) -> HidResult<Option<String>>;
        fn get_indexed_string(&self, index: i32) -> HidResult<Option<String>>;
    }

    impl From<DeviceInfo> for HidDeviceInfo {}


    fn hid_enumerate(&self, vendor_id: u16, product_id: u16) -> Result<impl Iterator<Item = &Self::DeviceInfo>, Error>;
    // Generic implementation available.
    fn hid_open(&self, vid: u16, pid: u16, sn: Option<&str>) -> Result<Self::HidDevice, Error>;
    fn hid_open_path(&self, device_path: &CStr) -> Result<Self::HidDevice, Error>;
    }
}
*/

pub struct HidApi {
    device_list: Vec<DeviceInfo>
}

impl HidApi {
    /// Initializes the HIDAPI.
    ///
    /// Will also initialize the currently available list.
    pub fn new() -> HidResult<HidApi> {
        let device_list = os::hid_enumerate(0, 0).collect::<Vec<DeviceInfo>>();
        Ok(HidApi {
            device_list
        })
    }

    /// Refresh device list and information about them (to access them use `device_list()` method)
    pub fn refresh_devices(&mut self) -> HidResult<()> {
        let device_list = os::hid_enumerate(0, 0).collect::<Vec<DeviceInfo>>();
        self.device_list = device_list;
        Ok(())
    }

    pub fn device_list(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.device_list.iter()
    }

    pub fn open(&self, vid: u16, pid: u16) -> HidResult<HidDevice> {
        Ok(HidDevice {
            internal: Box::new(os::hid_open(vid, pid, None)?)
        })
    }

    pub fn open_serial(&self, vid: u16, pid: u16, sn: &str) -> HidResult<HidDevice> {
        Ok(HidDevice {
            internal: Box::new(os::hid_open(vid, pid, Some(sn))?)
        })
    }

    pub fn open_path(&self, device_path: &CStr) -> HidResult<HidDevice> {
        Ok(HidDevice {
            internal: Box::new(os::hid_open_path(device_path)?)
        })
    }
}

pub struct HidDevice {
    internal: Box<os::HidDevice>
}

impl HidDevice {
    pub fn write(&self, data: &[u8]) -> HidResult<usize> {
        if data.len() == 0 {
            return Err(HidError::InvalidZeroSizeData);
        }

        self.internal.write(data)
    }
    pub fn read(&mut self, buf: &mut [u8]) -> HidResult<usize> {
        let timeout = if self.internal.is_nonblocking() { 0 } else { -1 };
        self.read_timeout(buf, timeout)
    }
    pub fn read_timeout(&mut self, buf: &mut [u8], timeout: i32) -> HidResult<usize> {
        self.internal.read_timeout(buf, timeout as u32)
    }
    pub fn send_feature_report(&self, data: &[u8]) -> HidResult<()> {
        if data.len() == 0 {
            return Err(HidError::InvalidZeroSizeData)
        }
        let res = self.internal.send_feature_report(data)?;
        if res != data.len() {
            Err(HidError::IncompleteSendError {
                sent: res,
                all: data.len()
            })
        } else {
            Ok(())
        }
    }
    pub fn get_feature_report(&self, buf: &mut [u8]) -> HidResult<usize> {
        self.internal.get_feature_report(buf)
    }
    pub fn set_blocking_mode(&mut self, blocking: bool) -> HidResult<()> {
        self.internal.set_nonblocking(blocking);
        Ok(())
    }
    pub fn get_manufacturer_string(&self) -> HidResult<Option<String>> {
        let mut buf = [0; STRING_BUF_LEN];
        self.internal.get_manufacturer_string(&mut buf)?;
        let end = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
        Ok(String::from_utf16(&buf[..end]).ok())
    }
    pub fn get_product_string(&self) -> HidResult<Option<String>> {
        let mut buf = [0; STRING_BUF_LEN];
        self.internal.get_product_string(&mut buf)?;
        let end = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
        Ok(String::from_utf16(&buf[..end]).ok())
    }
    pub fn get_serial_number_string(&self) -> HidResult<Option<String>> {
        let mut buf = [0; STRING_BUF_LEN];
        self.internal.get_serial_number_string(&mut buf)?;
        let end = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
        Ok(String::from_utf16(&buf[..end]).ok())
    }
    pub fn get_indexed_string(&self, index: i32) -> HidResult<Option<String>> {
        let mut buf = [0; STRING_BUF_LEN];
        self.internal.get_indexed_string(index, &mut buf)?;
        let end = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
        Ok(String::from_utf16(&buf[..end]).ok())
    }
}

#[derive(Clone)]
pub struct DeviceInfo {
    path: CString,
    vendor_id: u16,
    product_id: u16,
    serial_number: U16String,
    release_number: u16,
    manufacturer_string: U16String,
    product_string: U16String,
    usage_page: u16,
    usage: u16,
    interface_number: i32,
}

impl fmt::Debug for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DeviceInfo")
            .field("path", &self.path)
            .field("vendor_id", &self.vendor_id)
            .field("product_id", &self.product_id)
            .field("serial_number", &self.serial_number.to_string_lossy())
            .field("release_number", &self.release_number)
            .field("manufacturer_string", &self.manufacturer_string.to_string_lossy())
            .field("product_string", &self.product_string.to_string_lossy())
            .field("usage_page", &self.usage_page)
            .field("usage", &self.usage)
            .field("interface_number", &self.interface_number)
            .finish()
    }
}

impl DeviceInfo {
    fn new() -> DeviceInfo {
        DeviceInfo {
            path: CString::default(),
            vendor_id: 0,
            product_id: 0,
            serial_number: U16String::default(),
            release_number: 0,
            manufacturer_string: U16String::default(),
            product_string: U16String::default(),
            usage_page: 0,
            usage: 0,
            interface_number: 0,
        }
    }
    pub fn path(&self) -> &CStr {
        &self.path
    }
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }
    pub fn product_id(&self) -> u16 {
        self.product_id
    }

    /// Try to call `serial_number_raw()`, if None is returned.
    pub fn serial_number(&self) -> Option<String> {
        self.serial_number.to_string().ok()
    }
    pub fn serial_number_raw(&self) -> &[u16] {
        self.serial_number.as_slice()
    }

    pub fn release_number(&self) -> u16 {
        self.release_number
    }

    /// Try to call `manufacturer_string_raw()`, if None is returned.
    pub fn manufacturer_string(&self) -> Option<String> {
        self.manufacturer_string.to_string().ok()
    }
    pub fn manufacturer_string_raw(&self) -> &[u16] {
        self.manufacturer_string.as_slice()
    }

    /// Try to call `product_string_raw()`, if None is returned.
    pub fn product_string(&self) -> Option<String> {
        self.product_string.to_string().ok()
    }
    pub fn product_string_raw(&self) -> &[u16] {
        self.product_string.as_slice()
    }

    pub fn usage_page(&self) -> u16 {
        self.usage_page
    }
    pub fn usage(&self) -> u16 {
        self.usage
    }
    pub fn interface_number(&self) -> i32 {
        self.interface_number
    }

    /// Use the information contained in `DeviceInfo` to open
    /// and return a handle to a [HidDevice](struct.HidDevice.html).
    ///
    /// By default the device path is used to open the device.
    /// When no path is available, then vid, pid and serial number are used.
    /// If both path and serial number are not available, then this function will
    /// fail with [HidError::OpenHidDeviceWithDeviceInfoError](enum.HidError.html#variant.OpenHidDeviceWithDeviceInfoError).
    ///
    /// Note, that opening a device could still be done using [HidApi::open()](struct.HidApi.html#method.open) directly.
    pub fn open_device(&self, hidapi: &HidApi) -> HidResult<HidDevice> {
        if self.path.as_bytes().len() != 0 {
            hidapi.open_path(self.path.as_c_str())
        } else if let Some(ref sn) = self.serial_number() {
            hidapi.open_serial(self.vendor_id, self.product_id, sn)
        } else {
            Err(HidError::OpenHidDeviceWithDeviceInfoError {
                device_info: Box::new(self.clone()),
            })
        }
    }
}