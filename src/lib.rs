#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// hidapi info structure
#[derive(Debug, Clone, Default)]
pub struct HidDeviceInfo {
    /// Platform-specific device path
    pub path: String,
    /// Device Vendor ID
    pub vendor_id: u16,
    /// Device Product ID
    pub product_id: u16,
    /// Serial Number
    pub serial_number: Option<String>,
    /// Device Release Number in binary-coded decimal, also known as Device
    /// Version Number
    pub release_number: u16,
    /// Manufacturer String
    pub manufacturer_string: Option<String>,
    /// Product String
    pub product_string: Option<String>,
    /// Usage Page for this Device/Interface.
    ///
    /// (Windows/Mac only).
    pub usage_page: u16,
    /// Usage for this Device/Interface.
    ///
    /// (Windows/Mac only).
    pub usage: u16,
    /// The USB interface which this logical device represents. Valid on both
    /// Linux implementations in all cases, and valid on the Windows
    /// implementation only if the device contains more than one interface.
    pub interface_number: i32,
}

impl HidDeviceInfo {
    pub fn open_device(&self, _api: &HidApi) -> Result<Box<HidDevice>, Error> {
        hid_open_path(&self.path)
    }
}

pub struct HidApi {
    devices: Vec<HidDeviceInfo>
}

impl HidApi {
    pub fn new() -> Result<HidApi, Error> {
        Ok(HidApi {
            devices: hid_enumerate(0, 0)?
        })
    }

    pub fn refresh_devices(&mut self) -> Result<(), Error> {
        self.devices = hid_enumerate(0, 0)?;
        Ok(())
    }

    pub fn devices(&self) -> &[HidDeviceInfo] {
        &self.devices[..]
    }
}

/// Open a HID device using a Vendor ID (VID), Product ID (PID) and optionally a
/// serial number.
///
/// If `serial_number` is None, the first device with the specified VID and PID
/// is opened.
pub fn hid_open(vendor_id: u16, product_id: u16, serial_number: Option<&str>) -> Option<Box<HidDevice>>
{
    // TODO: Better error handling
    for cur_dev in hid_enumerate(vendor_id, product_id).unwrap_or(Vec::new()) {
        if cur_dev.vendor_id == vendor_id && cur_dev.product_id == product_id {
            match (serial_number, cur_dev.serial_number) {
                (Some(expected_sn), Some(sn)) if sn == expected_sn => {
                    return hid_open_path(cur_dev.path).ok();
                },
                (None, _) => return hid_open_path(cur_dev.path).ok(),
                _ => ()
            }
        }
    }

    return None
}


#[derive(Debug)]
pub enum Error {
    IoError {
        fnname: &'static str,
        source: std::io::Error
    },
    InitFailed
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError { fnname, source} => {
                write!(f, "Failed to open device: {}: {}", fnname, source)
            },
            Error::InitFailed => write!(f, "Failed to initialize hidapi")
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError { source, .. } => Some(source),
            _ => None
        }
    }
}