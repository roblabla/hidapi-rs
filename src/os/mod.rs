#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

use crate::{HidResult, HidError};

/// Open a HID device using a Vendor ID (VID), Product ID (PID) and optionally a
/// serial number.
///
/// If `serial_number` is None, the first device with the specified VID and PID
/// is opened.
pub fn hid_open(vendor_id: u16, product_id: u16, serial_number: Option<&str>) -> HidResult<HidDevice>
{
    for cur_dev in hid_enumerate(vendor_id, product_id) {
        if cur_dev.vendor_id() == vendor_id && cur_dev.product_id() == product_id {
            match (serial_number, cur_dev.serial_number()) {
                (Some(expected_sn), Some(sn)) if sn == expected_sn => {
                    return hid_open_path(&cur_dev.path);
                },
                (None, _) => return hid_open_path(&cur_dev.path),
                _ => ()
            }
        }
    }

    return Err(HidError::HidApiError {
        message: "Device not found".to_string()
    })
}