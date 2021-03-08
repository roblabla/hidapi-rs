use std::error::Error;
use std::fs::{DirEntry, OpenOptions};
use std::path::Path;
use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::io::{self, Write};

use widestring::U16String;

use crate::{HidResult, HidError};

mod hid;
use hid::*;

pub struct HidDevice {
    device_handle: File,
    blocking: bool,
    uses_numbered_reports: bool,
}

impl HidDevice {
    pub fn write(&self, data: &[u8]) -> HidResult<usize> {
        match (&self.device_handle).write(data) {
            Ok(v) => Ok(v),
            Err(err) => Err(HidError::HidApiErrorWithCause {
                cause: Box::new(err),
                message: "write".to_string()
            })
        }
    }

    pub fn read_timeout(&mut self, data: &mut [u8], milliseconds: u32) -> HidResult<usize> {
        unimplemented!()
    }

    pub fn send_feature_report(&self, data: &[u8]) -> HidResult<usize> {
        match hidiocsfeature(&self.device_handle, data) {
            Ok(_) => Ok(data.len()),
            Err(err) => Err(HidError::HidApiErrorWithCause {
                cause: Box::new(io::Error::last_os_error()),
                message: "hidiocsfeature".to_string()
            })
        }
    }

    pub fn get_feature_report(&self, data: &mut [u8]) -> HidResult<usize> {
        match hidiocgfeature(&self.device_handle, data) {
            Ok(_) => Ok(data.len()),
            Err(err) => Err(HidError::HidApiErrorWithCause {
                cause: Box::new(io::Error::last_os_error()),
                message: "hidiocgfeature".to_string()
            })
        }
    }

    pub fn is_nonblocking(&mut self) -> bool {
        !self.blocking
    }

    pub fn set_nonblocking(&mut self, nonblock: bool) {
        self.blocking = !nonblock;
    }

    pub fn get_manufacturer_string(&self, string: &mut [u16]) -> HidResult<()> {
        unimplemented!();
    }

    pub fn get_product_string(&self, string: &mut [u16]) -> HidResult<()> {
        unimplemented!();
    }

    pub fn get_serial_number_string(&self, string: &mut [u16]) -> HidResult<()> {
        unimplemented!();
    }

    pub fn get_indexed_string(&self, string_index: i32, string: &mut [u16]) -> HidResult<()> {
        unimplemented!();
    }
}

fn parse_uevent(event_path: &Path, event: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in event.split(|v| *v == b'\n') {
        // Ignore last empty line (and other empty lines...)
        if line.is_empty() {
            continue;
        }

        let eq_pos = match line.iter().position(|v| *v == b'=') {
            Some(v) => v,
            // Weird line
            None => {
                log::warn!("Line without '=' in {}", event_path.display());
                continue
            },
        };
        let (key, value) = line.split_at(eq_pos);
        let value = &value[1..];

        match (String::from_utf8(key.to_vec()), String::from_utf8(value.to_vec())) {
            (Ok(k), Ok(v)) => {
                map.insert(k, v);
            },
            _ => log::warn!("Non-utf8 line in {}", event_path.display()),
        }
    }
    map
}

fn get_parent_device_subsystem_devtype<'a>(child: &'a Path, subsystem: &str, devtype: &str) -> Option<&'a Path> {
    let canon_child = child.canonicalize();
    let mut cur = child.parent()?;
    loop {
        let cur_subsystem = cur.join("subsystem");
        let cur_subsystem = cur_subsystem.canonicalize()
            .map_err(|err| { log::warn!("Failed to canonicalize {}: {:?}", cur_subsystem.display(), err); err })
            .ok();
        let cur_subsystem = cur_subsystem.as_ref().and_then(|v| v.file_name());
        let cur_uevent_path = cur.join("uevent");
        let cur_uevent = std::fs::read(&cur_uevent_path)
            .map_err(|err| { log::warn!("Failed to read {}: {:?}", cur_uevent_path.display(), err) })
            .map(|v| parse_uevent(&cur_uevent_path, &v))
            .unwrap_or(HashMap::new());
        let cur_devtype = cur_uevent.get("DEVTYPE");

        if cur_subsystem == Some(OsStr::new(subsystem)) && cur_devtype.map(|v| &**v) == Some(devtype) {
            return Some(cur)
        }

        cur = cur.parent()?;
        if !cur.starts_with("/sys") {
            return None
        }
    }
}

struct UsagesIter<T> {
    hid_items: HidItemIterator<T>,
    pos: usize,
    cur_usage_page: u16,
    cur_usage: Option<u16>,
}

impl<T: AsRef<[u8]>> Iterator for UsagesIter<T> {
    type Item = (u16, u16);
    fn next(&mut self) -> Option<(u16, u16)> {
        while let Some((item, data)) = self.hid_items.next() {
            match (item, data) {
                (HidTy::Global(HidGlobal::UsagePage), HidItem::SmallItem(page)) => {
                    self.cur_usage_page = page as u16;
                },
                (HidTy::Local(HidLocal::Usage), HidItem::SmallItem(usage)) => {
                    self.cur_usage = Some(usage as u16);
                },
                (HidTy::Main(HidMain::Collection), _) => {
                    if let Some(cur_usage) = self.cur_usage.take() {
                        return Some((self.cur_usage_page, cur_usage))
                    } else {
                        log::warn!("Collection without usage!");
                    }
                },
                (HidTy::Main(_), _) => {
                    self.cur_usage = None;
                },
                _ => (),
            }
        }
        None
    }
}

/// Transform a sysfs device entry into a hidapi device.
fn sysfs_to_devinfo(entry: DirEntry) -> Option<Box<dyn Iterator<Item = crate::DeviceInfo>>> {
    let sysfs_path = entry.path();

    // Read /sys/class/hidraw/<device>/uevent to find devnode.
    // TODO: Technically, this doesn't work for /sys/bus stuff :|. Not sure how
    // to fix it though. Can we have a single hidraw devnode for multiple HID
    // devices???
    let sysfs_uevent_path = sysfs_path.join("uevent");
    let sysfs_uevent = std::fs::read(&sysfs_uevent_path)
        .map_err(|err| log::error!("Failed to read {}: {:?}", sysfs_uevent_path.display(), err))
        .ok()?;
    let data = parse_uevent(&sysfs_uevent_path, &sysfs_uevent);
    let devnode = match data.get("DEVNAME") {
        Some(v) => v,
        None => {
            log::error!("No devname for device {}", sysfs_path.display());
            return None;
        }
    };
    let devnode = Path::new("/dev").join(devnode);

    // Read /sys/class/hidraw/<device>/device/uevent to find vid/pid, bus_type,
    // product name and serial number.
    let device_path = sysfs_path.join("device");
    let device_uevent_path = device_path.join("uevent");
    let device_uevent = std::fs::read(&device_uevent_path)
        .map_err(|err| log::error!("Failed to read {}: {:?}", device_uevent_path.display(), err))
        .ok()?;
    let data = parse_uevent(&device_uevent_path, &device_uevent);
    let (bus_type, vid, pid) = data.get("HID_ID")
        .ok_or_else::<Box<dyn Error>, _>(|| format!("No HID_ID in {}", device_uevent_path.display()).into())
        .and_then(|v| {
            let mut hid_id_split = v.split(":");
            let invalid_hid_id = || format!("Invalid HID_ID format in {}", device_uevent_path.display());
            let bus_type = u32::from_str_radix(hid_id_split.next().ok_or_else(invalid_hid_id.clone())?, 16)?;
            let vid = u16::from_str_radix(hid_id_split.next().ok_or_else(invalid_hid_id.clone())?, 16)?;
            let pid = u16::from_str_radix(hid_id_split.next().ok_or_else(invalid_hid_id.clone())?, 16)?;
            Ok((bus_type, vid, pid))
        })
        .map_err(|err| log::error!("Failed to parse HID_ID in {}: {:?}", device_uevent_path.display(), err))
        .ok()?;

    println!("{:?}", data);
    let product_name = data.get("HID_NAME").cloned().unwrap_or_default();
    let serial_number = data.get("HID_UNIQ").cloned().unwrap_or_default();

    let device_report_descriptor_path = device_path.join("report_descriptor");
    let device_report_descriptor = std::fs::read(&device_report_descriptor_path)
        .map_err(|err| log::error!("Failed to read {}: {:?}", device_report_descriptor_path.display(), err))
        .ok()?;

    let mut dev_info = crate::DeviceInfo {
        path: CString::new(devnode.to_str().unwrap()).unwrap(),
        vendor_id: vid,
        product_id: pid,
        serial_number: serial_number.into(),
        release_number: 0,
        manufacturer_string: U16String::default(),
        product_string: product_name.into(),
        usage_page: 0,
        usage: 0,
        interface_number: 0,
    };

    if bus_type == 3 {
        let usb_device = get_parent_device_subsystem_devtype(&sysfs_path, "usb", "usb_device");
        dev_info.manufacturer_string = usb_device.map(|v| v.join("manufacturer"))
            .and_then(|v| std::fs::read_to_string(v).ok())
            .map(|v| U16String::from_str(&v))
            .unwrap_or(dev_info.manufacturer_string);
        dev_info.product_string = usb_device.map(|v| v.join("product"))
            .and_then(|v| std::fs::read_to_string(v).ok())
            .map(|v| U16String::from_str(&v))
            .unwrap_or(dev_info.product_string);

        dev_info.release_number = usb_device.map(|v| v.join("bcdDevice"))
            .and_then(|v| std::fs::read_to_string(v).ok())
            .and_then(|v| u16::from_str_radix(&v, 16).ok())
            .unwrap_or(0);

        dev_info.interface_number = get_parent_device_subsystem_devtype(&sysfs_path, "usb", "usb_interface")
            .map(|v| v.join("bInterfaceNumber"))
            .and_then(|v| std::fs::read_to_string(v).ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
    }

    let usages = UsagesIter {
        hid_items: iterate_hid_descriptor(device_report_descriptor),
        pos: 0,
        cur_usage_page: 0,
        cur_usage: None,
    };

    Some(Box::new(usages.map(move |(usage_page, usage)| {
        let mut dev_info = dev_info.clone();
        dev_info.usage_page = usage_page;
        dev_info.usage = usage;
        dev_info
    })))
}

#[derive(Debug, Clone, Copy)]
enum SysHidrawIteratorState {
    Starting, Subsystem, Class, Bus
}

struct SysHidrawIterator {
    state: SysHidrawIteratorState,
    cur_it: Option<std::fs::ReadDir>,
    devinfo_usages: Option<Box<dyn Iterator<Item = crate::DeviceInfo>>>,
}

impl Iterator for SysHidrawIterator {
    type Item = crate::DeviceInfo;
    fn next(&mut self) -> Option<crate::DeviceInfo> {
        loop {
            // First, check if the cur devinfo iterator has any new devices.
            if let Some(devinfo) = self.devinfo_usages.as_mut().and_then(|mut v| v.next()) {
                return Some(devinfo);
            }

            // Otherwise, get the next entry in the current sysfs node.
            let next = self.cur_it.as_mut().and_then(|v| v.next());
            match (next, &mut self.state) {
                (Some(Ok(v)), _) => {
                    self.devinfo_usages = sysfs_to_devinfo(v);
                },
                (_, state @ SysHidrawIteratorState::Starting) => {
                    *state = SysHidrawIteratorState::Subsystem;
                    self.cur_it = std::fs::read_dir("/sys/subsystem/hidraw").ok();
                }
                (_, state @ SysHidrawIteratorState::Subsystem) => {
                    *state = SysHidrawIteratorState::Class;
                    self.cur_it = std::fs::read_dir("/sys/class/hidraw").ok();
                }
                (_, state @ SysHidrawIteratorState::Class) => {
                    *state = SysHidrawIteratorState::Bus;
                    self.cur_it = std::fs::read_dir("/sys/bus/hidraw").ok();
                }
                (_, SysHidrawIteratorState::Bus) => {
                    return None;
                }
            }
        }
    }
}

pub fn hid_enumerate(vendor_id: u16, product_id: u16) -> impl Iterator<Item = crate::DeviceInfo> {
    SysHidrawIterator {
        devinfo_usages: None,
        state: SysHidrawIteratorState::Starting,
        cur_it: None,
    }
}

pub fn hid_open_path(device_path: &CStr) -> HidResult<HidDevice> {
    let path = OsStr::from_bytes(device_path.to_bytes());
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| HidError::HidApiErrorWithCause {
            message: format!("Failed to open {}", path.to_string_lossy()),
            cause: err.into(),
         })?;

    let mut desc_size = 0;

    let mut desc = Box::new(hidraw_report_descriptor::default());
    desc.size = desc.value.len() as u32;

    hidiocgrdesc(&f, &mut *desc)
        .map_err(|err| HidError::HidApiErrorWithCause {
            message: format!("Failed to call hdiocgrdesc on {}", path.to_string_lossy()),
            cause: err.into(),
        })?;

    let uses_numbered_reports = iterate_hid_descriptor(desc.value)
        .any(|(ty, item)| ty == HidTy::Global(HidGlobal::ReportId));

    Ok(HidDevice {
        device_handle: f,
        blocking: true,
        uses_numbered_reports,
    })
}

const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hidraw_report_descriptor {
    size: u32,
    value: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

impl Default for hidraw_report_descriptor {
    fn default() -> hidraw_report_descriptor {
        hidraw_report_descriptor {
            size: HID_MAX_DESCRIPTOR_SIZE as u32,
            value: [0; HID_MAX_DESCRIPTOR_SIZE],
        }
    }
}

ioctl_sys::ioctl!(read hidiocgrdescsize_raw with b'H', 0x01; c_int);
ioctl_sys::ioctl!(read hidiocgrdesc_raw with b'H', 0x02; hidraw_report_descriptor);

ioctl_sys::ioctl!(readwrite buf hidiocsfeature_raw with b'H', 0x06; u8);
ioctl_sys::ioctl!(readwrite buf hidiocgfeature_raw with b'H', 0x07; u8);

fn hidiocgrdescsize<F: AsRawFd>(f: &F) -> Result<c_int, io::Error> {
    let mut data = 0;
    let ret = unsafe {
        hidiocgrdescsize_raw(f.as_raw_fd(), &mut data)
    };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(data)
    }
}

fn hidiocgrdesc<F: AsRawFd>(f: &F, desc: &mut hidraw_report_descriptor) -> Result<(), io::Error> {
    let ret = unsafe {
        hidiocgrdesc_raw(f.as_raw_fd(), desc)
    };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn hidiocgfeature<F: AsRawFd>(f: &F, desc: &mut [u8]) -> Result<(), io::Error> {
    let ret = unsafe {
        hidiocgfeature_raw(f.as_raw_fd(), desc.as_mut_ptr(), desc.len())
    };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn hidiocsfeature<F: AsRawFd>(f: &F, desc: &[u8]) -> Result<(), io::Error> {
    let ret = unsafe {
        hidiocsfeature_raw(f.as_raw_fd(), desc.as_ptr(), desc.len())
    };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}