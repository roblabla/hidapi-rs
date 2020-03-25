use crate::DeviceInfo;
use crate::{HidResult, HidError};

use std::sync::Mutex;

use io_kit_sys::*;
use io_kit_sys::keys::*;
use io_kit_sys::hid::base::*;
use io_kit_sys::hid::device::*;
use io_kit_sys::hid::keys::*;
use io_kit_sys::hid::manager::*;
use io_kit_sys::usb::usb_spec::*;
use core_foundation_sys::array::*;
use core_foundation_sys::base::*;
use core_foundation_sys::dictionary::*;
use core_foundation_sys::string::*;
use core_foundation_sys::number::*;
use core_foundation_sys::set::*;
use core_foundation_sys::runloop::*;
use std::ffi::{CStr, CString};
use widestring::U16String;
use scopeguard::ScopeGuard;

pub struct HidDevice {
    device_handle: IOHIDDeviceRef,
    blocking: bool,
    uses_numbered_reports: bool,
    disconnected: bool,
    //run_loop_mode: CFStringRef,
    //run_loop: CFRunLoopRef,
    //source: CFRunLoopSourceRef,
    max_input_report_len: usize,
    input_report: Mutex<Vec<Vec<u8>>>,

    //thread: Thread,
    //condition: Condvar,
    // Ensures correct startup sequence
    //barrier: Barrier,
    //shutdown_barrier: Barrier, /* Ensures correct shutdown sequence */
    //shutdown_thread: bool,
}

impl HidDevice {
    fn get_report(&self, ty: IOHIDReportType, data: &mut [u8]) -> HidResult<usize> {
        let report_id = data[0];
        let mut report = data;

        if report_id == 0x0 {
            /* Not using numbered Reports.
               Don't send the report number. */
            report = &mut report[1..];
        }

        /* Avoid crash if the device has been unplugged. */
        if self.disconnected {
            return Err(HidError::HidApiError { message: "Attempted to get_report on an unplugged device.".to_string() });
        }

        let mut report_len = report.len() as isize;

        let res = unsafe { IOHIDDeviceGetReport(self.device_handle,
                                   ty,
                                   report_id as isize,
                                   report.as_mut_ptr(), &mut report_len) };

        if res == 0 /*kIOReturnSuccess*/ {
            if report_id == 0x0 { // 0 report number still present at the beginning
                report_len += 1;
            }
            return Ok(report_len as usize);
        }

        return Err(HidError::HidApiError { message: "IOHIDDeviceGetReport: failed to get report".to_string() });
    }


    fn set_report(&self, ty: IOHIDReportType, data: &[u8]) -> HidResult<usize> {
        let report_id = data[0];

        let mut data_to_send = data;
        if report_id == 0x0 {
            /* Not using numbered Reports.
               Don't send the report number. */
            data_to_send = &data[..1];
        }

        /* Avoid crash if the device has been unplugged. */
        if self.disconnected {
            return Err(HidError::HidApiError { message: "Attempted to set_report on an unplugged device.".to_string() });
        }

        let res = unsafe { IOHIDDeviceSetReport(self.device_handle,
                                   ty,
                                   report_id as isize,
                                   data_to_send.as_ptr(), data_to_send.len() as isize) };

        if res == 0 /*kIOReturnSuccess*/ {
            return Ok(data.len());
        }

        return Err(HidError::HidApiError { message: "IOHIDDeviceSetReport: failed to set report".to_string() });
    }

    pub fn write(&self, data: &[u8]) -> HidResult<usize> {
        unimplemented!();
    }

    pub fn read_timeout(&mut self, data: &mut [u8], milliseconds: u32) -> HidResult<usize> {
        unimplemented!();
    }

    pub fn send_feature_report(&self, data: &[u8]) -> HidResult<usize> {
        self.set_report(kIOHIDReportTypeFeature, data)
    }

    pub fn get_feature_report(&self, data: &mut [u8]) -> HidResult<usize> {
        self.get_report(kIOHIDReportTypeFeature, data)
    }

    pub fn is_nonblocking(&mut self) -> bool {
        unimplemented!();
    }

    pub fn set_nonblocking(&mut self, nonblock: bool) {
        unimplemented!();
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
/*

static void free_hid_device(hid_device *dev)
{
    if (!dev)
        return;

    /* Delete any input reports still left over. */
    struct input_report *rpt = dev->input_reports;
    while (rpt) {
        struct input_report *next = rpt->next;
        free(rpt->data);
        free(rpt);
        rpt = next;
    }

    /* Free the string and the report buffer. The check for NULL
       is necessary here as CFRelease() doesn't handle NULL like
       free() and others do. */
    if (dev->run_loop_mode)
        CFRelease(dev->run_loop_mode);
    if (dev->source)
        CFRelease(dev->source);
    free(dev->input_report_buf);

    /* Clean up the thread objects */
    pthread_barrier_destroy(&dev->shutdown_barrier);
    pthread_barrier_destroy(&dev->barrier);
    pthread_cond_destroy(&dev->condition);
    pthread_mutex_destroy(&dev->mutex);

    /* Free the structure itself. */
    free(dev);
}

static    IOHIDManagerRef hid_mgr = 0x0;
*/

fn get_array_property(device: IOHIDDeviceRef, key: CFStringRef) -> CFArrayRef {
    let r = unsafe { IOHIDDeviceGetProperty(device, key) };
    if !r.is_null() && unsafe { CFGetTypeID(r) == CFArrayGetTypeID() } {
        return r as CFArrayRef;
    } else {
        return std::ptr::null_mut();
    }
}

fn get_int_property(device: IOHIDDeviceRef, key: CFStringRef) -> i32 {
    unsafe {
        let r = IOHIDDeviceGetProperty(device, key);
        if !r.is_null() {
            if CFGetTypeID(r) == CFNumberGetTypeID() {
                let mut value = 0;
                CFNumberGetValue(r as CFNumberRef, kCFNumberSInt32Type, &mut value as *mut _ as *mut _);
                return value;
            }
        }
        return 0;
    }
}

fn get_usage_pairs(device: IOHIDDeviceRef) -> CFArrayRef {
    return get_array_property(device, CFSTR(kIOHIDDeviceUsagePairsKey));
}

fn get_vendor_id(device: IOHIDDeviceRef) -> u16 {
    return get_int_property(device, CFSTR(kIOHIDVendorIDKey)) as u16;
}

fn get_product_id(device: IOHIDDeviceRef) -> u16 {
    return get_int_property(device, CFSTR(kIOHIDProductIDKey)) as u16;
}

fn get_max_report_length(device: IOHIDDeviceRef) -> u32 {
    return get_int_property(device, CFSTR(kIOHIDMaxInputReportSizeKey)) as u32;
}

fn get_string_property(device: IOHIDDeviceRef, prop: CFStringRef, buf: &mut [u16]) -> i32 {
    if buf.is_empty() {
        return 0;
    }

    unsafe {
        let s = IOHIDDeviceGetProperty(device, prop) as CFStringRef;

        buf[0] = 0;

        if !s.is_null() {
            let str_len = CFStringGetLength(s);
            let range = CFRange {
                location: 0,
                length: std::cmp::min(str_len, (buf.len() - 1) as isize)
            };
            let mut used_buf_len = 0;

            let chars_copied = CFStringGetBytes(s,
                range,
                kCFStringEncodingUTF16LE,
                b'?',
                false as _,
                buf.as_mut_ptr() as *mut u8,
                ((buf.len() - 1) * std::mem::size_of::<u32>()) as isize,
                &mut used_buf_len);

            buf[chars_copied as usize] = 0;

            return 0;
        } else {
            return -1;
        }
    }
}

pub fn get_serial_number(device: IOHIDDeviceRef, buf: &mut [u16]) -> i32 {
    return get_string_property(device, CFSTR(kIOHIDSerialNumberKey), buf);
}

pub fn get_manufacturer_string(device: IOHIDDeviceRef, buf: &mut [u16]) -> i32 {
    return get_string_property(device, CFSTR(kIOHIDManufacturerKey), buf);
}

pub fn get_product_string(device: IOHIDDeviceRef, buf: &mut [u16]) -> i32 {
    return get_string_property(device, CFSTR(kIOHIDProductKey), buf);
}

/*/* Implementation of wcsdup() for Mac. */
static wchar_t *dup_wcs(const wchar_t *s)
{
    size_t len = wcslen(s);
    wchar_t *ret = (wchar_t*) malloc((len+1)*sizeof(wchar_t));
    wcscpy(ret, s);

    return ret;
}

/* hidapi_IOHIDDeviceGetService()
 *
 * Return the io_service_t corresponding to a given IOHIDDeviceRef, either by:
 * - on OS X 10.6 and above, calling IOHIDDeviceGetService()
 * - on OS X 10.5, extract it from the IOHIDDevice struct
 */
static io_service_t hidapi_IOHIDDeviceGetService(IOHIDDeviceRef device)
{
    static void *iokit_framework = NULL;
    typedef io_service_t (*dynamic_IOHIDDeviceGetService_t)(IOHIDDeviceRef device);
    static dynamic_IOHIDDeviceGetService_t dynamic_IOHIDDeviceGetService = NULL;

    /* Use dlopen()/dlsym() to get a pointer to IOHIDDeviceGetService() if it exists.
     * If any of these steps fail, dynamic_IOHIDDeviceGetService will be left NULL
     * and the fallback method will be used.
     */
    if (iokit_framework == NULL) {
        iokit_framework = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);

        if (iokit_framework != NULL)
            dynamic_IOHIDDeviceGetService = (dynamic_IOHIDDeviceGetService_t) dlsym(iokit_framework, "IOHIDDeviceGetService");
    }

    if (dynamic_IOHIDDeviceGetService != NULL) {
        /* Running on OS X 10.6 and above: IOHIDDeviceGetService() exists */
        return dynamic_IOHIDDeviceGetService(device);
    }
    else
    {
        /* Running on OS X 10.5: IOHIDDeviceGetService() doesn't exist.
         *
         * Be naughty and pull the service out of the IOHIDDevice.
         * IOHIDDevice is an opaque struct not exposed to applications, but its
         * layout is stable through all available versions of OS X.
         * Tested and working on OS X 10.5.8 i386, x86_64, and ppc.
         */
        struct IOHIDDevice_internal {
            /* The first field of the IOHIDDevice struct is a
             * CFRuntimeBase (which is a private CF struct).
             *
             * a, b, and c are the 3 fields that make up a CFRuntimeBase.
             * See http://opensource.apple.com/source/CF/CF-476.18/CFRuntime.h
             *
             * The second field of the IOHIDDevice is the io_service_t we're looking for.
             */
            uintptr_t a;
            uint8_t b[4];
#if __LP64__
            uint32_t c;
#endif
            io_service_t service;
        };
        struct IOHIDDevice_internal *tmp = (struct IOHIDDevice_internal *) device;

        return tmp->service;
    }
}

/* Initialize the IOHIDManager. Return 0 for success and -1 for failure. */
static int init_hid_manager(void)
{
    /* Initialize all the HID Manager Objects */
    hid_mgr = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (hid_mgr) {
        IOHIDManagerSetDeviceMatching(hid_mgr, NULL);
        IOHIDManagerScheduleWithRunLoop(hid_mgr, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        return 0;
    }

    return -1;
}

/* Initialize the IOHIDManager if necessary. This is the public function, and
   it is safe to call this function repeatedly. Return 0 for success and -1
   for failure. */
int HID_API_EXPORT hid_init(void)
{
    if (!hid_mgr) {
        return init_hid_manager();
    }

    /* Already initialized. */
    return 0;
}

int HID_API_EXPORT hid_exit(void)
{
    if (hid_mgr) {
        /* Close the HID manager. */
        IOHIDManagerClose(hid_mgr, kIOHIDOptionsTypeNone);
        CFRelease(hid_mgr);
        hid_mgr = NULL;
    }

    return 0;
}

static void process_pending_events(void) {
    SInt32 res;
    do {
        res = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.001, FALSE);
    } while(res != kCFRunLoopRunFinished && res != kCFRunLoopRunTimedOut);
}
*/
fn create_device_info_with_usage(dev: IOHIDDeviceRef, usage_page: u32, usage: u32) -> Option<DeviceInfo> {
    let mut cur_dev = DeviceInfo::new();

    cur_dev.vendor_id = get_vendor_id(dev);
    cur_dev.product_id = get_product_id(dev);

    /* Fill in the path (IOService plane) */
    let iokit_dev = unsafe { IOHIDDeviceGetService(dev) };
    let mut path = [0u8; 512];
    let res = unsafe { IORegistryEntryGetPath(iokit_dev, kIOServicePlane as _, path.as_mut_ptr() as _) };
    cur_dev.path = if res == 0 /*KERN_SUCCESS*/ {
        let end = path.iter().position(|v| *v == b'\0').unwrap_or(path.len());
        CString::new(&path[..end]).unwrap()
    } else {
        CString::default()
    };

    const BUF_LEN: usize = 256;
    let mut buf = [0u16; BUF_LEN];
    /* Serial Number */
    get_serial_number(dev, &mut buf[..]);
    let end_pos = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
    cur_dev.serial_number = U16String::from_vec(&buf[..end_pos]);

    /* Manufacturer and Product strings */
    get_manufacturer_string(dev, &mut buf[..]);
    let end_pos = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
    cur_dev.manufacturer_string = U16String::from_vec(&buf[..end_pos]);
    get_product_string(dev, &mut buf[..]);
    let end_pos = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
    cur_dev.product_string = U16String::from_vec(&buf[..end_pos]);

    /* Release Number */
    cur_dev.release_number = get_int_property(dev, CFSTR(kIOHIDVersionNumberKey)) as _;

    /* Interface Number */
    /* We can only retrieve the interface number for USB HID devices.
     * IOKit always seems to return 0 when querying a standard USB device
     * for its interface. */
    let is_usb_hid = get_int_property(dev, CFSTR(kUSBInterfaceClass)) == 3/*kUSBHIDClass*/;
    if is_usb_hid {
        /* Get the interface number */
        cur_dev.interface_number = get_int_property(dev, CFSTR(kUSBInterfaceNumber));
    } else {
        cur_dev.interface_number = -1;
    }

    return Some(cur_dev);
}


fn process_pending_events() {
    // Force HID_Manager initialization.
    HID_MGR.with(|_| ());
    loop {
        let res = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.001, false as _) };
        if res == kCFRunLoopRunFinished || res == kCFRunLoopRunTimedOut {
            break
        }
    }
}

struct HidDeviceIterator {
    // Holds the ownership of the IOHIDDeviceRef
    device_set: CFSetRef,
    devices: Vec<IOHIDDeviceRef>,
    cur_device: IOHIDDeviceRef,
    usage_pairs: CFArrayRef,
    usage_pairs_idx: usize,
}

impl Drop for HidDeviceIterator {
    fn drop(&mut self) {
        // First, drop devices to avoid having dangling pointers.
        self.devices = Vec::new();
        self.cur_device = std::ptr::null_mut();
        // Then, drop device_set
        unsafe { CFRelease(self.device_set as _); }
    }
}

impl Iterator for HidDeviceIterator {
    type Item = crate::DeviceInfo;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            loop {
                if self.usage_pairs.is_null() {
                    // Loop ends here.
                    self.cur_device = self.devices.pop()?;

                    self.usage_pairs = get_usage_pairs(self.cur_device);
                    CFRetain(self.usage_pairs as _);
                    self.usage_pairs_idx = 0;

                    if self.usage_pairs.is_null() {
                        // TODO: Get primary usage page.
                        continue;
                    }
                }

                if self.usage_pairs_idx < CFArrayGetCount(self.usage_pairs) as _ {
                    let dict = CFArrayGetValueAtIndex(self.usage_pairs, self.usage_pairs_idx as _) as CFDictionaryRef;
                    self.usage_pairs_idx += 1;
                    let mut usage_page_ref = std::ptr::null();
                    let mut usage_ref = std::ptr::null();
                    let mut usage_page = 0;
                    let mut usage = 0;

                    if CFDictionaryGetValueIfPresent(dict, CFSTR(kIOHIDDeviceUsagePageKey) as _, &mut usage_page_ref as *mut _ as _) == 0 ||
                        CFDictionaryGetValueIfPresent(dict, CFSTR(kIOHIDDeviceUsageKey) as _, &mut usage_ref as *mut _ as _) == 0 ||
                            CFGetTypeID(usage_page_ref) != CFNumberGetTypeID() ||
                            CFGetTypeID(usage_ref) != CFNumberGetTypeID() ||
                            !CFNumberGetValue(usage_page_ref as _, kCFNumberSInt32Type, &mut usage_page as *mut _ as _) ||
                            !CFNumberGetValue(usage_ref as _, kCFNumberSInt32Type, &mut usage as *mut _ as _)
                    {
                            continue;
                    }
                    let next = create_device_info_with_usage(self.cur_device, usage_page, usage);
                    if next.is_some() {
                        return next
                    }
                } else {
                    CFRelease(self.usage_pairs as _);
                    self.usage_pairs = std::ptr::null_mut();
                }
            }
        }
    }
}

thread_local! {
    /* Initialize all the HID Manager Objects */
    static HID_MGR: IOHIDManagerRef = unsafe {
        let hid_mgr = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
        if !hid_mgr.is_null() {
            IOHIDManagerSetDeviceMatching(hid_mgr, std::ptr::null());
            IOHIDManagerScheduleWithRunLoop(hid_mgr, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        }
        hid_mgr
    }
}

pub fn hid_enumerate(vendor_id: u16, product_id: u16) -> impl Iterator<Item = crate::DeviceInfo> {
    // Give the IOHIDManager a chance to update itself
    process_pending_events();
    // Get a list of the Devices
    HID_MGR.with(|hid_mgr| {
        unsafe {
            let mut matching = std::ptr::null_mut();
            if vendor_id != 0 && product_id != 0 {
                matching = CFDictionaryCreateMutable(kCFAllocatorDefault, kIOHIDOptionsTypeNone as _, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

                if !matching.is_null() && vendor_id != 0 {
                    let v = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &vendor_id as *const u16 as _);
                    CFDictionarySetValue(matching, CFSTR(kIOHIDVendorIDKey) as _, v as _);
                    CFRelease(v as _);
                }

                if !matching.is_null() && product_id != 0 {
                    let p = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &product_id as *const u16 as _);
                    CFDictionarySetValue(matching, CFSTR(kIOHIDProductIDKey) as _, p as _);
                    CFRelease(p as _);
                }
            }
            IOHIDManagerSetDeviceMatching(*hid_mgr, matching);
            if !matching.is_null() {
                CFRelease(matching as _);
            }

            let device_set = IOHIDManagerCopyDevices(*hid_mgr);

            /* Convert the list into a C array so we can iterate easily. */
            let num_devices = CFSetGetCount(device_set);
            let mut devices: Vec<IOHIDDeviceRef> = vec![std::ptr::null_mut(); num_devices as usize];
            CFSetGetValues(device_set, devices.as_mut_ptr() as *mut *const _);

            HidDeviceIterator {
                device_set,
                devices,
                cur_device: std::ptr::null_mut(),
                usage_pairs: std::ptr::null_mut(),
                usage_pairs_idx: 0,
            }
        }
    })
}
/*
void  HID_API_EXPORT hid_free_enumeration(struct hid_device_info *devs)
{
    /* This function is identical to the Linux version. Platform independent. */
    struct hid_device_info *d = devs;
    while (d) {
        struct hid_device_info *next = d->next;
        free(d->path);
        free(d->serial_number);
        free(d->manufacturer_string);
        free(d->product_string);
        free(d);
        d = next;
    }
}

hid_device * HID_API_EXPORT hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number)
{
    /* This function is identical to the Linux version. Platform independent. */
    struct hid_device_info *devs, *cur_dev;
    const char *path_to_open = NULL;
    hid_device * handle = NULL;

    devs = hid_enumerate(vendor_id, product_id);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->vendor_id == vendor_id &&
            cur_dev->product_id == product_id) {
            if (serial_number) {
                if (wcscmp(serial_number, cur_dev->serial_number) == 0) {
                    path_to_open = cur_dev->path;
                    break;
                }
            }
            else {
                path_to_open = cur_dev->path;
                break;
            }
        }
        cur_dev = cur_dev->next;
    }

    if (path_to_open) {
        /* Open the device */
        handle = hid_open_path(path_to_open);
    }

    hid_free_enumeration(devs);

    return handle;
}

static void hid_device_removal_callback(void *context, IOReturn result,
                                        void *sender)
{
    /* Stop the Run Loop for this device. */
    hid_device *d = (hid_device*) context;

    d->disconnected = 1;
    CFRunLoopStop(d->run_loop);
}

/* The Run Loop calls this function for each input report received.
   This function puts the data into a linked list to be picked up by
   hid_read(). */
static void hid_report_callback(void *context, IOReturn result, void *sender,
                         IOHIDReportType report_type, uint32_t report_id,
                         uint8_t *report, CFIndex report_length)
{
    struct input_report *rpt;
    hid_device *dev = (hid_device*) context;

    /* Make a new Input Report object */
    rpt = (struct input_report*) calloc(1, sizeof(struct input_report));
    rpt->data = (uint8_t*) calloc(1, report_length);
    memcpy(rpt->data, report, report_length);
    rpt->len = report_length;
    rpt->next = NULL;

    /* Lock this section */
    pthread_mutex_lock(&dev->mutex);

    /* Attach the new report object to the end of the list. */
    if (dev->input_reports == NULL) {
        /* The list is empty. Put it at the root. */
        dev->input_reports = rpt;
    }
    else {
        /* Find the end of the list and attach. */
        struct input_report *cur = dev->input_reports;
        int num_queued = 0;
        while (cur->next != NULL) {
            cur = cur->next;
            num_queued++;
        }
        cur->next = rpt;

        /* Pop one off if we've reached 30 in the queue. This
           way we don't grow forever if the user never reads
           anything from the device. */
        if (num_queued > 30) {
            return_data(dev, NULL, 0);
        }
    }

    /* Signal a waiting thread that there is data. */
    pthread_cond_signal(&dev->condition);

    /* Unlock */
    pthread_mutex_unlock(&dev->mutex);

}

/* This gets called when the read_thread's run loop gets signaled by
   hid_close(), and serves to stop the read_thread's run loop. */
static void perform_signal_callback(void *context)
{
    hid_device *dev = (hid_device*) context;
    CFRunLoopStop(dev->run_loop); /*TODO: CFRunLoopGetCurrent()*/
}

static void *read_thread(void *param)
{
    hid_device *dev = (hid_device*) param;
    SInt32 code;

    /* Move the device's run loop to this thread. */
    IOHIDDeviceScheduleWithRunLoop(dev->device_handle, CFRunLoopGetCurrent(), dev->run_loop_mode);

    /* Create the RunLoopSource which is used to signal the
       event loop to stop when hid_close() is called. */
    CFRunLoopSourceContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.version = 0;
    ctx.info = dev;
    ctx.perform = &perform_signal_callback;
    dev->source = CFRunLoopSourceCreate(kCFAllocatorDefault, 0/*order*/, &ctx);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), dev->source, dev->run_loop_mode);

    /* Store off the Run Loop so it can be stopped from hid_close()
       and on device disconnection. */
    dev->run_loop = CFRunLoopGetCurrent();

    /* Notify the main thread that the read thread is up and running. */
    pthread_barrier_wait(&dev->barrier);

    /* Run the Event Loop. CFRunLoopRunInMode() will dispatch HID input
       reports into the hid_report_callback(). */
    while (!dev->shutdown_thread && !dev->disconnected) {
        code = CFRunLoopRunInMode(dev->run_loop_mode, 1000/*sec*/, FALSE);
        /* Return if the device has been disconnected */
        if (code == kCFRunLoopRunFinished) {
            dev->disconnected = 1;
            break;
        }


        /* Break if The Run Loop returns Finished or Stopped. */
        if (code != kCFRunLoopRunTimedOut &&
            code != kCFRunLoopRunHandledSource) {
            /* There was some kind of error. Setting
               shutdown seems to make sense, but
               there may be something else more appropriate */
            dev->shutdown_thread = 1;
            break;
        }
    }

    /* Now that the read thread is stopping, Wake any threads which are
       waiting on data (in hid_read_timeout()). Do this under a mutex to
       make sure that a thread which is about to go to sleep waiting on
       the condition actually will go to sleep before the condition is
       signaled. */
    pthread_mutex_lock(&dev->mutex);
    pthread_cond_broadcast(&dev->condition);
    pthread_mutex_unlock(&dev->mutex);

    /* Wait here until hid_close() is called and makes it past
       the call to CFRunLoopWakeUp(). This thread still needs to
       be valid when that function is called on the other thread. */
    pthread_barrier_wait(&dev->shutdown_barrier);

    return NULL;
}
*/

/* hid_open_path()
 *
 * path must be a valid path to an IOHIDDevice in the IOService plane
 * Example: "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/EHC1@1D,7/AppleUSBEHCI/PLAYSTATION(R)3 Controller@fd120000/IOUSBInterface@0/IOUSBHIDDriver"
 */
pub fn hid_open_path(device_path: &CStr) -> HidResult<HidDevice> {
    /* Get the IORegistry entry for the given path */
    let entry_guard = {
        let entry = unsafe {
            // This is casting a *const to *mut. This is probably legal because
            // the function on the other side doesn't actually write to the ptr.
            IORegistryEntryFromPath(kIOMasterPortDefault, device_path.to_bytes().as_ptr() as *mut i8)
        };
        if entry == 0 /*MACH_PORT_NULL*/ {
            /* Path wasn't valid (maybe device was removed?) */
            return Err(HidError::OpenHidDeviceError)
        }

        scopeguard::guard(entry, |entry| {
            unsafe { IOObjectRelease(entry); }
        })
    };

    /* Create an IOHIDDevice for the entry */
    let device_handle_guard = {
        let device_handle = unsafe { IOHIDDeviceCreate(kCFAllocatorDefault, *entry_guard) };
        if device_handle.is_null() {
            /* Error creating the HID device */
            return Err(HidError::HidApiError { message: "IOHIDDeviceCreate: failed to create HID device.".to_string() })
        }

        scopeguard::guard(device_handle, |device_handle| {
            unsafe { CFRelease(device_handle as _); }
        })
    };

    /* Open the IOHIDDevice */
    let ret = unsafe { IOHIDDeviceOpen(*device_handle_guard, kIOHIDOptionsTypeSeizeDevice) };
    if ret == 0 /* kIOReturnSuccess */ {
        /* Create the buffers for receiving data */
        //let max_input_report_len = get_max_report_length(*device_handle_guard);
        //let input_report_buf = vec![0; max_input_report_len];

        /* Create the Run Loop Mode for this device.
           printing the reference seems to work. */
        //let s = format!("HIDAPI_%p\0", *device_handle);
        //let run_loop_mode = CFStringCreateWithBytes(std::ptr::null_mut(), s.as_bytes(), s.len(), kCFStringEncodingUTF8, false);

        /* Attach the device to a Run Loop */
        //IOHIDDeviceRegisterInputReportCallback(
        //    device_handle_guard, input_report_buf, max_input_report_len,
        //    &hid_report_callback, dev);
        //IOHIDDeviceRegisterRemovalCallback(dev->device_handle, hid_device_removal_callback, dev);

        /* Start the read thread */
        //pthread_create(&dev->thread, NULL, read_thread, dev);

        /* Wait here for the read thread to be initialized. */
        //pthread_barrier_wait(&dev->barrier);

        return Ok(HidDevice {
            device_handle: ScopeGuard::into_inner(device_handle_guard),
            blocking: true,
            uses_numbered_reports: false,
            disconnected: false,
            //run_loop_mode: CFStringRef,
            //run_loop: CFRunLoopRef,
            //source: CFRunLoopSourceRef,
            max_input_report_len: 0,
            input_report: Mutex::new(Vec::new()),

            //thread: Thread,
            //condition: Condvar,
            //barrier: Barrier,
            //shutdown_barrier; /* Ensures correct shutdown sequence */
            //int shutdown_thread;
        })
    } else {
        return Err(HidError::HidApiError { message: "IOHIDDeviceOpen: failed to open HID device.".into() })
    }
}
/*

int HID_API_EXPORT hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
    return set_report(dev, kIOHIDReportTypeOutput, data, length);
}

/* Helper function, so that this isn't duplicated in hid_read(). */
static int return_data(hid_device *dev, unsigned char *data, size_t length)
{
    /* Copy the data out of the linked list item (rpt) into the
       return buffer (data), and delete the liked list item. */
    struct input_report *rpt = dev->input_reports;
    size_t len = (length < rpt->len)? length: rpt->len;
    memcpy(data, rpt->data, len);
    dev->input_reports = rpt->next;
    free(rpt->data);
    free(rpt);
    return len;
}

int HID_API_EXPORT hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
    int bytes_read = -1;

    /* Lock the access to the report list. */
    pthread_mutex_lock(&dev->mutex);

    /* There's an input report queued up. Return it. */
    if (dev->input_reports) {
        /* Return the first one */
        bytes_read = return_data(dev, data, length);
        goto ret;
    }

    /* Return if the device has been disconnected. */
    if (dev->disconnected) {
        bytes_read = -1;
        goto ret;
    }

    if (dev->shutdown_thread) {
        /* This means the device has been closed (or there
           has been an error. An error code of -1 should
           be returned. */
        bytes_read = -1;
        goto ret;
    }

    /* There is no data. Go to sleep and wait for data. */

    if (milliseconds == -1) {
        /* Blocking */
        int res;
        res = cond_wait(dev, &dev->condition, &dev->mutex);
        if (res == 0)
            bytes_read = return_data(dev, data, length);
        else {
            /* There was an error, or a device disconnection. */
            bytes_read = -1;
        }
    }
    else if (milliseconds > 0) {
        /* Non-blocking, but called with timeout. */
        int res;
        struct timespec ts;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        TIMEVAL_TO_TIMESPEC(&tv, &ts);
        ts.tv_sec += milliseconds / 1000;
        ts.tv_nsec += (milliseconds % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }

        res = cond_timedwait(dev, &dev->condition, &dev->mutex, &ts);
        if (res == 0)
            bytes_read = return_data(dev, data, length);
        else if (res == ETIMEDOUT)
            bytes_read = 0;
        else
            bytes_read = -1;
    }
    else {
        /* Purely non-blocking */
        bytes_read = 0;
    }

ret:
    /* Unlock */
    pthread_mutex_unlock(&dev->mutex);
    return bytes_read;
}

int HID_API_EXPORT hid_read(hid_device *dev, unsigned char *data, size_t length)
{
    return hid_read_timeout(dev, data, length, (dev->blocking)? -1: 0);
}

int HID_API_EXPORT hid_set_nonblocking(hid_device *dev, int nonblock)
{
    /* All Nonblocking operation is handled by the library. */
    dev->blocking = !nonblock;

    return 0;
}

int HID_API_EXPORT HID_API_CALL hid_get_input_report(hid_device *dev, unsigned char *data, size_t length)
{
    return get_report(dev, kIOHIDReportTypeInput, data, length);
}

void HID_API_EXPORT hid_close(hid_device *dev)
{
    if (!dev)
        return;

    /* Disconnect the report callback before close. */
    if (!dev->disconnected) {
        IOHIDDeviceRegisterInputReportCallback(
            dev->device_handle, dev->input_report_buf, dev->max_input_report_len,
            NULL, dev);
        IOHIDDeviceRegisterRemovalCallback(dev->device_handle, NULL, dev);
        IOHIDDeviceUnscheduleFromRunLoop(dev->device_handle, dev->run_loop, dev->run_loop_mode);
        IOHIDDeviceScheduleWithRunLoop(dev->device_handle, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    }

    /* Cause read_thread() to stop. */
    dev->shutdown_thread = 1;

    /* Wake up the run thread's event loop so that the thread can exit. */
    CFRunLoopSourceSignal(dev->source);
    CFRunLoopWakeUp(dev->run_loop);

    /* Notify the read thread that it can shut down now. */
    pthread_barrier_wait(&dev->shutdown_barrier);

    /* Wait for read_thread() to end. */
    pthread_join(dev->thread, NULL);

    /* Close the OS handle to the device, but only if it's not
       been unplugged. If it's been unplugged, then calling
       IOHIDDeviceClose() will crash. */
    if (!dev->disconnected) {
        IOHIDDeviceClose(dev->device_handle, kIOHIDOptionsTypeSeizeDevice);
    }

    /* Clear out the queue of received reports. */
    pthread_mutex_lock(&dev->mutex);
    while (dev->input_reports) {
        return_data(dev, NULL, 0);
    }
    pthread_mutex_unlock(&dev->mutex);
    CFRelease(dev->device_handle);

    free_hid_device(dev);
}

int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_manufacturer_string(dev->device_handle, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_product_string(dev->device_handle, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
    return get_serial_number(dev->device_handle, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
    /* TODO: */

    return 0;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
    /* TODO: */

    return L"hid_error is not implemented yet";
}
*/