use std::error::Error;

#[derive(Debug)]
pub enum HidError {
    HidApiError { message: String },
    HidApiErrorWithCause { message: String, cause: Box<dyn Error + Send + Sync> },
    HidApiErrorEmptyWithCause { cause: Box<dyn Error + Send + Sync> },
    HidApiErrorEmpty,
    InitializationError,
    OpenHidDeviceError,
    InvalidZeroSizeData,
    IncompleteSendError { sent: usize, all: usize },
    SetBlockingModeError { mode: &'static str },
    OpenHidDeviceWithDeviceInfoError { device_info: Box<crate::DeviceInfo> }
}
impl std::fmt::Display for HidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HidError::HidApiError { message } => write!(f, "hidapi error: {}", message),
            HidError::HidApiErrorWithCause { message, cause } => write!(
                f,
                "hidapi error: {}, caused by: {}",
                message, cause
            ),
            HidError::HidApiErrorEmptyWithCause { cause } => write!(
                f,
                "hidapi error: (could not get error message), caused by: {}",
                cause
            ),
            HidError::HidApiErrorEmpty => write!(f, "hidapi error: (could not get error message)"),
            HidError::InitializationError => {
                write!(f, "Failed to initialize hidapi (maybe initialized before?)")
            }
            HidError::OpenHidDeviceError => write!(f, "Failed opening hid device"),
            HidError::InvalidZeroSizeData => write!(f, "Invalid data: size can not be 0"),
            HidError::IncompleteSendError { sent, all } => write!(
                f,
                "Failed to send all data: only sent {} out of {} bytes",
                sent, all
            ),
            HidError::SetBlockingModeError { mode } => {
                write!(f, "Can not set blocking mode to '{}'", mode)
            }
            HidError::OpenHidDeviceWithDeviceInfoError { device_info } => {
                write!(f, "Can not open hid device with: {:?}", *device_info)
            }
        }
    }
}


impl std::error::Error for HidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HidError::HidApiErrorWithCause { cause, .. } => Some(cause.as_ref()),
            HidError::HidApiErrorEmptyWithCause { cause, .. } => Some(cause.as_ref()),
            _ => None
        }
    }
}

pub type HidResult<T> = Result<T, HidError>;