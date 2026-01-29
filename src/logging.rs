#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum LogLevel {
    Error = 0,
    Info = 1,
    Debug = 2,
    Trace = 3,
}

pub static LOG_LEVEL: LogLevel = LogLevel::Error;

#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        if $level <= crate::logging::LOG_LEVEL {
            println!($($arg)*);
        }
    };
}