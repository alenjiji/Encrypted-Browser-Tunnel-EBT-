#[derive(PartialEq, PartialOrd)]
pub enum LogLevel {
    Error,
    Info,
    Debug,
    Trace,
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