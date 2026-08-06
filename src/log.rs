#[cfg(feature = "log")]
pub(crate) use log::{debug, error};

#[cfg(feature = "log_stdout")]
macro_rules! _debug {
    (target: $target:expr, $($arg:tt)+) => {println!($($arg)+)};
    ($($arg:tt)+) => {println!($($arg)+)};
}

#[cfg(feature = "log_stdout")]
macro_rules! _info {
    (target: $target:expr, $($arg:tt)+) => {println!($($arg)+)};
    ($($arg:tt)+) => {println!($($arg)+)};
}

#[cfg(feature = "log_stdout")]
macro_rules! _error {
    (target: $target:expr, $($arg:tt)+) => {println!($($arg)+)};
    ($($arg:tt)+) => {println!($($arg)+)};
}

#[cfg(feature = "log_stdout")]
pub(crate) use {_debug as debug, _info as info, _error as error};


#[cfg(all(not(feature = "log"), not(feature = "log_stdout")))]
macro_rules! _debug {
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}

#[cfg(all(not(feature = "log"), not(feature = "log_stdout")))]
macro_rules! _error {
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}

#[cfg(all(not(feature = "log"), not(feature = "log_stdout")))]
macro_rules! _info {
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}

#[cfg(all(not(feature = "log"), not(feature = "log_stdout")))]
pub(crate) use {_debug as debug, _info as info, _error as error};
