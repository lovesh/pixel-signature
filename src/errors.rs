/*error_chain! {
    errors {
        MoreThanSupported(T: u128) {
            description("Time more than the maximum supported value")
            display("T should be less than max value for u128 but was : {}", T)
        }
    }
}*/

use failure::Error;

#[derive(Debug, Fail)]
pub enum PixelError {
    #[fail(
        display = "T should be >= 3 and less than max value for u128 but was : {}",
        T
    )]
    InvalidMaxTimePeriod { T: u128 },
    //#[fail(display = "T+1 should be power of 2 but T was : {}", T+1)]
    #[fail(display = "T+1 should be power of 2")]
    NonPowerOfTwo { T: u128 },
    #[fail(display = "Invalid path={:?} for l={}", path, l)]
    InvalidPath { path: Vec<u8>, l: u8 },
    #[fail(display = "Invalid node number={} for l={}", t, l)]
    InvalidNodeNum { t: u128, l: u8 },
    #[fail(display = "Provide at least {} generators", n)]
    NotEnoughGenerators { n: usize },
    #[fail(display = "Sigkey for time t={} not found", t)]
    SigkeyNotFound { t: u128 },
    #[fail(
        display = "Cannot update key to previous time={}, current time={}",
        old_t, current_t
    )]
    SigkeyUpdateBackward { old_t: u128, current_t: u128 },
    #[fail(display = "Sigkey alrady updated to desired time={}", t)]
    SigkeyAlreadyUpdated { t: u128 },
}
