//! Date time utilities (a wrapper for crate [`time`] with mocking).

use std::ops::{Add, Sub};

/// Combined date and time (with time offset).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct DateTime(time::OffsetDateTime);

impl std::fmt::Debug for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(not(any(test, feature = "mock-time")))]
impl DateTime {
    /// The current date and time in UTC.
    pub fn now() -> Self {
        Self(time::OffsetDateTime::now_utc())
    }
}

#[cfg(any(test, feature = "mock-time"))]
#[doc(inline)]
pub use self::mock::MockDateTime;

#[cfg(any(test, feature = "mock-time"))]
impl DateTime {
    /// The current date and time in UTC.
    pub fn now() -> Self {
        MockDateTime::now()
    }
}

impl DateTime {
    /// Returns the result of rounding to the nearest multiple of the given duration.
    pub fn round(&self, duration: Duration) -> Self {
        let time_nanos = self.0.unix_timestamp_nanos();
        let duration_nanos = duration.0.whole_nanoseconds();
        let offset_nanos = time_nanos.rem_euclid(duration_nanos);
        let rounded_nanos = if 2 * offset_nanos < duration_nanos.abs() {
            time_nanos - offset_nanos
        } else {
            time_nanos + offset_nanos
        };
        let rounded = time::OffsetDateTime::from_unix_timestamp_nanos(rounded_nanos).unwrap();
        Self(rounded)
    }
}

/// A span of time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Duration(time::Duration);

impl std::fmt::Debug for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl Sub for DateTime {
    type Output = Duration;
    fn sub(self, rhs: Self) -> Self::Output {
        Duration(self.0 - rhs.0)
    }
}

impl Add<Duration> for DateTime {
    type Output = DateTime;
    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub<Duration> for DateTime {
    type Output = DateTime;
    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

#[cfg(any(test, feature = "mock-time"))]
mod mock {
    use std::cell::RefCell;

    use super::{DateTime, Duration};

    thread_local! {
        static NOW: RefCell<Option<DateTime>> = RefCell::new(None);
    }

    /// Mock clock.
    pub struct MockDateTime;

    /// The value of system clock.
    fn system_clock() -> DateTime {
        DateTime(time::OffsetDateTime::now_utc())
    }

    impl MockDateTime {
        /// Returns the current value of mock clock.
        pub fn now() -> DateTime {
            NOW.with_borrow(|now| now.unwrap_or_else(system_clock))
        }

        /// Freeze the mock clock, assigning the value of the system clock.
        pub fn freeze() {
            NOW.with_borrow_mut(|now| {
                *now = Some(system_clock());
            });
        }

        /// Move the mock clock of the current value (and freeze the clock again)
        pub fn advance(duration: Duration) {
            NOW.with_borrow_mut(|now| {
                *now = Some(now.unwrap_or_else(system_clock) + duration);
            });
        }
    }
}
