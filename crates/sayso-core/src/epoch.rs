//! Epochs and the TTL state machine (spec section 3).
//!
//! All functions take `now` as Unix seconds; nothing here reads a clock.

use core::ops::RangeInclusive;

use crate::{Error, Result};

/// How far a sender's clock may run ahead of an epoch's start.
pub const CLOCK_SKEW: u64 = 3600;

/// How many upcoming epochs the owner keeps published.
pub const LOOKAHEAD: u32 = 4;

/// The three durations fixed by the owner manifest, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochParams {
    /// `L`: length of an epoch.
    pub epoch_len: u64,
    /// `G`: how long after an epoch ends late deliveries are accepted.
    pub grace: u64,
    /// `T`: how long after an epoch ends its drops stay readable.
    pub ttl: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    /// Published ahead of time; not in use yet.
    Scheduled,
    /// Senders seal to it.
    Active,
    /// No longer sealed to; late deliveries still accepted.
    Grace,
    /// Decrypt only.
    Retained,
    /// The secret must no longer exist.
    Shredded,
}

impl Default for EpochParams {
    fn default() -> Self {
        Self {
            epoch_len: 7 * 86_400,
            grace: 2 * 86_400,
            ttl: 30 * 86_400,
        }
    }
}

impl EpochParams {
    pub fn new(epoch_len: u64, grace: u64, ttl: u64) -> Result<Self> {
        let params = Self {
            epoch_len,
            grace,
            ttl,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<()> {
        if self.epoch_len < 3600 {
            return Err(Error::Invalid("epoch length under one hour"));
        }
        if self.grace > self.ttl {
            return Err(Error::Invalid("grace longer than ttl"));
        }
        // Keeps every epoch index within u32 for any 64-bit time.
        if self.ttl > 10 * 365 * 86_400 {
            return Err(Error::Invalid("ttl over ten years"));
        }
        Ok(())
    }

    /// The epoch that contains `now`.
    pub fn epoch_at(&self, now: u64) -> u32 {
        (now / self.epoch_len).min(u32::MAX as u64) as u32
    }

    /// `s`: the first second of epoch `e`.
    pub fn start(&self, e: u32) -> u64 {
        e as u64 * self.epoch_len
    }

    /// The moment the secret of epoch `e` must be destroyed.
    pub fn shred_at(&self, e: u32) -> u64 {
        self.start(e) + self.epoch_len + self.ttl
    }

    pub fn state(&self, e: u32, now: u64) -> EpochState {
        let start = self.start(e);
        let end = start + self.epoch_len;
        if now < start {
            EpochState::Scheduled
        } else if now < end {
            EpochState::Active
        } else if now < end + self.grace {
            EpochState::Grace
        } else if now < end + self.ttl {
            EpochState::Retained
        } else {
            EpochState::Shredded
        }
    }

    fn starts_within_skew(&self, e: u32, now: u64) -> bool {
        let start = self.start(e);
        now < start && start - now <= CLOCK_SKEW
    }

    /// May a sender seal a new drop to epoch `e` at `now`?
    pub fn sender_may_seal(&self, e: u32, now: u64) -> bool {
        match self.state(e, now) {
            EpochState::Active => true,
            EpochState::Scheduled => self.starts_within_skew(e, now),
            _ => false,
        }
    }

    /// Does a receiver accept a drop sealed to epoch `e` at `now`?
    pub fn receiver_accepts(&self, e: u32, now: u64) -> bool {
        match self.state(e, now) {
            EpochState::Active | EpochState::Grace => true,
            EpochState::Scheduled => self.starts_within_skew(e, now),
            _ => false,
        }
    }

    /// Every epoch up to the current one whose secret still exists: the
    /// mailboxes a sender polls, and the keys an owner still holds.
    pub fn live(&self, now: u64) -> RangeInclusive<u32> {
        let current = self.epoch_at(now);
        // Epoch e is shredded once now >= start(e) + L + T, so the oldest live
        // epoch is the first whose shred time is still ahead.
        let span = self.epoch_len + self.ttl;
        let oldest = if now < span {
            0
        } else {
            ((now - span) / self.epoch_len + 1) as u32
        };
        oldest..=current
    }

    /// The epochs the owner should have keys published for at `now`.
    pub fn published(&self, now: u64) -> RangeInclusive<u32> {
        let current = self.epoch_at(now);
        let grace_epochs = self.grace.div_ceil(self.epoch_len) as u32;
        current.saturating_sub(grace_epochs)..=current.saturating_add(LOOKAHEAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn params() -> EpochParams {
        EpochParams::default()
    }

    #[test]
    fn states_change_exactly_on_the_boundaries() {
        let p = params();
        let e = 100;
        let s = p.start(e);
        let cases = [
            (s - 1, EpochState::Scheduled),
            (s, EpochState::Active),
            (s + 7 * DAY - 1, EpochState::Active),
            (s + 7 * DAY, EpochState::Grace),
            (s + 9 * DAY - 1, EpochState::Grace),
            (s + 9 * DAY, EpochState::Retained),
            (s + 37 * DAY - 1, EpochState::Retained),
            (s + 37 * DAY, EpochState::Shredded),
        ];
        for (now, expected) in cases {
            assert_eq!(
                p.state(e, now),
                expected,
                "at offset {}",
                now as i64 - s as i64
            );
        }
        assert_eq!(p.shred_at(e), s + 37 * DAY);
    }

    #[test]
    fn every_drop_is_readable_between_ttl_and_ttl_plus_one_epoch() {
        let p = params();
        let e = 100;
        let first = p.start(e);
        let last = first + p.epoch_len - 1;
        assert_eq!(p.shred_at(e) - first, p.ttl + p.epoch_len);
        assert_eq!(p.shred_at(e) - last, p.ttl + 1);
    }

    #[test]
    fn acceptance_rules() {
        let p = params();
        let e = 100;
        let s = p.start(e);
        // Clock skew: an hour early is tolerated, more is not.
        assert!(p.sender_may_seal(e, s - CLOCK_SKEW));
        assert!(!p.sender_may_seal(e, s - CLOCK_SKEW - 1));
        assert!(p.receiver_accepts(e, s - CLOCK_SKEW));
        // Grace: receivers accept, senders have moved on.
        assert!(!p.sender_may_seal(e, s + 8 * DAY));
        assert!(p.receiver_accepts(e, s + 8 * DAY));
        // Retained: decrypt only.
        assert!(!p.receiver_accepts(e, s + 10 * DAY));
    }

    #[test]
    fn live_range_is_exactly_the_unshredded_epochs() {
        let p = params();
        for now in [0, 5 * DAY, 36 * DAY, 37 * DAY, 37 * DAY + 1, 1_794_300_000] {
            let live = p.live(now);
            for e in *live.start()..=*live.end() {
                assert_ne!(p.state(e, now), EpochState::Shredded, "epoch {e} at {now}");
            }
            if *live.start() > 0 {
                assert_eq!(p.state(live.start() - 1, now), EpochState::Shredded);
            }
            assert_eq!(*live.end(), p.epoch_at(now));
        }
    }

    #[test]
    fn published_range_covers_grace_and_lookahead() {
        let p = params();
        let now = 1_794_300_000;
        let current = p.epoch_at(now);
        assert_eq!(p.published(now), (current - 1)..=(current + LOOKAHEAD));
        for e in p.published(now) {
            assert!(matches!(
                p.state(e, now),
                EpochState::Scheduled
                    | EpochState::Active
                    | EpochState::Grace
                    | EpochState::Retained
            ));
        }
    }

    #[test]
    fn parameters_are_validated() {
        assert!(EpochParams::new(60, 0, 0).is_err());
        assert!(EpochParams::new(7 * DAY, 3 * DAY, 2 * DAY).is_err());
        assert!(EpochParams::new(7 * DAY, 2 * DAY, 30 * DAY).is_ok());
    }
}
