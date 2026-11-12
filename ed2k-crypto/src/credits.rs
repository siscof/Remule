// SPDX-License-Identifier: GPL-2.0-or-later
//! Upload credits (`CClientCredits::GetCreditRatio` / `GetScoreRatio`,
//! ClientCredits.cpp): how much a peer's queue score is multiplied by, for
//! what it uploaded to us (`downloaded`) against what we uploaded to it.

/// `EIdentState`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentState {
    /// `IS_NOTAVAILABLE`: the peer does not do secure ident.
    NotAvailable,
    /// `IS_IDNEEDED`: not proved yet.
    Needed,
    /// `IS_IDENTIFIED`
    Identified,
    /// `IS_IDFAILED`
    Failed,
    /// `IS_IDBADGUY`: another key for this user hash.
    BadGuy,
}

/// `GetCreditRatio`, between 1 and 10: 1 below 1,000,000 bytes received;
/// else min(2·down/up (10 if nothing was uploaded), √(down in MiB + 2)).
pub fn credit_ratio(downloaded: u64, uploaded: u64) -> f32 {
    if downloaded < 1_000_000 {
        return 1.0;
    }
    let mut r = if uploaded == 0 {
        10.0f32
    } else {
        (downloaded as f32 * 2.0) / uploaded as f32
    };
    let cap = ((downloaded as f64 / 1_048_576.0) + 2.0).sqrt() as f32;
    if r > cap {
        r = cap;
    }
    r.clamp(1.0, 10.0)
}

/// `GetScoreRatio`: the credit ratio, but 1 for a peer that has not proved
/// its identity while we could check it.
pub fn score_ratio(
    state: IdentState,
    crypto_available: bool,
    downloaded: u64,
    uploaded: u64,
) -> f32 {
    match state {
        IdentState::Failed | IdentState::BadGuy | IdentState::Needed if crypto_available => 1.0,
        _ => credit_ratio(downloaded, uploaded),
    }
}
