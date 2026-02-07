use std::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

// Phase 9 invariants: compile-time markers only (no runtime flags).
pub trait NoPerUserConnectionOwnership: sealed::Sealed {}
pub trait NoStableSocketMapping: sealed::Sealed {}
pub trait NoDirectTimingCorrespondence: sealed::Sealed {}
pub trait NoRelayLocalLinkability: sealed::Sealed {}

pub trait Phase9Anonymity:
    sealed::Sealed
    + NoPerUserConnectionOwnership
    + NoStableSocketMapping
    + NoDirectTimingCorrespondence
    + NoRelayLocalLinkability
{
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase9;

impl sealed::Sealed for Phase9 {}
impl NoPerUserConnectionOwnership for Phase9 {}
impl NoStableSocketMapping for Phase9 {}
impl NoDirectTimingCorrespondence for Phase9 {}
impl NoRelayLocalLinkability for Phase9 {}
impl Phase9Anonymity for Phase9 {}

// Legacy allowances are explicit opt-ins for pre-Phase 9 components.
pub trait AllowsPerUserConnectionOwnership: sealed::Sealed {}
pub trait AllowsStableSocketMapping: sealed::Sealed {}
pub trait AllowsDirectTimingCorrespondence: sealed::Sealed {}
pub trait AllowsRelayLocalLinkability: sealed::Sealed {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyPhase;

impl sealed::Sealed for LegacyPhase {}
impl AllowsPerUserConnectionOwnership for LegacyPhase {}
impl AllowsStableSocketMapping for LegacyPhase {}
impl AllowsDirectTimingCorrespondence for LegacyPhase {}
impl AllowsRelayLocalLinkability for LegacyPhase {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase9Token<P: Phase9Anonymity>(PhantomData<P>);

impl Phase9Token<Phase9> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyToken<P: AllowsPerUserConnectionOwnership
    + AllowsStableSocketMapping
    + AllowsDirectTimingCorrespondence
    + AllowsRelayLocalLinkability>(PhantomData<P>);

impl LegacyToken<LegacyPhase> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}
