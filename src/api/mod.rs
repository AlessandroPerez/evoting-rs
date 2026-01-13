//! High level API surface.
//!
//! The `api` module provides the public, role oriented interface for the crate.
//! It targets a centralized deployment (single instance per role) while keeping
//! boundaries that map cleanly to a future multi party setting.
//!
//! Structure
//!
//! - `client` contains voter device types: ballot construction and local checks.
//! - `server` contains authority side roles and bulletin board helpers:
//!   - `bb` bulletin board storage types and the public verification pipeline
//!   - `rt` registration teller role (credential issuance and control proofs)
//!   - `tt` tabulation teller role (verifiable decryptions and tally decryption)
//!
//! The `prelude` re exports the most commonly used types so applications can do
//! `use evoting::api::prelude::*;` and get a coherent set of building blocks.

pub mod client;
pub mod server;

/// Convenient re exports for applications.
///
/// Exposes the role types and the minimum set of core types needed to drive 
/// the end to end flow.
pub mod prelude {
    // Client side
    pub use crate::api::client::{Ballot, BallotBuilder, Voter, VoterBuilder};

    // Server side roles and bulletin board
    pub use crate::api::server::{
        bb::{BulletinBoardStore, ElectionContext, InMemoryBB},
        rt::RegistrationTeller,
        tt::TabulationTeller,
    };

    // Core types commonly needed by applications wiring the protocol
    pub use crate::core::keys::{ElectionParams, ElectionPublicKey, TTSecretKey};
    pub use crate::core::vote::auth::ShortPublicACC;
    pub use crate::core::vote::choice::{Choice, ChoiceParameters, EncrChoice};
}