//! Server side API.
//!
//! This module groups all authority side roles and bulletin board components.
//! It represents the public facing and verifiable part of the protocol.
//!
//! Centralized setting
//!
//! The current implementation assumes a single instance per role:
//! - one bulletin board
//! - one registration teller
//! - one tabulation teller

/// Bulletin board storage types and public verification pipeline.
pub mod bb;

/// Registration teller role (credential issuance and control proofs).
pub mod rt;

/// Tabulation teller role (verifiable decryptions and tally decryption).
pub mod tt;
