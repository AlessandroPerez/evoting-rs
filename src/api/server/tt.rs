//! Tabulation teller API.
//!
//! This module implements the Tabulation Teller (TT) role for the centralized deployment.
//! The TT holds the decryption secret key and produces publicly verifiable decryptions used in
//! the public bulletin board pipeline.
//!
//! Context binding
//!
//! Every operation is bound to an ElectionContext. This ensures all transcripts are domain
//! separated and linked to the election context hash. It also avoids passing individual public
//! parameters around at the API boundary.

use dlog_group::group::Group;
use dlog_sigma_primitives::{
    elgamal::ciphertext::DiscreteLogTable,
    proofs::{fingerprints::VerifiableFingerprints, ver_decr::DecOk},
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    api::server::bb::ElectionContext,
    constants::{ACC_CHECK, MIX_CREDS, TALLY},
    core::{
        keys::TTSecretKey,
        tally::{CredentialControlProof, DecryptedTally},
        vote::{
            auth::ShortPublicACC,
            choice::EncrChoice,
            vote::{Vote, VoteWithEncPubCred},
        },
    },
    error::Error,
};

/// Tabulation Teller role.
///
/// The TT holds the election decryption secret key and produces verifiable decryptions for
/// accumulator validity checks, credential fingerprint matching, and final tally decryption.
///
/// In a future multi party setting this type can be replaced by a coordinator that collects
/// threshold decryptions and aggregates proofs.
#[derive(Debug, Clone)]
pub struct TabulationTeller<G: Group> {
    sk: TTSecretKey<G>,
    election: ElectionContext<G>,
}

impl<G: Group> TabulationTeller<G> {
    /// Construct a TT bound to a given election context.
    ///
    /// This is the preferred constructor for the context centric API.
    pub fn new(sk: TTSecretKey<G>, election: &ElectionContext<G>) -> Self {
        Self {
            sk,
            election: election.clone(),
        }
    }

    /// Borrow the election context.
    pub fn election(&self) -> &ElectionContext<G> {
        &self.election
    }

    /// Produce verifiable decryptions for credential validity checks.
    ///
    /// This is consumed by the public pipeline to filter invalid votes.
    ///
    /// Preconditions
    ///
    /// The votes and controls slices must be aligned. The ith control proof must correspond
    /// to the ith vote.
    pub fn gen_acc_checks<R: RngCore + CryptoRng>(
        &self,
        votes: &[Vote<G>],
        controls: &[CredentialControlProof<G>],
        rng: &mut R,
    ) -> Result<Vec<DecOk<G>>, Error> {
        let mut transcript = self.election.tr(ACC_CHECK);
        self.sk
            .gen_ACC_checks(
                &self.election.pk,
                &votes.to_vec(),
                &controls.to_vec(),
                rng,
                &mut transcript,
            )
            .map_err(Error::from)
    }

    /// Decrypt credential fingerprints for both the mixed public credential list and the votes.
    ///
    /// The returned pair is decryptions for the shuffled public credential fingerprints and
    /// decryptions for the vote credential fingerprints.
    pub fn decrypt_credential_fingerprints<R: RngCore + CryptoRng>(
        &self,
        valid_votes: &[VoteWithEncPubCred<G>],
        fps: &VerifiableFingerprints<G>,
        shuffled_creds: &[ShortPublicACC<G>],
        rng: &mut R,
    ) -> Result<(Vec<DecOk<G>>, Vec<DecOk<G>>), Error> {
        let mut transcript = self.election.tr(MIX_CREDS);
        self.sk
            .decrypt_credential_fingerprints(
                &self.election.pk,
                &valid_votes.to_vec(),
                fps,
                &shuffled_creds.to_vec(),
                &mut transcript,
                rng,
            )
            .map_err(Error::from)
    }

    /// Decrypt the final encrypted tally and return a verifiable object.
    ///
    /// The discrete log table is used to map decrypted group elements to counts.
    pub fn decrypt_tally<R: RngCore + CryptoRng>(
        &self,
        enc_tally: EncrChoice<G>,
        table: &DiscreteLogTable<G>,
        rng: &mut R,
    ) -> Result<DecryptedTally<G>, Error> {
        let mut transcript = self.election.tr(TALLY);
        self.sk
            .decrypt_tally(&self.election.pk, enc_tally, table, rng, &mut transcript)
            .map_err(Error::from)
    }
}
