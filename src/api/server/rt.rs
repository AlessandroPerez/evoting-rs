//! Registration teller API.
//!
//! This module implements the Registration Teller (RT) role for the centralized deployment.
//! The RT is the credential issuer for voters.
//!
//! Overview
//!
//! The public election material is represented by `ElectionContext`, which bundles a manifest,
//! the election public key, the choice parameters, and a 32 byte context hash. Clients include
//! the context hash in every ballot to prevent cross election replay.
//!
//! RT responsibilities
//!
//! - Setup: generate the RT keypair and derive the election public key.
//! - Registration: provide a `VotingCredentialBuilder` and finalize it into a `VotingCredential`
//!   bound to a voter public key.
//! - Audit: generate credential control proofs that let anyone verify that a posted vote was
//!   formed using a credential consistent with the RT secret.
//!
//! Notes
//!
//! - `gen_builder` returns a PIN for convenience in tests. In a real system the PIN must be
//!   delivered to the voter out of band and must not be exposed to the bulletin board.
//! - The current crate targets a centralized deployment (single RT instance).

use dlog_group::group::Group;
use dlog_sigma_primitives::{elgamal::keys::SecretKey, proofs::Proof};
use rand_core::{CryptoRng, RngCore};

use crate::{
    api::server::bb::{ElectionContext, ElectionManifest},
    core::{
        keys::{ElectionParams, ElectionPublicKey, RTKeyPair, VoterPublicKey},
        tally::{CredentialControlProof, CredentialControlPublicBorrowed},
        vote::{
            auth::{
                PrivateACC, PublicACC, ShortPublicACC, VotingCredential, VotingCredentialBuilder,
            },
            vote::Vote,
        },
    },
    error::Error,
};

/// Registration Teller role.
///
/// In multi party settings this can evolve into a coordinator or a share holder. In the
/// centralized setting this type owns the registration secret key.
#[derive(Debug)]
pub struct RegistrationTeller<G: Group> {
    election_pk: ElectionPublicKey<G>,
    pub(crate) keypair: RTKeyPair<G>,
}

impl<G: Group> RegistrationTeller<G> {
    /// Create a new RT from election parameters.
    ///
    /// This generates the RT mix encryption secret key and derives the RT keypair used by
    /// the credential issuer and credential control proofs.
    pub fn new<R: RngCore + CryptoRng>(params: ElectionParams<G>, rng: &mut R) -> Self {
        let meg_sk = SecretKey::new(rng);
        let keypair = RTKeyPair::new(meg_sk, &params, rng);
        let election_pk = ElectionPublicKey::new(&keypair.pk, params);
        Self { election_pk, keypair }
    }

    /// Return the election public key.
    ///
    /// Prefer using `election_context` at the API boundary, but this accessor is kept for
    /// internal and legacy usage.
    pub fn election_pk(&self) -> ElectionPublicKey<G> {
        self.election_pk.clone()
    }

    /// Build the public election context to be published on the bulletin board.
    pub fn election_context(
        &self,
        manifest: ElectionManifest,
        choice: crate::core::vote::choice::ChoiceParameters,
    ) -> ElectionContext<G> {
        ElectionContext::new(manifest, self.election_pk.clone(), choice)
    }

    /// Generate a credential builder for a new voter.
    ///
    /// Returns:
    /// - `VotingCredentialBuilder`: to be sent to the voter device
    /// - `pin`: the voter PIN derived from the private accumulator (test convenience)
    /// - `PublicACC`: a public handle that can be verified and optionally published
    pub fn gen_builder<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (VotingCredentialBuilder<G>, usize, PublicACC<G>) {
        let private_acc = PrivateACC::new(&self.keypair, &self.election_pk, rng);
        let public_acc = PublicACC::from_private(&self.election_pk, &private_acc, rng);
        let builder = VotingCredentialBuilder::new(&private_acc);
        let pin = private_acc.pin.get_pin_value();
        (builder, pin, public_acc)
    }

    /// Finalize a credential builder into a voting credential for a specific voter public key.
    ///
    /// The voter public key binds the credential to the voter device.
    pub fn gen_credential<R: RngCore + CryptoRng>(
        &self,
        voter_pk: &VoterPublicKey<G>,
        builder: &VotingCredentialBuilder<G>,
        rng: &mut R,
    ) -> Result<VotingCredential<G>, Error> {
        builder.finalize(&self.keypair, &self.election_pk, voter_pk, rng)
    }

    /// Generate credential control proofs for a list of verified votes.
    ///
    /// These proofs are published on the bulletin board and later consumed by the public
    /// pipeline to filter invalid votes.
    pub fn gen_controls<R: RngCore + CryptoRng>(
        &self,
        votes: &[Vote<G>],
        rng: &mut R,
    ) -> Vec<CredentialControlProof<G>> {
        votes
            .iter()
            .map(|v| {
                let public = CredentialControlPublicBorrowed::<G>::new(
                    &self.election_pk.params.g3,
                    &self.election_pk.registration_pk,
                    v,
                    v.auth.A_enc,
                );
                CredentialControlProof::<G>::prove(public, &self.keypair.sk.secret_scalar, rng)
            })
            .collect()
    }

    /// Convert a full public accumulator handle into its short, publishable form.
    ///
    /// This verifies that the handle is well formed for this election public key.
    pub fn short_public_acc(&self, public_acc: &PublicACC<G>) -> Result<ShortPublicACC<G>, Error> {
        Ok(public_acc.verify(&self.election_pk)?)
    }
}
