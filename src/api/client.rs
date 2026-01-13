//! Client side API.
//!
//! This module contains the types used on the voter device.
//! It is intentionally small and self contained.

use dlog_group::group::Group;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    api::server::bb::ElectionContext,
    constants::EMOJIS_VISUAL_LEN,
    core::{
        keys::{VoterKeyPair, VoterPublicKey},
        vote::{
            auth::{VotingCredential, VotingCredentialBuilder},
            choice::Choice,
            vote::{VerVote, Vote},
        },
    },
    error::Error,
    utils::hash_to_emojis,
};

/// Client side only: describes what the voter wants to vote.
///
/// This is a thin wrapper over `Choice` that makes the intent explicit at the
/// API boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BallotBuilder {
    choice: Choice,
}

impl BallotBuilder {
    /// Create a new builder for the given `choice`.
    pub fn new(choice: Choice) -> Self {
        Self { choice }
    }

    /// Borrow the underlying choice.
    pub fn choice(&self) -> &Choice {
        &self.choice
    }
}

/// A ballot message sent from the voter to the bulletin board.
///
/// The ballot includes:
/// - `election_ctx`: a 32 byte hash that binds the ballot to a specific
///   `ElectionContext` and prevents cross election replays.
/// - `ver_vote`: the verifiable vote, including the cryptographic proofs.
///
/// The bulletin board is expected to verify and then store or forward the
/// ballot according to the server side pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Ballot<G: Group> {
    /// Hash of the election context this ballot is bound to.
    pub election_ctx: [u8; 32],
    /// Verifiable vote with attached proofs.
    pub ver_vote: VerVote<G>,
}

impl<G: Group> Ballot<G> {
    /// Return a short visual digest of the ballot (hash to emojis).
    ///
    /// This is intended for user facing confirmation and for manual
    /// cross checks against a published digest.
    pub fn to_emoji(&self) -> Vec<&str> {
        let bytes = serde_cbor::to_vec(self).expect("ballot serialization must succeed");
        hash_to_emojis(&bytes, EMOJIS_VISUAL_LEN)
    }

    /// Verify the ballot with the provided election context.
    ///
    /// This checks the context hash binding first, then verifies the
    /// underlying cryptographic proofs.
    pub fn verify(&self, ctx: &ElectionContext<G>) -> Result<Vote<G>, Error> {
        if self.election_ctx != ctx.context_hash {
            return Err(Error::Mismatch("election context hash mismatch".into()));
        }
        self.ver_vote.verify(&ctx.pk, &ctx.choice)
    }
}

/// Intermediate client state during voter enrollment.
///
/// In a typical flow the voter device first obtains the election context,
/// then interacts with the registration teller (RT) to obtain a valid
/// voting credential.
///
/// This type exists to keep the RT output (the credential) separate from
/// the rest of the voters local state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VoterBuilder<G: Group> {
    election: ElectionContext<G>,
    credential_builder: VotingCredentialBuilder<G>,
    voter_keys: VoterKeyPair<G>,
}

impl<G: Group> VoterBuilder<G> {
    /// Create a new `VoterBuilder`.
    ///
    /// The builder generates the voters key pair that will be used to bind
    /// credentials and proofs to the voter device.
    pub fn new<R: RngCore + CryptoRng>(
        election: &ElectionContext<G>,
        credential_builder: VotingCredentialBuilder<G>,
        rng: &mut R,
    ) -> Self {
        let voter_keys = VoterKeyPair::new(&election.pk, rng);
        Self {
            election: election.clone(),
            credential_builder,
            voter_keys,
        }
    }

    /// Borrow the election context.
    pub fn election(&self) -> &ElectionContext<G> {
        &self.election
    }

    /// Return the voters public key.
    pub fn voter_pk(&self) -> VoterPublicKey<G> {
        self.voter_keys.pk.clone()
    }

    /// Local simulation helper.
    ///
    /// This creates a credential that verifies but is not expected to tally.
    pub fn simulate<R: RngCore + CryptoRng>(
        self,
        pin: usize,
        rng: &mut R,
    ) -> Result<Voter<G>, Error> {
        let credential = self
            .credential_builder
            .simulate(&self.election.pk, pin, &self.voter_keys, rng)?;

        Ok(Voter {
            election: self.election,
            credential,
            voter_keys: self.voter_keys,
        })
    }

    /// Finalize the builder into a real voter using a credential returned by RT.
    pub fn finalize(self, credential: VotingCredential<G>) -> Voter<G> {
        Voter {
            election: self.election,
            credential,
            voter_keys: self.voter_keys,
        }
    }

    /// Consume the builder and return its internal parts.
    pub fn into_inner(self) -> (ElectionContext<G>, VotingCredentialBuilder<G>, VoterKeyPair<G>) {
        (self.election, self.credential_builder, self.voter_keys)
    }
}

/// Fully initialized voter state.
///
/// A `Voter` owns the credential and the key pair required to cast ballots
/// and to prove possession of the correct PIN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Voter<G: Group> {
    election: ElectionContext<G>,
    credential: VotingCredential<G>,
    voter_keys: VoterKeyPair<G>,
}

impl<G: Group> Voter<G> {
    /// Borrow the election context.
    pub fn election(&self) -> &ElectionContext<G> {
        &self.election
    }

    /// Return the voters public key.
    pub fn voter_pk(&self) -> VoterPublicKey<G> {
        self.voter_keys.pk.clone()
    }

    /// Cast a ballot.
    ///
    /// The caller provides:
    /// - `ballot_builder`: the voters intent (choice)
    /// - `pin`: the PIN the voter typed
    /// - `rng`: randomness for encryption and proofs
    ///
    /// The returned ballot is ready to be posted to the bulletin board.
    pub fn vote<R: RngCore + CryptoRng>(
        &self,
        ballot_builder: &BallotBuilder,
        pin: usize,
        rng: &mut R,
    ) -> Ballot<G> {
        let ver_vote = VerVote::new(
            &self.election.pk,
            ballot_builder.choice(),
            &self.election.choice,
            &self.credential,
            pin,
            rng,
        );

        Ballot {
            election_ctx: self.election.context_hash,
            ver_vote,
        }
    }

    /// Check that a PIN is consistent with the credential and designated verifier proof.
    ///
    /// This is a local check meant for the voter device. It does not reveal
    /// which PIN is the valid one to the server side.
    pub fn verify_pin(&self, pin: usize) -> Result<(), Error> {
        self.credential
            .verify_pin(&self.election.pk, pin, &self.voter_keys.pk)?;
        Ok(())
    }

    /// Convert back to `VoterBuilder` by turning the credential into its builder form.
    pub fn to_builder(self) -> VoterBuilder<G> {
        VoterBuilder {
            election: self.election,
            credential_builder: self.credential.to_builder(),
            voter_keys: self.voter_keys,
        }
    }
}
