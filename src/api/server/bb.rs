//! Bulletin board types and public pipeline.
//!
//! This module defines:
//! - Public election metadata `ElectionManifest` and a compact bundle of all public parameters
//!   needed by clients and verifiers `ElectionContext`.
//! - Minimal storage and publication interfaces for a bulletin board `BulletinBoardStore`,
//!   plus a simple in memory implementation `InMemoryBB` suitable for tests and single process
//!   deployments.
//! - A public verification and tally pipeline `PublicPipeline`.
//!
//! Centralized setting
//!
//! The current crate implements a centralized variant: a single instance of each role exists.
//! The bulletin board is an append only log with server assigned receipts. These receipts define
//! authoritative ordering for revoting semantics last vote wins and provide audit metadata.
//!
//! Security notes
//!
//! - `ElectionContext` includes a context hash computed over the manifest, election public key,
//!   and choice parameters using a canonical encoding. Ballots must carry this hash to prevent
//!   cross election replay.
//! - Public verification uses Merlin transcripts. `ElectionContext::tr` domain separates each
//!   protocol step by label and binds all proofs to the context hash.
//! - Mixing functions produce artifacts that contain both the shuffled list and the corresponding
//!   zero knowledge proof. These artifacts are meant to be published by the bulletin board.

use std::collections::{HashMap, HashSet};

use dlog_group::group::Group;
use dlog_sigma_primitives::{
    pedersen::commitment::Parameters,
    proofs::{fingerprints::VerifiableFingerprints, ver_decr::DecOk},
};
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{
    api::client::Ballot,
    constants::{ACC_CHECK, MIX_CREDS, MIX_VOTES, TALLY},
    core::{
        keys::ElectionPublicKey,
        tally::{CredentialControlProof, DecryptedTally, MixedCredentials, MixedVotes},
        vote::{
            auth::ShortPublicACC,
            choice::{ChoiceParameters, EncrChoice},
            vote::{Vote, VoteWithEncPubCred},
        },
    },
    error::Error,
};

/// Public election metadata.
///
/// This is intended to be published and signed by the election authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElectionManifest {
    /// Globally unique election identifier.
    pub election_id: String,
    /// Display title for user interfaces.
    pub title: String,
    /// Responsible authority name or identifier.
    pub authority: String,
    /// Version of the manifest schema or policy.
    pub version: u32,
}

/// Bundle of all public information required to validate ballots.
///
/// It contains:
/// - `manifest` human readable election metadata
/// - `pk` election public key and public parameters
/// - `choice` choice parameters describing the ballot format
/// - `context_hash` a 32 byte hash binding the above data
///
/// The context hash is included by clients in each ballot. Verifiers must reject a ballot when
/// its context hash does not match the expected `ElectionContext`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ElectionContext<G: Group> {
    pub manifest: ElectionManifest,
    pub pk: ElectionPublicKey<G>,
    pub choice: ChoiceParameters,
    pub context_hash: [u8; 32],
}

impl<G: Group> ElectionContext<G> {
    /// Create a new context and compute the context hash.
    pub fn new(manifest: ElectionManifest, pk: ElectionPublicKey<G>, choice: ChoiceParameters) -> Self {
        let context_hash = compute_context_hash(&manifest, &pk, &choice);
        Self {
            manifest,
            pk,
            choice,
            context_hash,
        }
    }

    /// Create a Merlin transcript bound to this election context.
    ///
    /// Callers should use different labels for different protocol steps.
    pub fn tr(&self, label: &'static [u8]) -> Transcript {
        let mut tr = Transcript::new(label);
        tr.append_message(b"election_ctx", &self.context_hash);
        tr
    }
}

/// Compute the context hash for an election context.
///
/// The hash is computed over a canonical CBOR encoding of
/// (manifest, pk, choice) using Sha3 256.
fn compute_context_hash<G: Group>(
    manifest: &ElectionManifest,
    pk: &ElectionPublicKey<G>,
    choice: &ChoiceParameters,
) -> [u8; 32] {
    let bytes = serde_cbor::to_vec(&(manifest, pk, choice)).expect("context serialization must succeed");
    let digest = Sha3_256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Public election wrapper.
///
/// This exists to make it explicit which values are meant to be published.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicElection<G: Group> {
    pub ctx: ElectionContext<G>,
}

impl<G: Group> PublicElection<G> {
    pub fn new(ctx: ElectionContext<G>) -> Self {
        Self { ctx }
    }
}

/// Bulletin board assigned metadata for a posted ballot.
///
/// `seq_no` is authoritative ordering for revoting.
/// `received_at_unix_ms` is audit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub seq_no: u64,
    pub received_at_unix_ms: u64,
}

/// Stored ballot and the receipt assigned by the bulletin board.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BallotRecord<G: Group> {
    pub receipt: Receipt,
    pub ballot: Ballot<G>,
}

/// Verified vote coupled with the receipt it originated from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifiedVoteRecord<G: Group> {
    pub receipt: Receipt,
    pub vote: Vote<G>,
}

/// Vote coupled with its encrypted public credential handle and receipt.
///
/// This is used for duplicate resolution and revoting semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ValidVoteRecord<G: Group> {
    pub receipt: Receipt,
    pub vote: VoteWithEncPubCred<G>,
}

/// Minimal bulletin board storage and publication interface.
///
/// This trait intentionally avoids transport concerns and focuses on what needs to be stored and
/// made available for audit and public verification.
pub trait BulletinBoardStore<G: Group> {
    /// Append a ballot to the bulletin board and return the stored record.
    fn post_ballot(&mut self, ballot: Ballot<G>) -> Result<BallotRecord<G>, Error>;
    /// List all posted ballots in bulletin board order.
    fn list_ballots(&self) -> Vec<BallotRecord<G>>;

    /// Publish credential control proofs generated by RT.
    fn post_controls(&mut self, controls: Vec<CredentialControlProof<G>>) -> Result<(), Error>;
    /// List all published credential control proofs.
    fn list_controls(&self) -> Vec<CredentialControlProof<G>>;

    /// Publish publicly verified votes optional caching layer.
    fn post_verified_votes(&mut self, votes: Vec<VerifiedVoteRecord<G>>) -> Result<(), Error>;
    /// List all published verified votes.
    fn list_verified_votes(&self) -> Vec<VerifiedVoteRecord<G>>;
}

/// In memory bulletin board for tests and single process usage.
///
/// Not thread safe, not persistent, and not hardened.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct InMemoryBB<G: Group> {
    next_seq_no: u64,
    ballots: Vec<BallotRecord<G>>,
    controls: Vec<CredentialControlProof<G>>,
    verified_votes: Vec<VerifiedVoteRecord<G>>,
}

impl<G: Group> Default for InMemoryBB<G> {
    fn default() -> Self {
        Self {
            next_seq_no: 0,
            ballots: Vec::new(),
            controls: Vec::new(),
            verified_votes: Vec::new(),
        }
    }
}

impl<G: Group> InMemoryBB<G> {
    fn now_unix_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn next_receipt(&mut self) -> Receipt {
        let r = Receipt {
            seq_no: self.next_seq_no,
            received_at_unix_ms: Self::now_unix_ms(),
        };
        self.next_seq_no += 1;
        r
    }
}

impl<G: Group> BulletinBoardStore<G> for InMemoryBB<G> {
    fn post_ballot(&mut self, ballot: Ballot<G>) -> Result<BallotRecord<G>, Error> {
        let receipt = self.next_receipt();
        let record = BallotRecord { receipt, ballot };
        self.ballots.push(record.clone());
        Ok(record)
    }

    fn list_ballots(&self) -> Vec<BallotRecord<G>> {
        self.ballots.clone()
    }

    fn post_controls(&mut self, controls: Vec<CredentialControlProof<G>>) -> Result<(), Error> {
        self.controls.extend(controls);
        Ok(())
    }

    fn list_controls(&self) -> Vec<CredentialControlProof<G>> {
        self.controls.clone()
    }

    fn post_verified_votes(&mut self, votes: Vec<VerifiedVoteRecord<G>>) -> Result<(), Error> {
        self.verified_votes.extend(votes);
        Ok(())
    }

    fn list_verified_votes(&self) -> Vec<VerifiedVoteRecord<G>> {
        self.verified_votes.clone()
    }
}

/// Artifact produced when mixing votes.
///
/// `shuffled` contains the permuted verified vote records.
/// Receipts are carried through the shuffle to later implement revoting policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VoteMixArtifact<G: Group> {
    pub pedersen: Parameters<G>,
    pub shuffled: Vec<VerifiedVoteRecord<G>>,
    pub proof: MixedVotes<G>,
}

/// Artifact produced when mixing public credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CredMixArtifact<G: Group> {
    pub pedersen: Parameters<G>,
    pub shuffled: Vec<ShortPublicACC<G>>,
    pub proof: MixedCredentials<G>,
}

/// Public computation pipeline executed over bulletin board data.
///
/// This type is pure and deterministic except for explicit randomness passed to mixing and
/// fingerprint generation. It is designed so that anyone can rerun the same verification steps
/// from published data.
#[derive(Debug, Clone)]
pub struct PublicPipeline<G: Group> {
    pub election: PublicElection<G>,
}

impl<G: Group> PublicPipeline<G> {
    pub fn new(election: PublicElection<G>) -> Self {
        Self { election }
    }

    pub fn pk(&self) -> &ElectionPublicKey<G> {
        &self.election.ctx.pk
    }

    pub fn choice_params(&self) -> &ChoiceParameters {
        &self.election.ctx.choice
    }

    pub fn context_hash(&self) -> &[u8; 32] {
        &self.election.ctx.context_hash
    }

    /// Verify all ballots and return the verified votes paired with their receipts.
    pub fn verify_ballots(&self, ballots: &[BallotRecord<G>]) -> Result<Vec<VerifiedVoteRecord<G>>, Error> {
        ballots
            .iter()
            .map(|r| {
                let v = r.ballot.verify(&self.election.ctx)?;
                Ok(VerifiedVoteRecord {
                    receipt: r.receipt,
                    vote: v,
                })
            })
            .collect()
    }

    /// Mix votes while preserving receipts by shuffling vote records.
    pub fn mix_votes<R: RngCore + CryptoRng>(
        &self,
        originals: &[VerifiedVoteRecord<G>],
        rng: &mut R,
    ) -> VoteMixArtifact<G> {
        let n = originals.len();
        let ped = Parameters::<G>::new(n, rng);

        let mut perm: Vec<usize> = (0..ped.list_len).collect();
        perm.shuffle(rng);

        // Re encrypt votes following perm.
        let shuffled_ext = perm
            .iter()
            .map(|&i| originals[i].vote.re_encrypt(self.pk(), rng))
            .collect::<Vec<_>>();

        let mut tr = self.election.ctx.tr(MIX_VOTES);
        let proof = MixedVotes::<G>::new(
            self.pk(),
            &ped,
            &perm,
            &shuffled_ext,
            self.choice_params(),
            rng,
            &mut tr,
        );

        // Convert back to Vote and keep the permuted receipts.
        let shuffled = perm
            .iter()
            .zip(shuffled_ext.into_iter())
            .map(|(&i, ext)| VerifiedVoteRecord {
                receipt: originals[i].receipt,
                vote: ext.to_vote(),
            })
            .collect::<Vec<_>>();

        VoteMixArtifact {
            pedersen: ped,
            shuffled,
            proof,
        }
    }

    /// Verify a vote mix artifact against the original list.
    pub fn verify_vote_mix(
        &self,
        originals: &[VerifiedVoteRecord<G>],
        art: &VoteMixArtifact<G>,
    ) -> Result<(), Error> {
        let mut tr = self.election.ctx.tr(MIX_VOTES);

        let orig_votes = originals.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();
        let shuf_votes = art.shuffled.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();

        art.proof.verify(
            self.pk(),
            &art.pedersen,
            self.choice_params(),
            &orig_votes,
            &shuf_votes,
            &mut tr,
        )
    }

    /// Mix public credential handles and produce a shuffle proof.
    pub fn mix_credentials<R: RngCore + CryptoRng>(
        &self,
        originals: &[ShortPublicACC<G>],
        rng: &mut R,
    ) -> CredMixArtifact<G> {
        let n = originals.len();
        let ped = Parameters::<G>::new(n, rng);

        let mut perm: Vec<usize> = (0..ped.list_len).collect();
        perm.shuffle(rng);

        let shuffled_ext = perm
            .iter()
            .map(|&i| originals[i].re_encrypt(self.pk(), rng))
            .collect::<Vec<_>>();

        let mut tr = self.election.ctx.tr(MIX_CREDS);
        let proof = MixedCredentials::<G>::new(self.pk(), &ped, &perm, &shuffled_ext, rng, &mut tr);

        let shuffled = shuffled_ext.into_iter().map(|e| e.to_short()).collect::<Vec<_>>();

        CredMixArtifact {
            pedersen: ped,
            shuffled,
            proof,
        }
    }

    /// Verify a credential mix artifact against the original list.
    pub fn verify_cred_mix(&self, originals: &[ShortPublicACC<G>], art: &CredMixArtifact<G>) -> Result<(), Error> {
        let mut tr = self.election.ctx.tr(MIX_CREDS);
        art.proof.verify(
            self.pk(),
            &art.pedersen,
            &originals.to_vec(),
            &art.shuffled.to_vec(),
            &mut tr,
        )
    }

    /// Filter invalid votes while keeping receipts for later revoting semantics.
    ///
    /// Preconditions
    ///
    /// `mixed_votes[i]`, `controls[i]`, and `acc_checks[i]` must be aligned.
    pub fn filter_invalid(
        &self,
        mixed_votes: &[VerifiedVoteRecord<G>],
        controls: &[CredentialControlProof<G>],
        acc_checks: &[DecOk<G>],
    ) -> Result<Vec<ValidVoteRecord<G>>, Error> {
        let votes = mixed_votes.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();

        // Core returns indices into `votes`.
        let indexed_valid = self.pk().filter_invalid(&votes, controls, acc_checks)?;

        Ok(indexed_valid
            .into_iter()
            .map(|(i, vote)| ValidVoteRecord {
                receipt: mixed_votes[i].receipt,
                vote,
            })
            .collect())
    }

    /// Verify the designated verifier accumulator checks.
    pub fn verify_acc_checks(
        &self,
        acc_checks: &[DecOk<G>],
        controls: &[CredentialControlProof<G>],
        mixed_votes: &[VerifiedVoteRecord<G>],
    ) -> Result<(), Error> {
        let mut tr = self.election.ctx.tr(ACC_CHECK);
        let votes = mixed_votes.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();
        self.pk().verify_checks(acc_checks, controls, &votes, &mut tr)
    }

    /// Generate verifiable fingerprints for credentials.
    pub fn gen_credential_fingerprints<R: RngCore + CryptoRng>(
        &self,
        original_creds: &[ShortPublicACC<G>],
        cred_mix: &CredMixArtifact<G>,
        valid_votes: &[ValidVoteRecord<G>],
        rng: &mut R,
    ) -> Result<VerifiableFingerprints<G>, Error> {
        let mut tr = self.election.ctx.tr(MIX_CREDS);
        let vv = valid_votes.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();

        self.pk().gen_credential_fingerprints(
            &cred_mix.pedersen,
            original_creds,
            &cred_mix.shuffled,
            &cred_mix.proof,
            &vv,
            rng,
            &mut tr,
        )
    }

    /// Filter illicit votes and enforce revoting semantics keep only the last vote per credential.
    ///
    /// Preconditions
    ///
    /// `dec_votes_fps.len() == valid_votes.len()` and `dec_pub_fps.len() == cred_mix.shuffled.len()`.
    pub fn filter_illicit_keep_last(
        &self,
        valid_votes: &[ValidVoteRecord<G>],
        cred_mix: &CredMixArtifact<G>,
        fps: &VerifiableFingerprints<G>,
        dec_pub_fps: &[DecOk<G>],
        dec_votes_fps: &[DecOk<G>],
    ) -> Result<Vec<EncrChoice<G>>, Error> {
        assert_eq!(dec_votes_fps.len(), valid_votes.len());
        assert_eq!(dec_pub_fps.len(), cred_mix.shuffled.len());

        let mut tr = self.election.ctx.tr(MIX_CREDS);

        // Public verification checks proofs and consistency inside core.
        let vv = valid_votes.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();
        self.pk().filter_illicit(
            &vv,
            &cred_mix.shuffled,
            fps,
            dec_pub_fps,
            dec_votes_fps,
            &mut tr,
        )?;

        // Authorized fingerprint set derived from decrypted public credentials.
        let authorized: HashSet<Vec<u8>> = dec_pub_fps
            .iter()
            .map(|d| {
                let mut bytes = vec![0u8; G::POINT_SIZE];
                G::point_to_bytes(&mut bytes, &d.plaintext);
                bytes
            })
            .collect();

        // fp bytes to best seq no and index in valid_votes
        let mut best: HashMap<Vec<u8>, (u64, usize)> = HashMap::new();

        for (i, rec) in valid_votes.iter().enumerate() {
            let mut fp = vec![0u8; G::POINT_SIZE];
            G::point_to_bytes(&mut fp, &dec_votes_fps[i].plaintext);

            if !authorized.contains(&fp) {
                continue;
            }

            match best.get(&fp) {
                None => {
                    best.insert(fp, (rec.receipt.seq_no, i));
                }
                Some((seq, _)) => {
                    if rec.receipt.seq_no > *seq {
                        best.insert(fp, (rec.receipt.seq_no, i));
                    }
                }
            }
        }

        // Deterministic output ordering for reproducibility.
        let mut chosen = best.into_values().collect::<Vec<_>>();
        chosen.sort_by_key(|(seq, _)| *seq);

        Ok(chosen
            .into_iter()
            .map(|(_, i)| valid_votes[i].vote.choice.clone())
            .collect())
    }

    /// Homomorphically sum encrypted choices.
    pub fn homomorphic_sum(&self, legitimate: impl IntoIterator<Item = EncrChoice<G>>) -> EncrChoice<G> {
        let mut acc = EncrChoice::identity(self.choice_params());
        for c in legitimate {
            acc += c;
        }
        acc
    }

    /// Verify a decrypted tally against an encrypted tally.
    pub fn verify_decrypted_tally(&self, enc_tally: &EncrChoice<G>, decr: &DecryptedTally<G>) -> Result<(), Error> {
        let mut tr = self.election.ctx.tr(TALLY);
        decr.verify(
            &self.pk().params.tally,
            &self.pk().params.elgamal,
            enc_tally,
            &mut tr,
        )
    }
}
