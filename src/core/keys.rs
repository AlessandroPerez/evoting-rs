//! keys

use dlog_group::group::Group;
use dlog_group::serde::{PointHelper, ScalarHelper};
use dlog_sigma_primitives::{
    elgamal::{
        ciphertext::{Ciphertext, DiscreteLogTable, ExtendedCiphertext},
        keys::{ElGamalParams, PublicKey as ElGamalPublicKey, SecretKey, SecretScalar},
    },
    error::DecryptionError,
    pedersen::commitment::Parameters,
    proofs::{
        fingerprints::VerifiableFingerprints,
        ver_decr::{DecOk, DecOkProtocol, DecOkPublicBorrowed},
        Proof, SigmaProtocol, TranscriptForGroup,
    },
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::collections::HashSet;

use crate::error::Error::InvalidSize;
use crate::utils::generate_passphrase;
use crate::{
    core::tally::{
        CredentialControlProof, CredentialControlPublicBorrowed, DecryptedTally, MixedCredentials,
        Tally,
    },
    core::vote::{
        auth::ShortPublicACC,
        choice::EncrChoice,
        vote::{VerVote, Vote, VoteWithEncPubCred},
    },
    error::{self, Error},
};

// region: ---Election

/// Parameters required for setting up an election using Modified-ElGamal encryption. Includes public parameters and auxiliary points used in the cryptographic scheme.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ElectionParams<G: Group> {
    /// Modified-ElGamal parameters g1 and g2, used for all ElGamal related encryptions
    pub elgamal: ElGamalParams<G>,
    #[cfg_attr(feature = "serde", serde(with = "PointHelper::<G>"))]
    /// TODO: Additional Point
    pub(crate) g3: G::Point,
    #[cfg_attr(feature = "serde", serde(with = "PointHelper::<G>"))]
    /// TODO: Additional Point
    pub(crate) o: G::Point,
    /// Tally Modified-ElGamal Public Key
    pub tally: ElGamalPublicKey<G>,
}

impl<G: Group> ElectionParams<G> {
    /// Creates a new `ElectionParams` instance with the given ElGamal parameters and tally public key.
    ///
    /// # Arguments
    /// * `elgamal`: Reference to the ElGamal parameters used for encryption.
    /// * `tally`: Reference to the ElGamal public key used for tallying.
    /// * `rng`: A cryptographically secure random number generator.
    pub fn new<R: RngCore + CryptoRng>(
        elgamal: &ElGamalParams<G>,
        tally: &ElGamalPublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let g3 = G::point_random(rng);
        let o = G::point_random(rng);
        Self {
            elgamal: elgamal.clone(),
            g3,
            o,
            tally: tally.clone(),
        }
    }
    // Function only available in tests.
    #[cfg(test)]
    pub(crate) fn new_mock<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        use dlog_sigma_primitives::elgamal::keys::KeyPair;

        let elgamal = ElGamalParams::new(rng);
        let (_, tally) = KeyPair::new_from_params(&elgamal, rng).into_tuple();
        let g3 = G::point_random(rng);
        let o = G::point_random(rng);
        Self {
            elgamal,
            g3,
            o,
            tally,
        }
    }
}

/// Public key information for an election, including all the necessary public information to perform encryption, generate zero-knowledge proofs, and verify ballots in the election.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ElectionPublicKey<G: Group> {
    /// The Registration Teller's public key used for authenticating credentials.
    #[serde(with = "PointHelper::<G>")]
    pub(crate) registration_pk: G::Point,
    /// The election parameters (including ElGamal parameters, auxiliary points, and the Tally key).
    pub params: ElectionParams<G>,
}

impl<G: Group> ElectionPublicKey<G> {
    /// Creates a new `ElectionPublicKey` from a Registration Teller public key and election parameters.
    pub fn new(rt_pub: &RTPublicKey<G>, params: ElectionParams<G>) -> Self {
        Self {
            registration_pk: rt_pub.registration_pk,
            params,
        }
    }
    /// Encrypts a group element using the election’s tally public key and ElGamal parameters.
    pub(crate) fn encrypt<R: RngCore + CryptoRng>(
        &self,
        value: G::Point,
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::new(&self.params.tally, &self.params.elgamal, value, rng)
    }
    pub(crate) fn identity_encription<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::new(&self.params.tally, &self.params.elgamal, G::identity(), rng)
    }
    /// Encrypts a scalar exponentiated over a base using ElGamal under the election's tally public key.
    pub(crate) fn exp_encrypt<R: RngCore + CryptoRng>(
        &self,
        value: &G::Scalar,
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::exp_new(value, &self.params.tally, &self.params.elgamal, rng)
    }
    pub(crate) fn into_transcript(&self, transcript: &mut Transcript) {
        transcript.append_point::<G>(b"TALLY", &self.params.tally.h);
        transcript.append_point::<G>(b"G1", &self.params.elgamal.g1);
        transcript.append_point::<G>(b"G2", &self.params.elgamal.g2);
        transcript.append_point::<G>(b"G3", &self.params.g3);
        transcript.append_point::<G>(b"o", &self.params.o);
        transcript.append_point::<G>(b"RT-PK", &self.registration_pk);
    }

    /// Generate verifiable fingerprints of the ballots, used to filter ballots casted with the same private credential
    pub(crate) fn gen_ballot_fingerprints<R: CryptoRng + RngCore>(
        &self,
        // FIX: the naming assume it is ordered, should indeed make this ordered when added timestamps, also understand why this is a list of lists
        wf_ord: Vec<VerVote<G>>,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> VerifiableFingerprints<G> {
        let mut ct_lists = vec![];
        for bal in wf_ord {
            ct_lists.push(bal.auth.ox_enc);
        }
        VerifiableFingerprints::new(vec![ct_lists], rng, transcript)
    }
    /// Eliminate ballots casted with the same credential
    pub(crate) fn filter_duplicates(
        &self,
        wf_ord: Vec<VerVote<G>>,
        bal_fp: VerifiableFingerprints<G>,
        dec_bal_fp: Vec<DecOk<G>>,
        transcript: &mut Transcript,
    ) -> Result<Vec<VerVote<G>>, error::Error> {
        // Input coherence TODO: add a message or something
        if bal_fp.fp_lists.len() != 1 {
            return Err(InvalidSize("".to_string()));
        };
        if bal_fp.fp_lists[0].len() != wf_ord.len() {
            return Err(InvalidSize("".to_string()));
        };
        if wf_ord.len() != dec_bal_fp.len() {
            return Err(InvalidSize("".to_string()));
        };
        for i in 0..dec_bal_fp.len() {
            if bal_fp.fp_lists[0][i] != dec_bal_fp[i].ciphertext {
                return Err(InvalidSize("".to_string()));
            }
        }
        let mut ct_lists = vec![];
        for bal in &wf_ord {
            ct_lists.push(bal.auth.ox_enc);
        }
        bal_fp.verify(&vec![ct_lists], transcript)?;
        for vd in &dec_bal_fp {
            // here we need to define public for each of this verification,
            // a little ugly
            let public = DecOkPublicBorrowed::new(
                &self.params.elgamal,
                &self.params.tally,
                &vd.ciphertext,
                &vd.plaintext,
            );
            DecOkProtocol::verify(public, vd, transcript)?;
        }
        let mut used = HashSet::new();
        let mut filtered = vec![];
        for i in 0..dec_bal_fp.len() {
            // Convert to bytes in order to hash
            let mut buffer = vec![0_u8; G::POINT_SIZE];
            G::point_to_bytes(&mut buffer, &dec_bal_fp[i].plaintext);
            // Check if the fingerprints has already been used
            if used.contains(&buffer) {
                continue;
            }
            used.insert(buffer);
            filtered.push(wf_ord[i].clone())
        }
        Ok(filtered)
    }

    /// Generate the ciphertext used to control the validity of a credential, given an authenticated vote and its control element
    pub(crate) fn gen_credential_check(
        &self,
        vote: &Vote<G>,
        control: &CredentialControlProof<G>,
    ) -> Result<Ciphertext<G>, Error> {
        let public = CredentialControlPublicBorrowed::<G>::new(
            &self.params.g3,
            &self.registration_pk,
            &vote,
            vote.auth.A_enc,
        );

        control.verify(public)?;
        // Subtract the encryption of g1 with zero randomness (which simply is (0, 0, g1))
        let mut check_ct = vote.auth.Ar_enc.hom_sub(&self.params.elgamal.g1);
        check_ct -= vote.auth.g3x_enc;
        check_ct += control.Ay_enc;

        Ok(check_ct)
    }
    /// Eliminate votes associated to invalid credentials.
    /// Returns the index in `votes` together with the surviving vote.
    pub(crate) fn filter_invalid(
        &self,
        votes: &[Vote<G>],
        controls: &[CredentialControlProof<G>],
        ver_decryptions: &[DecOk<G>],
    ) -> Result<Vec<(usize, VoteWithEncPubCred<G>)>, Error> {
        // Lengths must match positionally
        assert_eq!(votes.len(), controls.len());
        assert_eq!(controls.len(), ver_decryptions.len());

        let mut out = Vec::new();

        for i in 0..votes.len() {
            // 1) Verify RT credential control proof
            let public = CredentialControlPublicBorrowed::<G>::new(
                &self.params.g3,
                &self.registration_pk,
                &votes[i],
                votes[i].auth.A_enc,
            );
            controls[i].verify(public)?;

            // 2) Recompute encrypted credential check
            let enc_check = self.gen_credential_check(&votes[i], &controls[i])?;

            // 3) Check TT verifiable decryption consistency
            if ver_decryptions[i].ciphertext != enc_check {
                return Err(Error::FailedVerifiableDecryption(i));
            }

            // 4) Valid credentials decrypt to the identity
            if ver_decryptions[i].plaintext == G::identity() {
                // IMPORTANT: keep the index
                out.push((i, votes[i].clone().strip()));
            }
        }

        Ok(out)
    }


    /// Generate verifiable fingerprints for the encrypted public credentials taken from the shuffled public list and the filtered votes.
    pub(crate) fn gen_credential_fingerprints<R: CryptoRng + RngCore>(
        &self,
        par: &Parameters<G>,
        originals: &[ShortPublicACC<G>],
        shuffled: &[ShortPublicACC<G>],
        proof: &MixedCredentials<G>,
        valid_votes: &[VoteWithEncPubCred<G>],
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<VerifiableFingerprints<G>, Error> {
        // TODO: here we are forking the transcript since we need it both to verify the shuffle and for generating the verifiable fingerprints, possible need a better solution but this might be the less convoluted. Possible we can hard code the trascript, which is something we need to do at some point.
        proof.verify(self, par, originals, shuffled, &mut transcript.clone())?;
        let mut ct_lists = vec![shuffled.iter().map(|a| a.enc_A).collect::<Vec<_>>()];
        ct_lists.push(valid_votes.iter().map(|v| v.A_enc).collect::<Vec<_>>());
        Ok(VerifiableFingerprints::new(ct_lists, rng, transcript))
    }

    /// Filter out votes whose credential is not on the public authorized Sequence, check using the fingerprints.
    pub(crate) fn filter_illicit(
        &self,
        valid_votes: &[VoteWithEncPubCred<G>],
        shuffled: &[ShortPublicACC<G>],
        fingerprints: &VerifiableFingerprints<G>,
        dec_pub_fp: &[DecOk<G>],
        dec_votes_fp: &[DecOk<G>],
        transcript: &mut Transcript,
    ) -> Result<Vec<EncrChoice<G>>, Error> {
        // TODO: too many checks
        assert_eq!(fingerprints.fp_lists.len(), 2);
        assert_eq!(fingerprints.fp_lists[0].len(), shuffled.len());
        assert_eq!(fingerprints.fp_lists[1].len(), valid_votes.len());
        assert_eq!(dec_pub_fp.len(), shuffled.len());
        assert_eq!(dec_votes_fp.len(), valid_votes.len());
        for i in 0..dec_pub_fp.len() {
            assert_eq!(fingerprints.fp_lists[0][i], dec_pub_fp[i].ciphertext);
        }
        for i in 0..dec_votes_fp.len() {
            assert_eq!(fingerprints.fp_lists[1][i], dec_votes_fp[i].ciphertext);
        }

        let mut ct_lists = vec![shuffled.iter().map(|a| a.enc_A).collect::<Vec<_>>()];
        ct_lists.push(valid_votes.iter().map(|v| v.A_enc).collect::<Vec<_>>());

        fingerprints.verify(&ct_lists, transcript)?;

        for i in 0..dec_pub_fp.len() {
            let public = DecOkPublicBorrowed::new(
                &self.params.elgamal,
                &self.params.tally,
                &dec_pub_fp[i].ciphertext,
                &dec_pub_fp[i].plaintext,
            );
            DecOkProtocol::verify(public, &dec_pub_fp[i], transcript)?;
        }

        for i in 0..dec_pub_fp.len() {
            let public = DecOkPublicBorrowed::new(
                &self.params.elgamal,
                &self.params.tally,
                &dec_votes_fp[i].ciphertext,
                &dec_votes_fp[i].plaintext,
            );
            DecOkProtocol::verify(public, &dec_votes_fp[i], transcript)?;
        }

        // Using an HashSet to filter
        let legitimate_fps: HashSet<Vec<u8>> = dec_pub_fp
            .iter()
            .map(|point| {
                let mut bytes = vec![0_u8; G::POINT_SIZE];
                G::point_to_bytes(&mut bytes, &point.plaintext);
                bytes
            })
            .collect();

        let mut legitimate_votes = vec![];
        for i in 0..valid_votes.len() {
            if legitimate_fps.contains(&{
                let mut bytes = vec![0_u8; G::POINT_SIZE];
                G::point_to_bytes(&mut bytes, &dec_votes_fp[i].plaintext);
                bytes
            }) {
                legitimate_votes.push(valid_votes[i].choice.clone());
            }
        }
        Ok(legitimate_votes)
    }

    /// Verify the correctness of a Sequence of credential checks given the mixed votes and the controls
    pub(crate) fn verify_checks(
        &self,
        checks: &[DecOk<G>],
        controls: &[CredentialControlProof<G>],
        shuffled: &[Vote<G>],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        // Check length consistency
        assert_eq!(controls.len(), checks.len());

        for i in 0..shuffled.len() {
            // Generate encrypted checks
            let enc_check = self.gen_credential_check(&shuffled[i], &controls[i])?;
            // Check verifiable decryption
            if checks[i].ciphertext != enc_check {
                return Err(Error::CiphertextMismatch(format!(
                    "check first failed at index {i}"
                )));
            }
            let public = DecOkPublicBorrowed::new(
                &self.params.elgamal,
                &self.params.tally,
                &checks[i].ciphertext,
                &checks[i].plaintext,
            );
            DecOkProtocol::verify(public, &checks[i], transcript)?;
        }

        Ok(())
    }
}

// endregion: ---Election

// region: ---Registration Teller

#[derive(Debug)]
pub(crate) struct RTSecretKey<G: Group> {
    pub(crate) secret_scalar: SecretScalar<G>,
    // Modified ElGamal SecretKey
    pub(crate) meg_sk: SecretKey<G>,
}

impl<G: Group> RTSecretKey<G> {
    pub(crate) fn new<R: RngCore + CryptoRng>(meg_sk: SecretKey<G>, rng: &mut R) -> Self {
        let secret_scalar = SecretScalar::new(rng);
        Self {
            secret_scalar,
            meg_sk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RTPublicKey<G: Group> {
    pub(crate) registration_pk: G::Point,
    pub(crate) meg_pk: ElGamalPublicKey<G>,
}

impl<G: Group> RTPublicKey<G> {
    pub(crate) fn new(sk: &RTSecretKey<G>, params: &ElectionParams<G>) -> Self {
        let meg_pk = ElGamalPublicKey::new_from_params(&sk.meg_sk, &params.elgamal);
        let registration_pk = params.g3 * sk.secret_scalar.expose();

        Self {
            registration_pk,
            meg_pk,
        }
    }
}

#[derive(Debug)]
pub struct RTKeyPair<G: Group> {
    pub(crate) sk: RTSecretKey<G>,
    pub(crate) pk: RTPublicKey<G>,
}

impl<G: Group> RTKeyPair<G> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        meg_sk: SecretKey<G>,
        params: &ElectionParams<G>,
        rng: &mut R,
    ) -> Self {
        let sk = RTSecretKey::new(meg_sk, rng);
        let pk = RTPublicKey::new(&sk, params);

        Self { sk, pk }
    }
    pub fn into_tuple(self) -> (RTSecretKey<G>, RTPublicKey<G>) {
        (self.sk, self.pk)
    }
}

// endregion: ---Registration Teller

// region: ---Tabulation Teller

#[derive(Debug, Clone)]
pub struct TTSecretKey<G: Group> {
    // Modified ElGamal SecretKey
    pub meg_sk: SecretKey<G>,
}

impl<G: Group> TTSecretKey<G> {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            meg_sk: SecretKey::new(rng),
        }
    }
    /// Filter out votes whose credential is not on the public authorized Sequence, check using the fingerprints
    pub(crate) fn decrypt_ballot_fingerprints<R: CryptoRng + RngCore>(
        &self,
        election_pk: &ElectionPublicKey<G>,
        wf_ord: Vec<VerVote<G>>,
        bal_fp: VerifiableFingerprints<G>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Vec<DecOk<G>>, error::Error> {
        // TODO: add len checks
        let mut ct_lists = vec![];
        for bal in &wf_ord {
            ct_lists.push(bal.auth.ox_enc);
        }
        bal_fp.verify(&vec![ct_lists], transcript)?;

        let mut dec_bal_fp = vec![];
        for fp in &bal_fp.fp_lists[0] {
            dec_bal_fp.push(self.meg_sk.ver_decrypt(
                &election_pk.params.elgamal,
                fp,
                transcript,
                rng,
            ))
        }
        Ok(dec_bal_fp)
    }

    /// Filter out votes whose credential is not on the public authorized list, check using the fingerprints.
    pub(crate) fn decrypt_credential_fingerprints<R: CryptoRng + RngCore>(
        &self,
        election_pk: &ElectionPublicKey<G>,
        valid_votes: &Vec<VoteWithEncPubCred<G>>,
        cred_fp: &VerifiableFingerprints<G>,
        shuffled: &Vec<ShortPublicACC<G>>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<(Vec<DecOk<G>>, Vec<DecOk<G>>), error::Error> {
        assert_eq!(cred_fp.fp_lists.len(), 2);
        assert_eq!(cred_fp.fp_lists[0].len(), shuffled.len());
        assert_eq!(cred_fp.fp_lists[1].len(), valid_votes.len());

        let valid_ct = valid_votes.iter().map(|v| v.A_enc).collect::<Vec<_>>();
        let shuffled_ct = shuffled.iter().map(|v| v.enc_A).collect::<Vec<_>>();

        cred_fp.verify(&vec![shuffled_ct, valid_ct], transcript)?;

        let mut dec_cred_fp0 = vec![];
        for fp in &cred_fp.fp_lists[0] {
            dec_cred_fp0.push(self.meg_sk.ver_decrypt(
                &election_pk.params.elgamal,
                fp,
                transcript,
                rng,
            ))
        }
        let mut dec_cred_fp1 = vec![];
        for fp in &cred_fp.fp_lists[1] {
            dec_cred_fp1.push(self.meg_sk.ver_decrypt(
                &election_pk.params.elgamal,
                fp,
                transcript,
                rng,
            ))
        }
        Ok((dec_cred_fp0, dec_cred_fp1))
    }

    pub(crate) fn gen_ACC_checks<R: CryptoRng + RngCore>(
        &self,
        election_pk: &ElectionPublicKey<G>,
        votes: &Vec<Vote<G>>, // TODO: it could be better Vec<&Vote>, elaborate on that, not only here
        controls: &Vec<CredentialControlProof<G>>,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<Vec<DecOk<G>>, Error> {
        let mut ver_decryptions = vec![];
        assert_eq!(controls.len(), votes.len());
        for i in 0..controls.len() {
            let ct = match election_pk.gen_credential_check(&votes[i], &controls[i]) {
                Ok(x) => x,
                Err(_) => return Err(Error::FailedCredentialControl(i)),
            };
            ver_decryptions.push(self.meg_sk.ver_decrypt(
                &election_pk.params.elgamal,
                &ct,
                transcript,
                rng,
            ))
        }
        Ok(ver_decryptions)
    }
    /// Verifiable decryption of an encrypted tally
    pub(crate) fn decrypt_tally<R: RngCore + CryptoRng>(
        &self,
        pk: &ElectionPublicKey<G>,
        tallied: EncrChoice<G>,
        table: &DiscreteLogTable<G>,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<DecryptedTally<G>, DecryptionError> {
        let mut l1_d = vec![];
        let mut l2_d = vec![];
        for i in 0..tallied.l1.len() {
            l1_d.push(
                self.meg_sk
                    .ver_decrypt(&pk.params.elgamal, &tallied.l1[i], transcript, rng),
            );
            let mut temp = vec![];
            for j in 0..tallied.l2[i].len() {
                temp.push(self.meg_sk.ver_decrypt(
                    &pk.params.elgamal,
                    &tallied.l2[i][j],
                    transcript,
                    rng,
                ));
            }
            l2_d.push(temp)
        }
        let mut l1 = vec![];
        let mut l2 = vec![];
        for point in &l1_d {
            match table.get(&point.plaintext) {
                Some(point) => l1.push(point),
                None => return Err(DecryptionError::ElementNotFound),
            }
        }
        for i in &l2_d {
            let mut temp = vec![];
            for point in i {
                match table.get(&point.plaintext) {
                    Some(point) => temp.push(point),
                    None => return Err(DecryptionError::ElementNotFound),
                }
            }
            l2.push(temp)
        }
        Ok(DecryptedTally {
            tally: Tally { l1, l2 },
            l1_d,
            l2_d,
        })
    }
}

// endregion: ---Tabulation Teller

// region: ---Voter

/// Secret information generated by the Voter, including passphrase, share and the secret key used in the designated verifier protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VoterSecretKey<G: Group> {
    pub passphrase: String,
    pub share: Vec<u8>, // bytes
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) sk: G::Scalar,
}

impl<G: Group> VoterSecretKey<G> {
    /// Generate a new random passphrase and compute share and secret key.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let passphrase = generate_passphrase(rng, 6);
        //
        let mut hasher = Shake128::default();
        hasher.update(passphrase.as_bytes());
        let mut reader = hasher.finalize_xof();
        let mut mask = vec![0u8; G::SCALAR_SIZE];
        reader.read(&mut mask);
        //
        let sk = G::scalar_random(rng);
        let mut sk_bytes = vec![0u8; G::SCALAR_SIZE];
        G::scalar_to_bytes(&mut sk_bytes, &sk);
        let share: Vec<u8> = mask
            .iter()
            .zip(sk_bytes.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        //
        Self {
            passphrase: passphrase.to_owned(),
            share,
            sk,
        }
    }
    /// Given a passphrase and share compute the secret key.
    pub fn new_with_passphrase(passphrase: &str, share: Vec<u8>) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(passphrase.as_bytes());
        let mut reader = hasher.finalize_xof();
        let mut mask = vec![0u8; G::SCALAR_SIZE];
        reader.read(&mut mask);
        //
        let sk_bytes: Vec<u8> = mask
            .iter()
            .zip(share.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        //
        // FIX: unwrap() here??
        let sk = G::scalar_from_bytes(&sk_bytes).unwrap();
        Self {
            passphrase: passphrase.to_owned(),
            share,
            sk,
        }
    }
}

/// Public Key generated from the [`VoterSecretKey`] used in the Designated Verifier protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VoterPublicKey<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub(crate) pk: G::Point,
}

impl<G: Group> VoterPublicKey<G> {
    /// Given the Elgamal parameters included in [`ElectionPublicKey`] and the [`VoterSecretKey`] generate the related public key.
    pub(crate) fn new(election_pk: &ElectionPublicKey<G>, voter_sk: &VoterSecretKey<G>) -> Self {
        let pk = election_pk.params.elgamal.g2 * &voter_sk.sk;
        Self { pk }
    }
}

/// Voter key pair used for the designated verifier protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VoterKeyPair<G: Group> {
    pub(crate) sk: VoterSecretKey<G>,
    pub(crate) pk: VoterPublicKey<G>,
}

impl<G: Group> VoterKeyPair<G> {
    /// Given the [`ElectionPublicKey`] generate a new key pair for a voter.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        election_pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let sk = VoterSecretKey::new(rng);
        let pk = VoterPublicKey::new(election_pk, &sk);
        Self { sk, pk }
    }
    /// Given the [`ElectionPublicKey`], passpharase and share generate a new keypair for a voter.
    pub(crate) fn new_with_passphrase(
        election_pk: &ElectionPublicKey<G>,
        passphrase: &str,
        share: Vec<u8>,
    ) -> Self {
        let sk = VoterSecretKey::new_with_passphrase(passphrase, share);
        let pk = VoterPublicKey::new(election_pk, &sk);
        Self { sk, pk }
    }

    pub(crate) fn into_tuple(self) -> (VoterSecretKey<G>, VoterPublicKey<G>) {
        (self.sk, self.pk)
    }
}

// endregion: ---Voter

// // region: ---Test

// #[cfg(test)]
// mod test {
//     use std::{sync::LazyLock, time::Instant};

//     use super::*;
//     use crate::utils::hash_to_emojis;
//     use crate::{
//         api::{
//             client::{BallotBuilder, VoterBuilder},
//             prelude::{RegistrationTeller, TabulationTeller},
//         },
//         core::{
//             tally::{MixedCredentials, MixedVotes},
//             vote::{
//                 auth::{PrivateACC, ShortPublicACC, VotingCredentialBuilder},
//                 choice::{Choice, ChoiceParameters},
//             },
//         },
//     };
//     use dlog_sigma_primitives::{elgamal::keys::SecretKey, pedersen::commitment::Parameters};
//     use rand::{seq::SliceRandom, thread_rng, Rng};

//     use dlog_group::{group::GroupPoint, ristretto::RistrettoGroup};

//     macro_rules! debug_println {
//         ($($arg:tt)*) => (if ::std::cfg!(debug_assertions) { ::std::println!($($arg)*); })
//     }

//     #[test]
//     fn ballot_fingerprints() {
//         // Setup RT.
//         let mut rng = thread_rng();
//         let tt_sk: TTSecretKey<RistrettoGroup> = TTSecretKey::new(&mut rng);
//         let elgamal = ElGamalParams::new(&mut rng);
//         let params: ElectionParams<RistrettoGroup> =
//             ElectionParams::new(&elgamal, &tt_sk.meg_sk.to_public(&elgamal), &mut rng);
//         let rt = RegistrationTeller::new(params, &mut rng);
//         let election_pk = rt.election_pk();

//         // Choice, it is the same for both ballot.
//         let choice_parameters = ChoiceParameters::new(3, vec![9, 13, 5], false).unwrap();
//         let choice = Choice::new(2, vec![4], &choice_parameters).unwrap();

//         // Generate ACCs and builder credentials
//         let (builder1, pin1, _) = rt.gen_builder(&mut rng);
//         let (builder2, pin2, _) = rt.gen_builder(&mut rng);
//         println!("PIN1: {:?}", &serde_json::to_value(pin1));
//         println!("PIN2: {:?}", &serde_json::to_value(pin2));

//         // Generate Voter builder
//         let voter_builder1 = VoterBuilder::new(&election_pk, builder1.clone(), &mut rng);
//         let voter_builder2 = VoterBuilder::new(&election_pk, builder2.clone(), &mut rng);

//         // Generate the Voting Credential
//         let voting_credential1 = rt
//             .gen_credential(&voter_builder1.voter_pk(), &builder1, &mut rng)
//             .unwrap();
//         let voting_credential2 = rt
//             .gen_credential(&voter_builder2.voter_pk(), &builder2, &mut rng)
//             .unwrap();

//         // Finalize the Voter storing the Voting Credential
//         let voter1 = voter_builder1.finalize(voting_credential1);
//         let voter2 = voter_builder2.finalize(voting_credential2);

//         // Ballot
//         let ballot_builder1 = BallotBuilder::new(choice, choice_parameters);
//         let ballot_builder2 = ballot_builder1.clone();

//         // Vote
//         let ballot1 = voter1.vote(&ballot_builder1, pin1, &mut rng);
//         let ballot2 = voter2.vote(&ballot_builder2, pin2, &mut rng);

//         // Add a third vote made by voter 1
//         let ballot3 = voter1.vote(&ballot_builder1, pin1, &mut rng);

//         let wf_ord = vec![ballot1.ver_vote, ballot2.ver_vote, ballot3.ver_vote];

//         let mut transcript = Transcript::new(b"test");
//         let bal_fp = election_pk.gen_ballot_fingerprints(wf_ord.clone(), &mut rng, &mut transcript);

//         let mut transcript = Transcript::new(b"test");
//         let dec_bal_fp = tt_sk
//             .decrypt_ballot_fingerprints(
//                 &election_pk,
//                 wf_ord.clone(),
//                 bal_fp.clone(),
//                 &mut transcript,
//                 &mut rng,
//             )
//             .unwrap();

//         let mut transcript1 = Transcript::new(b"test");
//         let filtered = election_pk
//             .filter_duplicates(wf_ord.clone(), bal_fp, dec_bal_fp, &mut transcript1)
//             .unwrap();

//         // Finally check that the third ballot has been correctly removed
//         assert_eq!(wf_ord.len(), 3);
//         assert_eq!(filtered.len(), 2);
//     }

//     #[test]
//     fn emoji() {
//         // Setup RT.
//         let mut rng = thread_rng();
//         let tt_sk: TTSecretKey<RistrettoGroup> = TTSecretKey::new(&mut rng);
//         let elgamal = ElGamalParams::new(&mut rng);
//         let params: ElectionParams<RistrettoGroup> =
//             ElectionParams::new(&elgamal, &tt_sk.meg_sk.to_public(&elgamal), &mut rng);
//         let rt = RegistrationTeller::new(params, &mut rng);
//         let election_pk = rt.election_pk();

//         // Hash to emoji of different length
//         let bytes = serde_cbor::to_vec(&election_pk).unwrap();
//         let emoji4 = hash_to_emojis(&bytes, 4);
//         let emoji8 = hash_to_emojis(&bytes, 8);

//         assert_eq!(emoji4[0..4], emoji8[0..4]);

//         let mut bytes_mod = bytes.clone();
//         bytes_mod.push(0);
//         let emoji4_mod = hash_to_emojis(&bytes_mod, 4);

//         assert_ne!(emoji4[0..4], emoji4_mod[0..4])
//     }

//     #[test]
//     fn voting_and_tallying() {
//         // Table
//         static DLOG_TABLE: LazyLock<DiscreteLogTable<RistrettoGroup>> =
//             LazyLock::new(|| DiscreteLogTable::new(0..100));
//         // Test params
//         let num_voters = 3;
//         println!("NUMBER OF VOTERS: {}", num_voters);
//         // Setup RT.
//         let mut rng = thread_rng();
//         let tt_sk: TTSecretKey<RistrettoGroup> = TTSecretKey::new(&mut rng);
//         let elgamal = ElGamalParams::new(&mut rng);
//         let params: ElectionParams<RistrettoGroup> =
//             ElectionParams::new(&elgamal, &tt_sk.meg_sk.to_public(&elgamal), &mut rng);
//         let rt = RegistrationTeller::new(params, &mut rng);
//         let election_pk = rt.election_pk();

//         // Choice, it is the same for both ballot.
//         let choice_parameters = ChoiceParameters::new(3, vec![3, 3, 3], false).unwrap();
//         let choice = Choice::new(2, vec![2], &choice_parameters).unwrap();

//         println!(
//             "POSSIBLE CHOICES:\n    PARTIES: {} \n    CANDIDATES: {:?}",
//             choice_parameters.n1, choice_parameters.ln2
//         );

//         // Generate ACCs and builder credentials
//         let builder_list: Vec<(VotingCredentialBuilder<RistrettoGroup>, usize, _)> =
//             (0..num_voters).map(|_| rt.gen_builder(&mut rng)).collect();
//         // Generate Voter builder
//         let voter_builder_list = (0..num_voters)
//             .map(|i| VoterBuilder::new(&election_pk, builder_list[i].0.clone(), &mut rng))
//             .collect::<Vec<_>>();
//         // Generate the Voting Credential
//         let voting_credential_list = (0..num_voters)
//             .map(|i| {
//                 rt.gen_credential(
//                     &voter_builder_list[i].voter_pk(),
//                     &builder_list[i].0,
//                     &mut rng,
//                 )
//                 .unwrap()
//             })
//             .collect::<Vec<_>>();
//         // Finalize the Voter storing the Voting Credential
//         let voter_list = (0..num_voters)
//             .map(|i| {
//                 voter_builder_list[i]
//                     .clone()
//                     .finalize(voting_credential_list[i].clone())
//             })
//             .collect::<Vec<_>>();
//         // Ballot
//         let ballot_builder_list = (0..num_voters)
//             .map(|_| BallotBuilder::new(choice.clone(), choice_parameters.clone()))
//             .collect::<Vec<_>>();
//         // Vote
//         let originals = (0..num_voters)
//             .map(|i| voter_list[i].vote(&ballot_builder_list[i], builder_list[i].1, &mut rng))
//             .collect::<Vec<_>>();

//         // Given the Ballots mix and re-encrypt, but before extract only the votes since ftm we lack an outer function on the ballots.
//         // Extract and verify vote
//         let vote_list = (0..num_voters)
//             .map(|i| {
//                 originals[i]
//                     .ver_vote
//                     .verify(&election_pk, &choice_parameters)
//                     .unwrap()
//             })
//             .collect::<Vec<_>>();
//         // To check filtering we add a copy of the first vote

//         // Generate pedersen parameters
//         let ped_params = Parameters::<RistrettoGroup>::new(num_voters, &mut rng);
//         // Generate a random permutation and shuffle the list
//         let start = Instant::now();
//         let mut perm: Vec<usize> = (0..ped_params.list_len).collect();
//         perm.shuffle(&mut rng);
//         let shuffled = perm
//             .iter()
//             .map(|&i| {
//                 originals[i]
//                     .ver_vote
//                     .verify(&election_pk, &choice_parameters)
//                     .unwrap()
//                     .re_encrypt(&election_pk, &mut rng)
//             })
//             .collect::<Vec<_>>();
//         // Initialize new Transcript
//         let mut transcript = Transcript::new(b"test");
//         // Mix
//         let mix_vote_list = MixedVotes::new(
//             &election_pk,
//             &ped_params,
//             &perm,
//             &shuffled,
//             &choice_parameters,
//             &mut rng,
//             &mut transcript,
//         );
//         let duration1 = start.elapsed();
//         // Serialize the shuffled vector
//         let mut json_list = vec![];
//         let json_bytes = serde_json::to_vec(&shuffled[0].clone().to_vote()).unwrap();
//         for extended in shuffled {
//             json_list.push(serde_json::to_value(extended.to_vote()).unwrap());
//         }
//         println!(
//             "EXAMPLE OF A SINGLE SHUFFLED VOTE ({} BYTES):\n {:#?}",
//             json_bytes.len(),
//             json_list[0]
//         );

//         // Serialize the mix proof
//         let json = serde_json::to_value(mix_vote_list.clone()).unwrap();
//         let json_bytes = serde_json::to_vec(&mix_vote_list).unwrap();
//         println!(
//             "EXAMPLE OF A SERIALIZED MIXED-PROOF ({} BYTES):\n {:#?}",
//             json_bytes.len(),
//             json
//         );

//         // Deserialize
//         let de: MixedVotes<RistrettoGroup> = serde_json::from_value(json).unwrap();
//         let vote_shuffled = json_list
//             .iter()
//             .map(|json| serde_json::from_value(json.clone()).unwrap())
//             .collect::<Vec<Vote<RistrettoGroup>>>();

//         // Verify the mix
//         let mut transcript = Transcript::new(b"test");
//         let start = Instant::now();
//         de.verify(
//             &election_pk,
//             &ped_params,
//             &choice_parameters,
//             &vote_list,
//             &vote_shuffled,
//             &mut transcript,
//         )
//         .unwrap();
//         let duration = start.elapsed();
//         println!("Mix and re-encrypt took: {:?}", duration1);
//         println!("Verification took: {:?}", duration);
//         debug_println!("NOTE: those are debug timings without compiler optimizations.");

//         let controls = rt.gen_controls(&vote_shuffled, &mut rng);

//         let tab_teller = TabulationTeller::new(tt_sk.clone(), &election_pk);

//         let ver_decryptions = tab_teller
//             .gen_acc_checks(&vote_shuffled, &controls, &mut rng)
//             .unwrap();

//         println!(
//             "IDENTITY: {:?} \n",
//             hash_to_emojis(&serde_cbor::to_vec(&RistrettoGroup::identity()).unwrap(), 3)
//         );
//         for i in ver_decryptions.clone() {
//             println!(
//                 "{:?}",
//                 hash_to_emojis(&serde_cbor::to_vec(&i.plaintext).unwrap(), 3)
//             )
//         }

//         // TODO: check wellness of errors
//         let valid = election_pk
//             .filter_invalid(&vote_shuffled, &controls, &ver_decryptions)
//             .unwrap();

//         let valid: Vec<VoteWithEncPubCred<RistrettoGroup>> = valid.into_iter().map(|(_, v)| v).collect();

//         assert_eq!(3, valid.len());

//         // Generate new Pedersen parameters for ACC shuffle
//         let ped_par_cred = Parameters::<RistrettoGroup>::new(num_voters, &mut rng);
//         // Construct a list of ShortPublicACC in order to shuffle them
//         let pub_cred_list = builder_list
//             .iter()
//             .map(|(_a, _b, c)| c.verify(&election_pk).unwrap())
//             .collect::<Vec<ShortPublicACC<RistrettoGroup>>>();
//         // Generate a random permutation and shuffle the list
//         let start = Instant::now();
//         let mut perm: Vec<usize> = (0..ped_par_cred.list_len).collect();
//         perm.shuffle(&mut rng);
//         let shuffled = perm
//             .iter()
//             .map(|&i| pub_cred_list[i].re_encrypt(&election_pk, &mut rng))
//             .collect::<Vec<_>>();
//         // Initialize new Transcript
//         let mut transcript = Transcript::new(b"test");
//         // Mix
//         let mix = MixedCredentials::new(
//             &election_pk,
//             &ped_par_cred,
//             &perm,
//             &shuffled,
//             &mut rng,
//             &mut transcript,
//         );
//         let duration1 = start.elapsed();
//         // Serialize the shuffled vector
//         let mut json_list = vec![];
//         for extended in shuffled {
//             json_list.push(serde_json::to_value(extended.to_short()).unwrap());
//         }
//         // Deserialize
//         let shuffled = json_list
//             .iter()
//             .map(|json| serde_json::from_value(json.clone()).unwrap())
//             .collect::<Vec<ShortPublicACC<RistrettoGroup>>>();
//         // Verify the mix
//         let mut transcript = Transcript::new(b"test");
//         let start = Instant::now();
//         mix.verify(
//             &election_pk,
//             &ped_par_cred,
//             &pub_cred_list,
//             &shuffled,
//             &mut transcript,
//         )
//         .unwrap();
//         let duration = start.elapsed();

//         println!("Mix and re-encrypt Credentials took: {:?}", duration1);
//         println!("Verification took: {:?}", duration);
//         debug_println!("NOTE: those are debug timings without compiler optimizations.");

//         println!("\n EXPECTED RESULT:\n PARTY: 2x{num_voters}\n CANDIDATE: 2x{num_voters}\n");

//         let mut transcript = Transcript::new(b"test");
//         let fingerprints = election_pk
//             .gen_credential_fingerprints(
//                 &ped_par_cred,
//                 &pub_cred_list,
//                 &shuffled,
//                 &mix,
//                 &valid,
//                 &mut rng,
//                 &mut transcript,
//             )
//             .unwrap();

//         let mut transcript = Transcript::new(b"test");
//         let (d_pub_fps, d_votes_fps) = tt_sk
//             .decrypt_credential_fingerprints(
//                 &election_pk,
//                 &valid,
//                 &fingerprints,
//                 &shuffled,
//                 &mut transcript,
//                 &mut rng,
//             )
//             .unwrap();

//         let mut transcript = Transcript::new(b"test");
//         let legitimate = election_pk
//             .filter_illicit(
//                 &valid,
//                 &shuffled,
//                 &fingerprints,
//                 &d_pub_fps,
//                 &d_votes_fps,
//                 &mut transcript,
//             )
//             .unwrap();

//         let mut enc_tally = EncrChoice::identity(&choice_parameters);
//         for choice in legitimate {
//             enc_tally += choice;
//         }

//         let mut transcript = Transcript::new(b"test");
//         let decr_tal = tt_sk
//             .decrypt_tally(
//                 &election_pk,
//                 enc_tally.clone(),
//                 &DLOG_TABLE,
//                 &mut rng,
//                 &mut transcript,
//             )
//             .unwrap();

//         let mut transcript = Transcript::new(b"acc-checks");
//         election_pk
//             .verify_checks(&ver_decryptions, &controls, &vote_shuffled, &mut transcript)
//             .unwrap();

//         let mut transcript = Transcript::new(b"test");
//         decr_tal
//             .verify(
//                 &election_pk.params.tally,
//                 &election_pk.params.elgamal,
//                 &enc_tally,
//                 &mut transcript,
//             )
//             .unwrap();
//     }
// }

// // endregion: ---Test
