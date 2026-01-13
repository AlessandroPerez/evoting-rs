//! tally
//!

use std::marker::PhantomData;

use dlog_group::group::Group;
use dlog_group::serde::{PointHelper, ScalarHelper, VecHelper};
use dlog_sigma_primitives::elgamal::keys::SecretScalar;
use dlog_sigma_primitives::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey},
    },
    pedersen::commitment::Parameters,
    proofs::{
        shuffle::{Shuffle, ShuffleBuilder},
        ver_decr::{DecOk, DecOkProtocol, DecOkPublicBorrowed},
        zero::Zero,
        Proof, SigmaProtocol, TranscriptForGroup,
    },
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    core::keys::{ElectionPublicKey, RTSecretKey},
    core::vote::{
        auth::{ExtendedShortPublicACC, ShortPublicACC},
        choice::{ChoiceParameters, EncrChoice},
        vote::{ExtendedVote, Vote},
    },
    error::Error,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MixedVotes<G: Group> {
    core_proof: Shuffle<G>,
    // Additonal parameters to check re-encryption
    ed_L1: Vec<Ciphertext<G>>,
    ed_L2: Vec<Vec<Ciphertext<G>>>,
    ed_A: Ciphertext<G>,
    ed_Ar: Ciphertext<G>,
    ed_g3x: Ciphertext<G>,
    //
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    z_L1: Vec<G::Scalar>,
    // FIX: this should be a Vec<Vec<_>> but need to change serialization
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    z_L2: Vec<G::Scalar>,
    #[serde(with = "ScalarHelper::<G>")]
    z_A: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    z_Ar: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    z_g3x: G::Scalar,
}

impl<G: Group> MixedVotes<G> {
    /// Verifiably mix the ballots. The idea is to apply [JG05] to all the encrypted elements in the ballots, which means computing a LOT of intermediate E_d values, one for each encrypted element.
    pub(crate) fn new<R>(
        pk: &ElectionPublicKey<G>,
        ped_params: &Parameters<G>,
        perm: &Vec<usize>,
        shuffled: &Vec<ExtendedVote<G>>,
        choice_params: &ChoiceParameters,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Self
    where
        // evaluate to use this maybe in a higher level I: IntoIterator<Item = Vote<G>>,
        R: RngCore + CryptoRng,
    {
        // NIZKP computation, TODO: understand if we need to iterate;
        // Initialize ZKP builder
        let builder = ShuffleBuilder::new(ped_params, perm, rng);

        // Generate the E_d related to the Choice
        let mut ed_L1 = vec![];
        let mut ed_L2 = vec![vec![]; choice_params.n1];
        // Store randomness putside in order to avoid possibly expensive conversions later
        let mut r_ed_L1 = vec![];
        let mut r_ed_L2 = vec![vec![]; choice_params.n1];
        for i in 0..choice_params.n1 {
            let temp = builder.get_e_d(
                &pk.params.tally,
                &pk.params.elgamal,
                &shuffled
                    .iter()
                    .map(|v| v.choice.l1[i].inner)
                    .collect::<Vec<_>>(),
                rng,
            );
            // Update transcript
            transcript.append_ciphertext(b"", &temp.inner);
            // Update list
            r_ed_L1.push(*temp.expose());
            ed_L1.push(temp.inner);

            for j in 0..choice_params.ln2[i] {
                let temp = builder.get_e_d(
                    &pk.params.tally,
                    &pk.params.elgamal,
                    &shuffled
                        .iter()
                        .map(|v| v.choice.l2[i][j].inner)
                        .collect::<Vec<_>>(),
                    rng,
                );
                transcript.append_ciphertext(b"", &temp.inner);
                r_ed_L2[i].push(*temp.expose());
                ed_L2[i].push(temp.inner);
            }
        }
        // Generate E_d related to AuthValues
        let ed_A = builder.get_e_d(
            &pk.params.tally,
            &pk.params.elgamal,
            &shuffled
                .iter()
                .map(|v| v.auth.A_enc.inner)
                .collect::<Vec<_>>(),
            rng,
        );
        transcript.append_ciphertext(b"", &ed_A.inner);

        let ed_Ar = builder.get_e_d(
            &pk.params.tally,
            &pk.params.elgamal,
            &shuffled
                .iter()
                .map(|v| v.auth.Ar_enc.inner)
                .collect::<Vec<_>>(),
            rng,
        );
        transcript.append_ciphertext(b"", &ed_Ar.inner);

        let ed_g3x = builder.get_e_d(
            &pk.params.tally,
            &pk.params.elgamal,
            &shuffled
                .iter()
                .map(|v| v.auth.g3x_enc.inner)
                .collect::<Vec<_>>(),
            rng,
        );
        transcript.append_ciphertext(b"", &ed_g3x.inner);

        // Before computing f we update with commit_d
        builder.update_transcript1(transcript);

        // Update transcript with the values included in the builder
        let (f_list, t_list) = builder.compute_t(perm, transcript);

        // Compute Z = /sum{t_iR_i} + R_d // TODO: this can be optimize
        let mut z_L1 = vec![];
        let mut z_L2 = vec![];
        for i in 0..choice_params.n1 {
            let mut temp = r_ed_L1[i];
            for k in 0..ped_params.list_len {
                temp += t_list[perm[k]] * shuffled[k].choice.l1[i].expose();
            }
            z_L1.push(temp);
            for j in 0..choice_params.ln2[i] {
                let mut temp = r_ed_L2[i][j];
                for k in 0..ped_params.list_len {
                    temp += t_list[perm[k]] * shuffled[k].choice.l2[i][j].expose();
                }
                z_L2.push(temp);
            }
        }
        let mut z_A = *ed_A.expose();
        for i in 0..ped_params.list_len {
            z_A += t_list[perm[i]] * shuffled[i].auth.A_enc.expose();
        }

        let mut z_Ar = *ed_Ar.expose();
        for i in 0..ped_params.list_len {
            z_Ar += t_list[perm[i]] * shuffled[i].auth.Ar_enc.expose();
        }

        let mut z_g3x = *ed_g3x.expose();
        for i in 0..ped_params.list_len {
            z_g3x += t_list[perm[i]] * shuffled[i].auth.g3x_enc.expose();
        }

        builder.update_transcript2(transcript, &f_list);

        let core_proof = builder.complete(ped_params, &f_list, &t_list, perm, transcript, rng);

        Self {
            core_proof,
            ed_L1,
            ed_L2,
            ed_A: ed_A.inner,
            ed_Ar: ed_Ar.inner,
            ed_g3x: ed_g3x.inner,
            z_L1,
            z_L2,
            z_A,
            z_Ar,
            z_g3x,
        }
    }

    pub(crate) fn verify(
        &self,
        pk: &ElectionPublicKey<G>,
        ped_params: &Parameters<G>,
        choice_params: &ChoiceParameters,
        originals: &Vec<Vote<G>>,
        shuffled: &Vec<Vote<G>>,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        // add length checks and ciphertext validity
        assert_eq!(ped_params.list_len, originals.len(), "Length Check Failed!");

        // Update transcript

        for i in 0..choice_params.n1 {
            transcript.append_ciphertext(b"", &self.ed_L1[i]);
            for j in 0..choice_params.ln2[i] {
                transcript.append_ciphertext(b"", &self.ed_L2[i][j]);
            }
        }
        transcript.append_ciphertext(b"", &self.ed_A);
        transcript.append_ciphertext(b"", &self.ed_Ar);
        transcript.append_ciphertext(b"", &self.ed_g3x);

        // Check the core proof
        let t_list = self.core_proof.verify(ped_params, transcript)?;

        // Check re-encryption
        for i in 0..choice_params.n1 {
            self.core_proof.check_re_encryption(
                &pk.params.tally,
                &pk.params.elgamal,
                &self.ed_L1[i],
                &self.z_L1[i],
                &t_list,
                &originals.iter().map(|v| v.choice.l1[i]).collect::<Vec<_>>(),
                &shuffled.iter().map(|v| v.choice.l1[i]).collect::<Vec<_>>(),
            )?;
        }

        for i in 0..choice_params.n1 {
            for j in 0..choice_params.ln2[i] {
                self.core_proof.check_re_encryption(
                    &pk.params.tally,
                    &pk.params.elgamal,
                    &self.ed_L2[i][j],
                    &self.z_L2[i * choice_params.ln2[i] + j],
                    &t_list,
                    &originals
                        .iter()
                        .map(|v| v.choice.l2[i][j])
                        .collect::<Vec<_>>(),
                    &shuffled
                        .iter()
                        .map(|v| v.choice.l2[i][j])
                        .collect::<Vec<_>>(),
                )?;
            }
        }

        self.core_proof.check_re_encryption(
            &pk.params.tally,
            &pk.params.elgamal,
            &self.ed_A,
            &self.z_A,
            &t_list,
            &originals.iter().map(|v| v.auth.A_enc).collect::<Vec<_>>(),
            &shuffled.iter().map(|v| v.auth.A_enc).collect::<Vec<_>>(),
        )?;

        self.core_proof.check_re_encryption(
            &pk.params.tally,
            &pk.params.elgamal,
            &self.ed_Ar,
            &self.z_Ar,
            &t_list,
            &originals.iter().map(|v| v.auth.Ar_enc).collect::<Vec<_>>(),
            &shuffled.iter().map(|v| v.auth.Ar_enc).collect::<Vec<_>>(),
        )?;

        self.core_proof.check_re_encryption(
            &pk.params.tally,
            &pk.params.elgamal,
            &self.ed_g3x,
            &self.z_g3x,
            &t_list,
            &originals.iter().map(|v| v.auth.g3x_enc).collect::<Vec<_>>(),
            &shuffled.iter().map(|v| v.auth.g3x_enc).collect::<Vec<_>>(),
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MixedCredentials<G: Group> {
    core_proof: Shuffle<G>,
    // Additonal parameters to check re-encryption
    e_d: Ciphertext<G>,
    //
    #[serde(with = "ScalarHelper::<G>")]
    z: G::Scalar,
}

impl<G: Group> MixedCredentials<G> {
    /// Generate a Shuffle proof of PublicACC
    pub(crate) fn new<R: RngCore + CryptoRng>(
        pk: &ElectionPublicKey<G>,
        ped_params: &Parameters<G>,
        perm: &Vec<usize>,
        shuffled: &Vec<ExtendedShortPublicACC<G>>,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Self {
        // TODO:
        assert_eq!(ped_params.list_len, shuffled.len(), "Length Check Failed!");

        // Initialize ZKP builder
        let builder = ShuffleBuilder::new(ped_params, perm, rng);

        let e_d = builder.get_e_d(
            &pk.params.tally,
            &pk.params.elgamal,
            &shuffled.iter().map(|v| v.enc_A.inner).collect::<Vec<_>>(),
            rng,
        );
        transcript.append_ciphertext(b"", &e_d.inner);
        builder.update_transcript1(transcript);
        let (f_list, t_list) = builder.compute_t(perm, transcript);

        let mut z = *e_d.expose();
        for i in 0..ped_params.list_len {
            z += t_list[perm[i]] * shuffled[i].enc_A.expose();
        }

        builder.update_transcript2(transcript, &f_list);

        let core_proof = builder.complete(ped_params, &f_list, &t_list, perm, transcript, rng);

        Self {
            core_proof,
            e_d: e_d.inner,
            z,
        }
    }

    pub(crate) fn verify(
        &self,
        pk: &ElectionPublicKey<G>,
        ped_params: &Parameters<G>,
        originals: &[ShortPublicACC<G>],
        shuffled: &[ShortPublicACC<G>],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        assert_eq!(ped_params.list_len, originals.len(), "Length Check Failed!");
        // Update transcript
        transcript.append_ciphertext(b"", &self.e_d);
        // Check the core proof
        let t_list = self.core_proof.verify(ped_params, transcript)?;
        // Check re-encryption
        self.core_proof.check_re_encryption(
            &pk.params.tally,
            &pk.params.elgamal,
            &self.e_d,
            &self.z,
            &t_list,
            &originals.iter().map(|v| v.enc_A).collect::<Vec<_>>(),
            &shuffled.iter().map(|v| v.enc_A).collect::<Vec<_>>(),
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CredentialControlPublicBorrowed<'a, G: Group> {
    pub g3: &'a G::Point,
    pub registration_pk: &'a G::Point,

    // authenticated vote (needed for transcript binding)
    pub vote: &'a Vote<G>,

    // DLEQ pair over ciphertext group
    pub A_enc: Ciphertext<G>,
}

impl<'a, G: Group> CredentialControlPublicBorrowed<'a, G> {
    pub fn new(
        g3: &'a G::Point,
        registration_pk: &'a G::Point,
        vote: &'a Vote<G>,
        A_enc: Ciphertext<G>,
    ) -> Self {
        Self {
            g3,
            registration_pk,
            vote,
            A_enc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CredentialControlProof<G: Group> {
    /// Ay_enc = [sk_rt]A_enc
    pub Ay_enc: Ciphertext<G>,

    /// I_ct = [t]A_enc
    pub I_ct: Ciphertext<G>,

    /// I_pk = [t]g3
    #[serde(with = "PointHelper::<G>")]
    pub I_pk: G::Point,

    /// z = t + c·sk
    #[serde(with = "ScalarHelper::<G>")]
    pub z: G::Scalar,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct CredentialControlState<G: Group> {
    pub t: SecretScalar<G>,
    pub A_enc: Option<Ciphertext<G>>,
    pub I_ct: Option<Ciphertext<G>>,
    pub I_pk: Option<G::Point>,
}

pub struct CredentialControlProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for CredentialControlProtocol<G> {
    const DOMAIN: &'static [u8] = b"CREDENTIAL-CONTROL";

    type Public<'a> = CredentialControlPublicBorrowed<'a, G>;
    type Witness = SecretScalar<G>;
    type Proof = CredentialControlProof<G>;
    type State = CredentialControlState<G>;

    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        // Bind to election statement
        tr.append_point::<G>(b"g3", public.g3);
        tr.append_point::<G>(b"reg_pk", public.registration_pk);

        // Bind to the vote (exactly like your code)
        tr.append_bytes(b"vote", &public.vote.to_bytes());

        // Bind to ciphertext statement
        tr.append_ciphertext::<G>(b"A_enc", &public.A_enc);
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        Self::State {
            t: SecretScalar::new(rng),
            A_enc: Some(public.A_enc),
            I_ct: None,
            I_pk: None,
        }
    }

    fn commit(
        public: Self::Public<'_>,
        st: &mut Self::State,
        _witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        // Commitments: I_ct = [t]A_enc, I_pk = [t]g3
        let I_ct = public.A_enc * st.t.expose();
        let I_pk = *public.g3 * st.t.expose();

        // Must be replayed verbatim in update_transcript
        tr.append_ciphertext::<G>(b"I_ct=[t]A_enc", &I_ct);
        tr.append_point::<G>(b"I_pk=[t]g3", &I_pk);

        st.I_ct = Some(I_ct);
        st.I_pk = Some(I_pk);
    }

    fn complete(st: Self::State, witness: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        let c = tr.challenge_scalar::<G>(b"c");

        // z = t + c·sk
        let z = c * witness.expose() + st.t.expose();

        let Ay_enc = st.A_enc.unwrap() * witness.expose();

        CredentialControlProof {
            I_ct: st.I_ct.expect("commit must run before complete"),
            I_pk: st.I_pk.expect("commit must run before complete"),
            z,
            Ay_enc,
        }
    }

    fn update_transcript(
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        // Replay commitments exactly as prover did
        tr.append_ciphertext::<G>(b"I_ct=[t]A_enc", &proof.I_ct);
        tr.append_point::<G>(b"I_pk=[t]g3", &proof.I_pk);
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        let c = tr.challenge_scalar::<G>(b"c");

        // Ciphertext-side: [z]A_enc == I_ct + [c]Ay_enc
        let lhs_ct = public.A_enc * &proof.z;
        let rhs_ct = proof.I_ct + (proof.Ay_enc * &c);
        if lhs_ct != rhs_ct {
            return Err(dlog_sigma_primitives::error::Error::CommitmentMismatch);
        }

        // Group-side: [z]g3 == I_pk + [c]reg_pk
        let lhs_pk = (*public.g3) * &proof.z;
        let rhs_pk = proof.I_pk + &((*public.registration_pk) * &c);
        if lhs_pk != rhs_pk {
            return Err(dlog_sigma_primitives::error::Error::CommitmentMismatch);
        }

        Ok(())
    }
}

impl<G: Group> Proof for CredentialControlProof<G> {
    type Protocol = CredentialControlProtocol<G>;
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DecryptedTally<G: Group> {
    pub tally: Tally,
    pub(crate) l1_d: Vec<DecOk<G>>,
    pub(crate) l2_d: Vec<Vec<DecOk<G>>>,
}

impl<G: Group> DecryptedTally<G> {
    /// Verify correctness of a tally given the talliers' public key and the encrypted sum of the votes
    pub(crate) fn verify(
        &self,
        pk: &PublicKey<G>,
        params: &ElGamalParams<G>,
        enc_tally: &EncrChoice<G>,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        for i in 0..enc_tally.l1.len() {
            // Party checks
            // First check the encryptions
            if enc_tally.l1[i] != self.l1_d[i].ciphertext {
                return Err(Error::CiphertextMismatch(format!(
                    "check first failed at layer l1, index {i}"
                )));
            }
            let public = DecOkPublicBorrowed::new(
                &params,
                &pk,
                &self.l1_d[i].ciphertext,
                &self.l1_d[i].plaintext,
            );
            DecOkProtocol::verify(public, &self.l1_d[i], transcript)?;
            // Verify DLOG
            if G::generator() * &G::Scalar::from(self.tally.l1[i]) != self.l1_d[i].plaintext {
                return Err(Error::DlogMismatch(format!(
                    "check first failed at layer l1, index {i}"
                )));
            }
            // Candidates checks
            for j in 0..enc_tally.l2[i].len() {
                // First check the encryptions
                if enc_tally.l2[i][j] != self.l2_d[i][j].ciphertext {
                    return Err(Error::CiphertextMismatch(format!(
                        "check first failed at layer l2, index ({i},{j})"
                    )));
                }
                let public = DecOkPublicBorrowed::new(
                    &params,
                    &pk,
                    &self.l2_d[i][j].ciphertext,
                    &self.l2_d[i][j].plaintext,
                );
                DecOkProtocol::verify(public, &self.l2_d[i][j], transcript)?;
                // Verify DLOG
                if G::generator() * &G::Scalar::from(self.tally.l2[i][j])
                    != self.l2_d[i][j].plaintext
                {
                    return Err(Error::DlogMismatch(format!(
                        "check first failed at layer l2, index ({i},{j})"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct Tally {
    pub(crate) l1: Vec<u64>,
    pub(crate) l2: Vec<Vec<u64>>,
}

// // region: ---Test

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{
//         api::{
//             client::{BallotBuilder, VoterBuilder},
//             prelude::RegistrationTeller,
//         },
//         core::{
//             keys::{ElectionParams, TTSecretKey},
//             vote::{
//                 auth::{PublicACC, VotingCredentialBuilder},
//                 choice::{Choice, ChoiceParameters},
//             },
//         },
//     };
//     use rand::{seq::SliceRandom, thread_rng};

//     use dlog_group::ristretto::RistrettoGroup;

//     use std::time::Instant;

//     macro_rules! debug_println {
//         ($($arg:tt)*) => (if ::std::cfg!(debug_assertions) { ::std::println!($($arg)*); })
//     }

//     #[test]
//     fn credential_control() {
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

//         // Generate ACC and builder credential
//         let builder: (VotingCredentialBuilder<RistrettoGroup>, usize, _) = rt.gen_builder(&mut rng);
//         // Generate Voter builder
//         let voter_builder = VoterBuilder::new(&election_pk, builder.0.clone(), &mut rng);
//         // Generate the Voting Credential
//         let voting_credential = rt
//             .gen_credential(&voter_builder.voter_pk(), &builder.0, &mut rng)
//             .unwrap();
//         // Finalize the Voter storing the Voting Credential
//         let voter = voter_builder.clone().finalize(voting_credential.clone());
//         // Ballot
//         let ballot_builder = BallotBuilder::new(choice.clone(), choice_parameters.clone());
//         // Vote
//         let vote = voter
//             .vote(&ballot_builder, builder.1, &mut rng)
//             .verify(&election_pk)
//             .unwrap();

//         let public = CredentialControlPublicBorrowed::<RistrettoGroup>::new(
//             &election_pk.params.g3,
//             &election_pk.registration_pk,
//             &vote,
//             vote.auth.A_enc,
//         );

//         let proof = CredentialControlProof::<RistrettoGroup>::prove(
//             public,
//             &rt.keypair.sk.secret_scalar,
//             &mut rng,
//         );
//         proof.verify(public).unwrap();
//     }

//     #[test]
//     fn ballot_mixing() {
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
//         let builder_list: Vec<(
//             VotingCredentialBuilder<RistrettoGroup>,
//             usize,
//             PublicACC<RistrettoGroup>,
//         )> = (0..num_voters).map(|_| rt.gen_builder(&mut rng)).collect();
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
//         let shuffled = json_list
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
//             &shuffled,
//             &mut transcript,
//         )
//         .unwrap();
//         let duration = start.elapsed();
//         println!("Mix and re-encrypt took: {:?}", duration1);
//         println!("Verification took: {:?}", duration);
//         debug_println!("NOTE: those are debug timings without compiler optimizations.");
//     }
// }
