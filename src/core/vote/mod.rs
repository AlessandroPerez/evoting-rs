pub mod auth;
pub mod choice;

pub mod vote {
    //! Vote (verifiable ballot) module: combines choice + CAI + auth into a single SigmaProtocol proof.

    use dlog_group::group::Group;
    use dlog_sigma_primitives::{
        elgamal::ciphertext::Ciphertext,
        proofs::{Proof as ProofTrait, SigmaProtocol, TranscriptForGroup},
    };
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest, Sha3_256};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::{
        constants::CAI_POW,
        core::keys::ElectionPublicKey,
        core::vote::choice::{
            Choice, ChoiceParameters, EncrChoice, EncrValuesCAI, ExtendedEncrChoice,
            ExtendedEncrValuesCAI, ProofCAI, ProofCAIPublic, ProofCAIState, ProofCAIWitness,
            ProofEncrChoice, ProofEncrChoicePublic, ProofEncrChoiceState, ProofEncrChoiceWitness,
            ValuesCAI,
        },
        error::Error,
    };

    use super::auth::{
        EncrAuthValues, ExtendedEncrAuthValues, ExtendedShortEncrAuthValues, ProofAuthValues,
        ProofAuthValuesPublic, ProofAuthValuesState, ProofAuthValuesWitness, ShortEncrAuthValues,
        VotingCredential,
    };

    use serde_cbor;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub(crate) struct Proof<G: Group> {
        pub(crate) choice_proof: ProofEncrChoice<G>,
        pub(crate) cai_proof: ProofCAI<G>,
        pub(crate) auth_proof: ProofAuthValues<G>,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct ProofPublicBorrowed<'a, G: Group> {
        pub(crate) choice_public: ProofEncrChoicePublic<'a, G>,
        pub(crate) cai_public: ProofCAIPublic<'a, G>,
        pub(crate) auth_public: ProofAuthValuesPublic<'a, G>,
    }

    #[derive(Debug, Zeroize, ZeroizeOnDrop)]
    pub(crate) struct ProofWitness<G: Group> {
        pub(crate) choice_wit: ProofEncrChoiceWitness<G>,
        pub(crate) cai_wit: ProofCAIWitness<G>,
        pub(crate) auth_wit: ProofAuthValuesWitness<G>,
    }

    #[derive(Debug, Zeroize, ZeroizeOnDrop)]
    pub(crate) struct ProofState<G: Group> {
        pub(crate) choice_state: Option<ProofEncrChoiceState<G>>,
        pub(crate) cai_state: Option<ProofCAIState<G>>,
        pub(crate) auth_state: Option<ProofAuthValuesState<G>>,
    }

    pub(crate) struct ProofProtocol<G: Group>(core::marker::PhantomData<G>);

    impl<G: Group> SigmaProtocol for ProofProtocol<G> {
        // domain-sep for the *whole* vote proof
        const DOMAIN: &'static [u8] = b"vote-proof";

        type Public<'a> = ProofPublicBorrowed<'a, G>;
        type Witness = ProofWitness<G>;
        type Proof = Proof<G>;
        type State = ProofState<G>;

        fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript) {
            // Deterministic ordering + sub-domain separation
            transcript.append_message(b"sub", b"choice");
            <ProofEncrChoice<G> as ProofTrait>::Protocol::absorb_public(
                public.choice_public,
                transcript,
            );

            transcript.append_message(b"sub", b"cai");
            <ProofCAI<G> as ProofTrait>::Protocol::absorb_public(public.cai_public, transcript);

            transcript.append_message(b"sub", b"auth");
            <ProofAuthValues<G> as ProofTrait>::Protocol::absorb_public(
                public.auth_public,
                transcript,
            );
        }

        fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
            let choice_state =
                <ProofEncrChoice<G> as ProofTrait>::Protocol::init(public.choice_public, rng);
            let cai_state = <ProofCAI<G> as ProofTrait>::Protocol::init(public.cai_public, rng);
            let auth_state =
                <ProofAuthValues<G> as ProofTrait>::Protocol::init(public.auth_public, rng);

            ProofState {
                choice_state: Some(choice_state),
                cai_state: Some(cai_state),
                auth_state: Some(auth_state),
            }
        }

        fn commit(
            public: Self::Public<'_>,
            state: &mut Self::State,
            witness: &Self::Witness,
            transcript: &mut Transcript,
        ) {
            transcript.append_message(b"sub", b"choice");
            <ProofEncrChoice<G> as ProofTrait>::Protocol::commit(
                public.choice_public,
                state.choice_state.as_mut().unwrap(),
                &witness.choice_wit,
                transcript,
            );

            transcript.append_message(b"sub", b"cai");
            <ProofCAI<G> as ProofTrait>::Protocol::commit(
                public.cai_public,
                state.cai_state.as_mut().unwrap(),
                &witness.cai_wit,
                transcript,
            );

            transcript.append_message(b"sub", b"auth");
            <ProofAuthValues<G> as ProofTrait>::Protocol::commit(
                public.auth_public,
                state.auth_state.as_mut().unwrap(),
                &witness.auth_wit,
                transcript,
            );
        }

        fn complete(
            mut state: Self::State,
            witness: &Self::Witness,
            transcript: &mut Transcript,
        ) -> Self::Proof {
            let choice_state = state.choice_state.take().unwrap();
            let cai_state = state.cai_state.take().unwrap();
            let auth_state = state.auth_state.take().unwrap();

            transcript.append_message(b"sub", b"choice");
            let choice_proof = <ProofEncrChoice<G> as ProofTrait>::Protocol::complete(
                choice_state,
                &witness.choice_wit,
                transcript,
            );

            transcript.append_message(b"sub", b"cai");
            let cai_proof = <ProofCAI<G> as ProofTrait>::Protocol::complete(
                cai_state,
                &witness.cai_wit,
                transcript,
            );

            transcript.append_message(b"sub", b"auth");
            let auth_proof = <ProofAuthValues<G> as ProofTrait>::Protocol::complete(
                auth_state,
                &witness.auth_wit,
                transcript,
            );

            Proof {
                choice_proof,
                cai_proof,
                auth_proof,
            }
        }

        fn update_transcript(
            proof: &Self::Proof,
            transcript: &mut Transcript,
        ) -> Result<(), dlog_sigma_primitives::error::Error> {
            transcript.append_message(b"sub", b"choice");
            <ProofEncrChoice<G> as ProofTrait>::Protocol::update_transcript(
                &proof.choice_proof,
                transcript,
            )?;

            transcript.append_message(b"sub", b"cai");
            <ProofCAI<G> as ProofTrait>::Protocol::update_transcript(&proof.cai_proof, transcript)?;

            transcript.append_message(b"sub", b"auth");
            <ProofAuthValues<G> as ProofTrait>::Protocol::update_transcript(
                &proof.auth_proof,
                transcript,
            )?;

            Ok(())
        }

        fn verify_relation(
            public: Self::Public<'_>,
            proof: &Self::Proof,
            transcript: &mut Transcript,
        ) -> Result<(), dlog_sigma_primitives::error::Error> {
            transcript.append_message(b"sub", b"choice");
            <ProofEncrChoice<G> as ProofTrait>::Protocol::verify_relation(
                public.choice_public,
                &proof.choice_proof,
                transcript,
            )?;

            transcript.append_message(b"sub", b"cai");
            <ProofCAI<G> as ProofTrait>::Protocol::verify_relation(
                public.cai_public,
                &proof.cai_proof,
                transcript,
            )?;

            transcript.append_message(b"sub", b"auth");
            <ProofAuthValues<G> as ProofTrait>::Protocol::verify_relation(
                public.auth_public,
                &proof.auth_proof,
                transcript,
            )?;

            Ok(())
        }

        fn prove<R: RngCore + CryptoRng>(
            public: Self::Public<'_>,
            witness: &Self::Witness,
            transcript: &mut Transcript,
            rng: &mut R,
        ) -> Self::Proof {
            transcript.start_proof(Self::DOMAIN, public.clone(), |tr, p| {
                Self::absorb_public(p, tr)
            });
            let mut state = Self::init(public.clone(), rng);
            Self::commit(public, &mut state, witness, transcript);
            Self::complete(state, witness, transcript)
        }

        fn verify(
            public: Self::Public<'_>,
            proof: &Self::Proof,
            transcript: &mut Transcript,
        ) -> Result<(), dlog_sigma_primitives::error::Error> {
            transcript.start_proof(Self::DOMAIN, public.clone(), |tr, p| {
                Self::absorb_public(p, tr)
            });
            Self::update_transcript(proof, transcript)?;
            Self::verify_relation(public, proof, transcript)
        }
    }

    impl<G: Group> ProofTrait for Proof<G> {
        type Protocol = ProofProtocol<G>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct VerVote<G: Group> {
        /// Encrypted choices.
        pub(crate) choice: EncrChoice<G>,
        /// Cast-as-Intended values.
        pub(crate) cai: EncrValuesCAI<G>,
        /// Values related to the Credential.
        pub(crate) auth: EncrAuthValues<G>,
        /// ZKP
        pub(crate) proof: Proof<G>,
    }

    impl<G: Group> VerVote<G> {
        pub(crate) fn new<R: RngCore + CryptoRng>(
            pk: &ElectionPublicKey<G>,
            choice: &Choice,
            choice_params: &ChoiceParameters,
            credential: &VotingCredential<G>,
            pin: usize,
            rng: &mut R,
        ) -> Self {
            // Encrypt choice
            let ext_choice = ExtendedEncrChoice::new(choice, pk, rng);
            let enc_choice = ext_choice.clone().to_encryption();

            // CAI values + encryption
            let cai = ValuesCAI::new(choice, CAI_POW, rng);
            let ext_cai = ExtendedEncrValuesCAI::new(&cai, pk, rng);
            let enc_cai = ext_cai.clone().to_encrypted();

            // Auth values + encryption
            let ext_auth = ExtendedEncrAuthValues::new(credential, pk, pin, rng);
            let enc_auth = ext_auth.clone().to_encrypted();

            // Build publics
            let choice_public = ProofEncrChoicePublic::new(&enc_choice, pk, choice_params);
            let cai_public = ProofCAIPublic::new(pk, &enc_cai, &enc_choice);
            let auth_public = ProofAuthValuesPublic::new(&enc_auth, pk);

            let public = ProofPublicBorrowed {
                choice_public,
                cai_public,
                auth_public,
            };

            // Build witnesses
            let choice_wit = ProofEncrChoiceWitness::new(
                public.choice_public.clone(),
                ext_choice.clone(),
                choice,
            );
            let cai_wit = ProofCAIWitness::new(&cai, &ext_cai, &ext_choice);
            let auth_wit = ProofAuthValuesWitness::new(&ext_auth, credential, pin);

            let witness = ProofWitness {
                choice_wit,
                cai_wit,
                auth_wit,
            };

            // Prove (uses ProofTrait default `prove`, transcript handled by the framework)
            let proof = Proof::<G>::prove(public, &witness, rng);

            Self {
                choice: enc_choice,
                cai: enc_cai,
                auth: enc_auth,
                proof,
            }
        }

        pub(crate) fn to_vote(&self) -> Vote<G> {
            Vote {
                choice: self.choice.clone(),
                auth: self.auth.to_short(),
            }
        }

        /// Verify the ZKPs and strip.
        pub(crate) fn verify(
            &self,
            pk: &ElectionPublicKey<G>,
            choice_params: &ChoiceParameters,
        ) -> Result<Vote<G>, Error> {
            let choice_public = ProofEncrChoicePublic::new(&self.choice, pk, choice_params);
            let cai_public = ProofCAIPublic::new(pk, &self.cai, &self.choice);
            let auth_public = ProofAuthValuesPublic::new(&self.auth, pk);

            let public = ProofPublicBorrowed {
                choice_public,
                cai_public,
                auth_public,
            };

            self.proof.verify(public)?; // Error::from(dlog_sigma_primitives::error::Error) should kick in
            Ok(self.to_vote())
        }

        pub(crate) fn commit<R: RngCore + CryptoRng>(
            self,
            rng: &mut R,
        ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
            let mut hasher = Sha3_256::new();
            let vote_bytes = serde_cbor::to_vec(&self).unwrap();
            hasher.update(&vote_bytes);

            let mut random_bytes = [0u8; 32];
            rng.fill_bytes(&mut random_bytes);

            hasher.update(random_bytes);
            let digest = hasher.finalize();
            (vote_bytes, digest.into(), random_bytes)
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct Vote<G: Group> {
        pub(crate) choice: EncrChoice<G>,
        pub(crate) auth: ShortEncrAuthValues<G>,
    }

    impl<G: Group> Vote<G> {
        pub(crate) fn re_encrypt<R: CryptoRng + RngCore>(
            &self,
            pk: &ElectionPublicKey<G>,
            rng: &mut R,
        ) -> ExtendedVote<G> {
            let choice = self
                .choice
                .re_encrypt(&pk.params.tally, &pk.params.elgamal, rng);
            let auth = self.auth.re_encrypt(pk, rng);
            ExtendedVote { choice, auth }
        }

        pub(crate) fn to_bytes(&self) -> Vec<u8> {
            serde_cbor::to_vec(&self).unwrap()
        }

        pub(crate) fn strip(self) -> VoteWithEncPubCred<G> {
            VoteWithEncPubCred {
                choice: self.choice,
                A_enc: self.auth.A_enc,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub(crate) struct ExtendedVote<G: Group> {
        pub(crate) choice: ExtendedEncrChoice<G>,
        pub(crate) auth: ExtendedShortEncrAuthValues<G>,
    }

    impl<G: Group> ExtendedVote<G> {
        pub(crate) fn to_vote(self) -> Vote<G> {
            Vote {
                choice: self.choice.to_encryption(),
                auth: self.auth.to_short(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(bound = "")]
    pub struct VoteWithEncPubCred<G: Group> {
        pub(crate) choice: EncrChoice<G>,
        pub(crate) A_enc: Ciphertext<G>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            core::keys::{ElectionParams, RTKeyPair, VoterKeyPair},
            core::vote::auth::{PrivateACC, PublicACC, VotingCredentialBuilder},
        };
        use dlog_group::ristretto::RistrettoGroup;
        use dlog_sigma_primitives::elgamal::keys::SecretKey;
        use rand::thread_rng;

        #[test]
        fn verifiable_vote() {
            // Setup the Voting Credential.
            let mut rng = thread_rng();
            let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
            let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
            let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
            let election_pk: ElectionPublicKey<RistrettoGroup> =
                ElectionPublicKey::new(&rt_pair.pk, params);

            let private: PrivateACC<RistrettoGroup> =
                PrivateACC::new(&rt_pair, &election_pk, &mut rng);
            let public: PublicACC<RistrettoGroup> =
                PublicACC::from_private(&election_pk, &private, &mut rng);
            public.verify(&election_pk).unwrap();

            let (_, voter_pk) = VoterKeyPair::new(&election_pk, &mut rng).into_tuple();
            let builder = VotingCredentialBuilder::new(&private);
            let voting_credential = builder
                .finalize(&rt_pair, &election_pk, &voter_pk, &mut rng)
                .unwrap();

            let pin = private.pin.get_pin_value();
            voting_credential
                .verify_pin(&election_pk, pin, &voter_pk)
                .unwrap();

            // Choice
            let choice_params = ChoiceParameters::new(3, vec![9, 13, 5], false).unwrap();
            let choice = Choice::new(2, vec![4], &choice_params).unwrap();

            let ver_vote = VerVote::new(
                &election_pk,
                &choice,
                &choice_params,
                &voting_credential,
                pin,
                &mut rng,
            );
            ver_vote.verify(&election_pk, &choice_params).unwrap();
        }

        #[test]
        fn re_encryption() {
            let mut rng = thread_rng();
            let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
            let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
            let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
            let election_pk: ElectionPublicKey<RistrettoGroup> =
                ElectionPublicKey::new(&rt_pair.pk, params);

            let private: PrivateACC<RistrettoGroup> =
                PrivateACC::new(&rt_pair, &election_pk, &mut rng);
            let public: PublicACC<RistrettoGroup> =
                PublicACC::from_private(&election_pk, &private, &mut rng);
            public.verify(&election_pk).unwrap();

            let (_, voter_pk) = VoterKeyPair::new(&election_pk, &mut rng).into_tuple();
            let builder = VotingCredentialBuilder::new(&private);
            let voting_credential = builder
                .finalize(&rt_pair, &election_pk, &voter_pk, &mut rng)
                .unwrap();

            let pin = private.pin.get_pin_value();
            voting_credential
                .verify_pin(&election_pk, pin, &voter_pk)
                .unwrap();

            let choice_params = ChoiceParameters::new(3, vec![9, 13, 5], false).unwrap();
            let choice = Choice::new(2, vec![4], &choice_params).unwrap();

            let ver_vote = VerVote::new(
                &election_pk,
                &choice,
                &choice_params,
                &voting_credential,
                pin,
                &mut rng,
            );
            let vote = ver_vote.verify(&election_pk, &choice_params).unwrap();

            let re_encryption = vote.re_encrypt(&election_pk, &mut rng);
            assert_ne!(vote, re_encryption.to_vote());
        }
    }
}
