//! Everything related to the authentication and well formedness of the Ballot; including the Access Control Credential generation
//!

use std::marker::PhantomData;

use dlog_group::serde::ScalarHelper;
use dlog_group::{group::Group, serde::*};
use dlog_sigma_primitives::serde::CiphertextHelper;
use dlog_sigma_primitives::{
    elgamal::{
        ciphertext::{Ciphertext, ExtendedCiphertext},
        keys::SecretScalar,
    },
    proofs::{
        dvzkp::{DesignatedPublic, DvProof, DvPublicBorrowed, DvWitness},
        exp::{ExpProof, ExpProtocol, ExpPublicBorrowed, ExpState, ExpWitness},
        log_equality::{LogEq, LogEqProtocol, LogEqPublicBorrowed, LogEqState, LogEqWitness},
        not_identity::{NotId, NotIdProtocol, NotIdPublicBorrowed, NotIdState},
        zero::{Zero, ZeroProtocol, ZeroPublicBorrowed},
        Proof, SigmaProtocol, TranscriptForGroup,
    },
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    constants::MAX_PIN,
    core::keys::{
        ElectionParams, ElectionPublicKey, RTKeyPair, RTPublicKey, RTSecretKey, VoterKeyPair,
        VoterPublicKey,
    },
    error::Error,
};

// region: ---Pin

/// Unique Voter identifier included in the ACC.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct PIN<G: Group> {
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) x: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) mask: G::Scalar,
}

impl<G: Group> PIN<G> {
    /// Generate a new pin from a cryptographically secure rng.
    pub(crate) fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let x = G::scalar_random(rng);
        let mask = G::scalar_random(rng);
        Self { x, mask }
    }

    pub(crate) fn get_pin_value(&self) -> usize {
        let mut buffer = vec![0; G::SCALAR_SIZE];
        G::scalar_to_bytes(&mut buffer, &self.mask);
        assert!(G::SCALAR_SIZE >= 8);

        // Make an usize from the last 8 bytes of a Scalar
        let slice = &buffer[G::SCALAR_SIZE - 8..G::SCALAR_SIZE];
        let out = usize::from_be_bytes(slice.try_into().expect("Slice must be 8 bytes!"));
        out % MAX_PIN
    }

    pub(crate) fn get_partial_mask(&self) -> G::Scalar {
        let pin = self.get_pin_value();
        self.x - &G::Scalar::from(pin as u64)
    }

    pub(crate) fn to_masked(&self) -> MaskedPIN<G> {
        let masked_x = self.x + &self.mask;
        let partial_mask = self.mask - &G::Scalar::from(self.get_pin_value() as u64);
        MaskedPIN {
            masked_x,
            partial_mask,
        }
    }
}

/// Store all the necessary information to retrieve a [`PIN`] hence both the secret value x included in the ACC and the mask from a numerical pin.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct MaskedPIN<G: Group> {
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) masked_x: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) partial_mask: G::Scalar,
}

impl<G: Group> MaskedPIN<G> {
    /// Retrive a [`PIN`] from a numerical pin.
    pub(crate) fn to_pin(&self, pin: usize) -> PIN<G> {
        let mask = self.partial_mask + &G::Scalar::from(pin as u64);
        let x = self.masked_x - &mask;
        PIN { x, mask }
    }
}

// endregion: ---Pin

// region: ---ACC

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
/// Public ACC (A,r)
pub(crate) struct RTSignature<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub(crate) A: G::Point,
    #[serde(with = "ScalarHelper::<G>")]
    pub(crate) r: G::Scalar,
}

impl<G: Group> RTSignature<G> {
    /// Sign the value x with the Registration Teller secret key, under the ElGamal parameters included in the [`ElectionPublicKey`].
    pub(crate) fn new<R: CryptoRng + RngCore>(
        sk: &RTSecretKey<G>,
        params: &ElectionParams<G>,
        x: &G::Scalar,
        rng: &mut R,
    ) -> RTSignature<G> {
        let r = G::scalar_random(rng);
        let A =
            (params.elgamal.g1 + &(params.g3 * x)) * &G::scalar_inv(r + sk.secret_scalar.expose());

        Self { A, r }
    }
}

#[derive(Debug, Clone)]
/// Encrypted part of the Public ACC (E(A), E(g1g3^x)) where the first is encrypted under the Tally public key and the second under the Registration Teller public key. Additionally stores the randomnesses used for encryption.
pub(crate) struct ExtendedEncryptedRTSignature<G: Group> {
    enc_A: ExtendedCiphertext<G>,
    enc_r: ExtendedCiphertext<G>,
}

/// Encrypt the RTSignature
impl<G: Group> ExtendedEncryptedRTSignature<G> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rt_pk: &RTPublicKey<G>,
        sign: &RTSignature<G>,
        election_pk: &ElectionPublicKey<G>,
        pin: &PIN<G>,
        rng: &mut R,
    ) -> Self {
        let enc_A = election_pk.encrypt(sign.A, rng);
        let enc_r = ExtendedCiphertext::new(
            &rt_pk.meg_pk,
            &election_pk.params.elgamal,
            election_pk.params.elgamal.g1 + &(election_pk.params.g3 * &pin.x),
            rng,
        );
        Self { enc_A, enc_r }
    }
    pub(crate) fn to_encrypted(self) -> EncryptedRTSignature<G> {
        EncryptedRTSignature {
            enc_A: self.enc_A.inner,
            enc_r: self.enc_r.inner,
        }
    }
}

// FIX: the rng related to enc_r may need to be pseudorandom
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct EncryptedRTSignature<G: Group> {
    #[serde(with = "CiphertextHelper::<G>")]
    pub(crate) enc_A: Ciphertext<G>,
    #[serde(with = "CiphertextHelper::<G>")]
    pub(crate) enc_r: Ciphertext<G>,
}

/// Private Access Control Credential (ACC) used to generate a Public one
#[derive(Debug)]
pub(crate) struct PrivateACC<G: Group> {
    /// Private [`PIN`] of a voter
    pub(crate) pin: PIN<G>,
    /// Signature made from a Registration Teller on the private [`PIN`] of a Voter.
    pub(crate) sign: RTSignature<G>,
    /// Encryption of the [`RTSignature`].
    pub(crate) enc_sign: ExtendedEncryptedRTSignature<G>,
}

impl<G: Group> PrivateACC<G> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rt_pair: &RTKeyPair<G>,
        election_pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> Self {
        // FIX?: Here I am using the same rng for multiple things
        let pin = PIN::new(rng);
        let sign = RTSignature::new(&rt_pair.sk, &election_pk.params, &pin.x, rng);
        let enc_sign =
            ExtendedEncryptedRTSignature::new(&rt_pair.pk, &sign, election_pk, &pin, rng);
        Self {
            pin,
            sign,
            enc_sign,
        }
    }
}
// TODO: go back to private
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
/// Public Access Control Credential (ACC) used for authorize a Voter identified by its [`PIN`] to vote.
pub struct PublicACC<G: Group> {
    /// Signature made from a Registration Teller on the private [`PIN`] of a Voter.
    pub(crate) sign: RTSignature<G>,
    /// Encryption of the [`RTSignature`].
    pub(crate) enc_sign: EncryptedRTSignature<G>,
    /// Proof that the `sign` is an encrytion of `sign`.
    pub(crate) proof: Zero<G>,
}

impl<G: Group> PublicACC<G> {
    /// Spoil a [`PrivateACC`] from the private parameters and compute the proof.
    pub(crate) fn from_private<R: RngCore + CryptoRng>(
        election_pk: &ElectionPublicKey<G>,
        private: &PrivateACC<G>,
        rng: &mut R,
    ) -> Self {
        let mut transcript = Transcript::new(b"PB-CR");
        let zero_public = ZeroPublicBorrowed::new(
            &election_pk.params.tally,
            &election_pk.params.elgamal,
            private.enc_sign.enc_A.inner.hom_sub(&private.sign.A),
        );
        let proof = ZeroProtocol::prove(
            zero_public,
            &private.enc_sign.enc_A.random_scalar,
            &mut transcript,
            rng,
        );
        Self {
            sign: private.sign.clone(),
            enc_sign: private.enc_sign.clone().to_encrypted(),
            proof,
        }
    }
    pub(crate) fn new<R: RngCore + CryptoRng>(
        election_pk: &ElectionPublicKey<G>,
        rt_pair: &RTKeyPair<G>,
        rng: &mut R,
    ) -> Self {
        let private = PrivateACC::new(rt_pair, election_pk, rng);
        Self::from_private(election_pk, &private, rng)
    }
    /// Verify the proof included in the [`PublicACC`] exploiting the homomorphic properties of the encryption.
    pub(crate) fn verify(
        &self,
        election_pk: &ElectionPublicKey<G>,
    ) -> Result<ShortPublicACC<G>, dlog_sigma_primitives::error::Error> {
        let mut transcript = Transcript::new(b"PB-CR");
        let zero_public = ZeroPublicBorrowed::new(
            &election_pk.params.tally,
            &election_pk.params.elgamal,
            self.enc_sign.enc_A.hom_sub(&self.sign.A),
        );
        ZeroProtocol::verify(zero_public, &self.proof, &mut transcript)?;
        Ok(ShortPublicACC {
            enc_A: self.enc_sign.enc_A,
        })
    }

    pub(crate) fn to_short(&self) -> ShortPublicACC<G> {
        ShortPublicACC {
            enc_A: self.enc_sign.enc_A,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShortPublicACC<G: Group> {
    pub(crate) enc_A: Ciphertext<G>,
}

impl<G: Group> ShortPublicACC<G> {
    pub(crate) fn re_encrypt<R: RngCore + CryptoRng>(
        &self,
        pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> ExtendedShortPublicACC<G> {
        let enc_A = pk.identity_encription(rng) + self.enc_A;

        ExtendedShortPublicACC { enc_A }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExtendedShortPublicACC<G: Group> {
    pub(crate) enc_A: ExtendedCiphertext<G>,
}

impl<G: Group> ExtendedShortPublicACC<G> {
    pub(crate) fn to_short(self) -> ShortPublicACC<G> {
        ShortPublicACC {
            enc_A: self.enc_A.inner,
        }
    }
}

// endregion: ---ACC

// region: ---Authentication Values

#[derive(Debug, Clone)]
pub(crate) struct ExtendedEncrAuthValues<G: Group> {
    pub(crate) B: G::Point,
    pub(crate) s: G::Scalar,
    pub(crate) A_enc: ExtendedCiphertext<G>,
    pub(crate) Ar_enc: ExtendedCiphertext<G>,
    // x dependant values
    pub(crate) g3x_enc: ExtendedCiphertext<G>,
    pub(crate) ox_enc: ExtendedCiphertext<G>,
}

impl<G: Group> ExtendedEncrAuthValues<G> {
    /// authenticate encrypted vote with ACC
    pub(crate) fn new<R: RngCore + CryptoRng>(
        credential: &VotingCredential<G>,
        pk: &ElectionPublicKey<G>,
        pin: usize,
        rng: &mut R,
    ) -> Self {
        let x = credential.get_x(pin);
        // See if we can do here the encryptions
        let g3x_enc = pk.encrypt(pk.params.g3 * &x, rng);
        let A_enc = pk.encrypt(credential.sign.A, rng);
        let Ar_enc = pk.encrypt(credential.sign.A * &credential.sign.r, rng);

        let s = G::scalar_random(rng);
        let B = credential.sign.A * &s;

        let ox = pk.params.o * &x;
        let ox_enc = pk.encrypt(ox, rng);

        Self {
            B,
            s,
            A_enc,
            Ar_enc,
            g3x_enc,
            ox_enc,
        }
    }

    pub(crate) fn to_encrypted(&self) -> EncrAuthValues<G> {
        EncrAuthValues {
            B: self.B,
            A_enc: self.A_enc.inner,
            Ar_enc: self.Ar_enc.inner,
            g3x_enc: self.g3x_enc.inner,
            ox_enc: self.ox_enc.inner,
        }
    }
}

// TODO: here whe have that B and ox have a different role from the other elements in the struct, and do not seems to need to be re-encrypted, moreover ox is used only for the fingerprints of the ballot
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct EncrAuthValues<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "PointHelper::<G>"))]
    pub(crate) B: G::Point,
    pub(crate) A_enc: Ciphertext<G>,
    pub(crate) Ar_enc: Ciphertext<G>,
    // x dependant values
    pub(crate) g3x_enc: Ciphertext<G>,
    pub(crate) ox_enc: Ciphertext<G>,
}

impl<G: Group> EncrAuthValues<G> {
    // FIX: understand if we can avoid cloning, or if these values are needed in other instancies
    pub(crate) fn to_short(&self) -> ShortEncrAuthValues<G> {
        ShortEncrAuthValues {
            A_enc: self.A_enc,
            Ar_enc: self.Ar_enc,
            g3x_enc: self.g3x_enc,
        }
    }
}

/// Final layer to keep for re-encryption
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct ShortEncrAuthValues<G: Group> {
    pub(crate) A_enc: Ciphertext<G>,
    pub(crate) Ar_enc: Ciphertext<G>,
    // x dependant values
    pub(crate) g3x_enc: Ciphertext<G>,
}

impl<G: Group> ShortEncrAuthValues<G> {
    pub(crate) fn re_encrypt<R: CryptoRng + RngCore>(
        &self,
        pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> ExtendedShortEncrAuthValues<G> {
        let A_enc = pk.identity_encription(rng) + self.A_enc;
        let Ar_enc = pk.identity_encription(rng) + self.Ar_enc;
        let g3x_enc = pk.identity_encription(rng) + self.g3x_enc;

        ExtendedShortEncrAuthValues {
            A_enc,
            Ar_enc,
            g3x_enc,
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct ExtendedShortEncrAuthValues<G: Group> {
    pub(crate) A_enc: ExtendedCiphertext<G>,
    pub(crate) Ar_enc: ExtendedCiphertext<G>,
    // x dependant values
    pub(crate) g3x_enc: ExtendedCiphertext<G>,
}

impl<G: Group> ExtendedShortEncrAuthValues<G> {
    pub(crate) fn to_short(self) -> ShortEncrAuthValues<G> {
        ShortEncrAuthValues {
            A_enc: self.A_enc.inner,
            Ar_enc: self.Ar_enc.inner,
            g3x_enc: self.g3x_enc.inner,
        }
    }
}

/// ZKP related to the authenticated values
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct ProofAuthValues<G: Group> {
    pub(crate) A_pt_nizkp: ExpProof<G>,
    pub(crate) Ar_pt_nizkp: ExpProof<G>,
    pub(crate) A_notid_nizkp: NotId<G>,
    pub(crate) g3x_ox_ptdlogeq_nizkp: LogEq<G>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProofAuthValuesPublic<'a, G: Group> {
    pub(crate) A_pt_public: ExpPublicBorrowed<'a, G>,
    pub(crate) Ar_pt_public: ExpPublicBorrowed<'a, G>,
    pub(crate) A_notid_public: NotIdPublicBorrowed<'a, G>,
    pub(crate) g3x_ox_ptdlogeq_public: LogEqPublicBorrowed<'a, G>,

    pub(crate) auth: &'a EncrAuthValues<G>,
    pub(crate) pk: &'a ElectionPublicKey<G>,
}

impl<'a, G: Group> ProofAuthValuesPublic<'a, G> {
    pub(crate) fn new(auth: &'a EncrAuthValues<G>, pk: &'a ElectionPublicKey<G>) -> Self {
        let A_pt_public =
            ExpPublicBorrowed::new(&pk.params.tally, &pk.params.elgamal, &auth.A_enc, &auth.B);

        let Ar_pt_public =
            ExpPublicBorrowed::new(&pk.params.tally, &pk.params.elgamal, &auth.Ar_enc, &auth.B);

        let A_notid_public =
            NotIdPublicBorrowed::new(&pk.params.tally, &pk.params.elgamal, &auth.A_enc);

        let g3x_ox_ptdlogeq_public = LogEqPublicBorrowed::new(
            &pk.params.tally,
            &pk.params.elgamal,
            &auth.g3x_enc,
            &auth.ox_enc,
            &pk.params.g3,
            &pk.params.o,
        );

        Self {
            A_pt_public,
            Ar_pt_public,
            A_notid_public,
            g3x_ox_ptdlogeq_public,
            auth,
            pk,
        }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofAuthValuesWitness<G: Group> {
    pub(crate) A_pt_wit: ExpWitness<G>,
    pub(crate) Ar_pt_wit: ExpWitness<G>,
    pub(crate) A_notid_wit: SecretScalar<G>,
    pub(crate) g3x_ox_ptdlogeq_wit: LogEqWitness<G>,
}

impl<G: Group> ProofAuthValuesWitness<G> {
    pub(crate) fn new(
        auth: &ExtendedEncrAuthValues<G>,
        credential: &VotingCredential<G>,
        pin: usize,
    ) -> Self {
        let x = credential.get_x(pin);
        let A_pt_wit = ExpWitness::new(
            auth.A_enc.random_scalar.clone(),
            SecretScalar(G::scalar_inv(auth.s)),
        );
        let Ar_pt_wit = ExpWitness::new(
            auth.Ar_enc.random_scalar.clone(),
            SecretScalar(credential.sign.r * &G::scalar_inv(auth.s)),
        );
        let A_notid_wit = auth.A_enc.random_scalar.clone();
        let g3x_ox_ptdlogeq_wit = LogEqWitness::from_r1_r2(
            x,
            auth.g3x_enc.random_scalar.clone(),
            auth.ox_enc.random_scalar.clone(),
        );

        Self {
            A_pt_wit,
            Ar_pt_wit,
            A_notid_wit,
            g3x_ox_ptdlogeq_wit,
        }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofAuthValuesState<G: Group> {
    pub(crate) A_pt_state: Option<ExpState<G>>,
    pub(crate) Ar_pt_state: Option<ExpState<G>>,
    pub(crate) A_notid_state: Option<NotIdState<G>>,
    pub(crate) g3x_ox_ptdlogeq_state: Option<LogEqState<G>>,
}

pub(crate) struct ProofAuthValuesProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for ProofAuthValuesProtocol<G> {
    const DOMAIN: &'static [u8] = b"auth-values";

    type Public<'a>
        = ProofAuthValuesPublic<'a, G>
    where
        Self: 'a;
    type Witness = ProofAuthValuesWitness<G>;
    type Proof = ProofAuthValues<G>;
    type State = ProofAuthValuesState<G>;

    fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript) {
        // FIX
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        let A_pt_state = ExpProtocol::<G>::init(public.A_pt_public.clone(), rng);
        let Ar_pt_state = ExpProtocol::<G>::init(public.Ar_pt_public.clone(), rng);
        let A_notid_state = NotIdProtocol::<G>::init(public.A_notid_public.clone(), rng);
        let g3x_ox_ptdlogeq_state =
            LogEqProtocol::<G>::init(public.g3x_ox_ptdlogeq_public.clone(), rng);

        ProofAuthValuesState {
            A_pt_state: Some(A_pt_state),
            Ar_pt_state: Some(Ar_pt_state),
            A_notid_state: Some(A_notid_state),
            g3x_ox_ptdlogeq_state: Some(g3x_ox_ptdlogeq_state),
        }
    }

    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) {
        ExpProtocol::<G>::commit(
            public.A_pt_public.clone(),
            state.A_pt_state.as_mut().unwrap(),
            &witness.A_pt_wit,
            transcript,
        );

        ExpProtocol::<G>::commit(
            public.Ar_pt_public.clone(),
            state.Ar_pt_state.as_mut().unwrap(),
            &witness.Ar_pt_wit,
            transcript,
        );

        NotIdProtocol::<G>::commit(
            public.A_notid_public.clone(),
            state.A_notid_state.as_mut().unwrap(),
            &witness.A_notid_wit,
            transcript,
        );

        LogEqProtocol::<G>::commit(
            public.g3x_ox_ptdlogeq_public.clone(),
            state.g3x_ox_ptdlogeq_state.as_mut().unwrap(),
            &witness.g3x_ox_ptdlogeq_wit,
            transcript,
        );
    }

    fn complete(
        mut state: Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) -> Self::Proof {
        let A_pt_state = state.A_pt_state.take().unwrap();
        let Ar_pt_state = state.Ar_pt_state.take().unwrap();
        let A_notid_state = state.A_notid_state.take().unwrap();
        let g3x_ox_ptdlogeq_state = state.g3x_ox_ptdlogeq_state.take().unwrap();

        let A_pt_nizkp = ExpProtocol::<G>::complete(A_pt_state, &witness.A_pt_wit, transcript);
        let Ar_pt_nizkp = ExpProtocol::<G>::complete(Ar_pt_state, &witness.Ar_pt_wit, transcript);

        let A_notid_nizkp =
            NotIdProtocol::<G>::complete(A_notid_state, &witness.A_notid_wit, transcript);

        let g3x_ox_ptdlogeq_nizkp = LogEqProtocol::<G>::complete(
            g3x_ox_ptdlogeq_state,
            &witness.g3x_ox_ptdlogeq_wit,
            transcript,
        );

        ProofAuthValues {
            A_pt_nizkp,
            Ar_pt_nizkp,
            A_notid_nizkp,
            g3x_ox_ptdlogeq_nizkp,
        }
    }

    fn update_transcript(
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        ExpProtocol::<G>::update_transcript(&proof.A_pt_nizkp, transcript)?;
        ExpProtocol::<G>::update_transcript(&proof.Ar_pt_nizkp, transcript)?;
        NotIdProtocol::<G>::update_transcript(&proof.A_notid_nizkp, transcript)?;
        LogEqProtocol::<G>::update_transcript(&proof.g3x_ox_ptdlogeq_nizkp, transcript)?;
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        ExpProtocol::<G>::verify_relation(
            public.A_pt_public.clone(),
            &proof.A_pt_nizkp,
            transcript,
        )?;
        ExpProtocol::<G>::verify_relation(
            public.Ar_pt_public.clone(),
            &proof.Ar_pt_nizkp,
            transcript,
        )?;
        NotIdProtocol::<G>::verify_relation(
            public.A_notid_public.clone(),
            &proof.A_notid_nizkp,
            transcript,
        )?;
        LogEqProtocol::<G>::verify_relation(
            public.g3x_ox_ptdlogeq_public.clone(),
            &proof.g3x_ox_ptdlogeq_nizkp,
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

impl<G: Group> Proof for ProofAuthValues<G> {
    type Protocol = ProofAuthValuesProtocol<G>;
}

// /// Credential related values needed for authenticating a vote
// #[derive(Debug, Clone)]
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// #[cfg_attr(feature = "serde", serde(bound = ""))]
// pub(crate) struct AuthValues<G: Group> {
//     pub(crate) value: EncrAuthValues<G>,
//     pub(crate) proof: ProofAuthValues<G>
// }

// impl<G: Group> AuthValues<G> {
//     pub(crate) fn new<R: RngCore+ CryptoRng>(
//         credential: &VotingCredential<G>,
//         pk: &ElectionPublicKey<G>,
//         pin: usize,
//         rng: &mut R,
//         transcript: &mut Transcript
//     ) -> Self {
//         let exd_auth = ExtendedEncrAuthValues::new(credential, pk, pin, rng);
//         // FIX: the randomness here is lost, so need to understand if this make sense
//         let proof = ProofAuthValues::new(&exd_auth, credential, pk, pin, transcript, rng);

//         Self {
//             value: exd_auth.to_encrypted(),
//             proof
//         }
//     }

//     // TODO: probably it makes sense to return the value [`EncrAuthValues`] here
//     pub(crate) fn verify_nizkp(
//         &self,
//         pk: &ElectionPublicKey<G>,
//         transcript: &mut Transcript
//     ) -> Result<(), VerificationError> {
//         self.proof.verify(&self.value, pk, transcript)?;
//         Ok(())
//     }
// }

// endregion: ---Authentication Values

// region: ---VotingCredential

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
/// Voting-Credential Builder, includes the public ACC (A, r), the masked pin (x + \sigma) and the partial mask \sigma - pin. Before voting it is needed to finalize it, by generating the Designated Verifier ZKP.
pub struct VotingCredentialBuilder<G: Group> {
    pub(crate) sign: RTSignature<G>,
    pub(crate) masked_pin: MaskedPIN<G>,
}

impl<G: Group> VotingCredentialBuilder<G> {
    pub fn new(private_acc: &PrivateACC<G>) -> Self {
        Self {
            sign: private_acc.sign.clone(),
            masked_pin: private_acc.pin.to_masked(),
        }
    }
    /// Extract secret value x given a pin
    pub fn get_x(&self, pin: usize) -> G::Scalar {
        self.masked_pin.to_pin(pin).x
    }
    pub fn finalize<R: RngCore + CryptoRng>(
        &self,
        pair: &RTKeyPair<G>,
        pk: &ElectionPublicKey<G>,
        dv_pk: &VoterPublicKey<G>,
        rng: &mut R,
    ) -> Result<VotingCredential<G>, Error> {
        let dvnizkp = self.gen_dvnizkp(pair, pk, dv_pk, rng)?;
        Ok(VotingCredential {
            sign: self.sign.clone(),
            masked_pin: self.masked_pin.clone(),
            dvnizkp,
        })
    }
    pub fn simulate<R: RngCore + CryptoRng>(
        &self,
        pk: &ElectionPublicKey<G>,
        pin: usize,
        dv: &VoterKeyPair<G>,
        rng: &mut R,
    ) -> Result<VotingCredential<G>, Error> {
        let dvnizkp = self.simulate_dvzkp(pk, pin, dv, rng);
        Ok(VotingCredential {
            sign: self.sign.clone(),
            masked_pin: self.masked_pin.clone(),
            dvnizkp,
        })
    }
    pub(crate) fn gen_dvnizkp<R: RngCore + CryptoRng>(
        &self,
        pair: &RTKeyPair<G>,
        pk: &ElectionPublicKey<G>,
        dv_pk: &VoterPublicKey<G>,
        rng: &mut R,
    ) -> Result<DvProof<G>, Error> {
        // Maybe solve as design
        if G::is_id(&dv_pk.pk) {
            return Err(Error::DvKeysNotSet(3));
        }
        let x = pair.sk.secret_scalar.clone();
        let dv = DesignatedPublic {
            base0: pk.params.elgamal.g2,
            pv: dv_pk.pk,
        };
        let p1a = self.sign.A * x.expose();
        let dv_public = DvPublicBorrowed::new(
            &dv,
            &self.sign.A,
            &pk.params.g3,
            &p1a,
            &pair.pk.registration_pk,
        );
        let dv_wit = DvWitness::new(pair.sk.secret_scalar.clone());

        let proof = DvProof::prove(dv_public, &dv_wit, rng);
        Ok(proof)
    }
    pub(crate) fn simulate_dvzkp<R: RngCore + CryptoRng>(
        &self,
        pk: &ElectionPublicKey<G>,
        pin: usize,
        dv: &VoterKeyPair<G>,
        rng: &mut R,
    ) -> DvProof<G> {
        // Moved "-" outside
        let p1a = pk.params.elgamal.g1 + &(pk.params.g3 * &self.get_x(pin))
            - &(self.sign.A * &self.sign.r);
        let dv_wit = DvWitness::new_simulate(SecretScalar(dv.sk.sk));

        let dv = DesignatedPublic {
            base0: pk.params.elgamal.g2,
            pv: dv.pk.pk,
        };
        let dv_public =
            DvPublicBorrowed::new(&dv, &self.sign.A, &pk.params.g3, &p1a, &pk.registration_pk);

        let proof = DvProof::prove(dv_public, &dv_wit, rng);
        proof
    }
}

/// Voting credential
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VotingCredential<G: Group> {
    pub(crate) sign: RTSignature<G>,
    pub(crate) masked_pin: MaskedPIN<G>,
    pub(crate) dvnizkp: DvProof<G>,
}

impl<G: Group> VotingCredential<G> {
    /// Set the value for the mask
    pub fn set_mask(mut self, rhs: G::Scalar) {
        self.masked_pin.partial_mask = rhs
    }
    /// Extract secret value x given a pin
    pub fn get_x(&self, pin: usize) -> G::Scalar {
        self.masked_pin.to_pin(pin).x
    }
    /// Verify consistency of the PIN with [`DvProof`]-ZKP
    pub fn verify_pin(
        &self,
        pk: &ElectionPublicKey<G>,
        pin: usize,
        dv_pk: &VoterPublicKey<G>,
    ) -> Result<(), Error> {
        let p1a = pk.params.elgamal.g1 + &(pk.params.g3 * &self.get_x(pin))
            - &(self.sign.A * &self.sign.r);
        let dv = DesignatedPublic {
            base0: pk.params.elgamal.g2,
            pv: dv_pk.pk,
        };
        let dv_public =
            DvPublicBorrowed::new(&dv, &self.sign.A, &pk.params.g3, &p1a, &pk.registration_pk);

        self.dvnizkp.verify(dv_public)?;
        Ok(())
    }
    // This consumes the previous instance in order to generate a new builder and a new dvnizkp
    pub fn to_builder(self) -> VotingCredentialBuilder<G> {
        VotingCredentialBuilder {
            sign: self.sign,
            masked_pin: self.masked_pin,
        }
    }
    // /// authenticate encrypted vote with ACC
    // pub(crate) fn get_cred_values<R: RngCore + CryptoRng>(
    //     &self,
    //     pk: &ElectionPublicKey<G>,
    //     pin: usize,
    //     rng: &mut R,
    //     transcript: &mut Transcript
    // ) -> AuthValues<G> {
    //     AuthValues::new(&self, pk, pin, rng, transcript)
    // }
}

// endregion: ---VotingCredential

// region: ---Tests

#[cfg(test)]
mod tests {
    use super::*;
    use dlog_sigma_primitives::elgamal::keys::SecretKey;
    use rand::{thread_rng, Rng};

    use dlog_group::ristretto::RistrettoGroup;

    /// [`PIN`] construction.
    #[test]
    pub fn de_pin() {
        // Generate a random rng.
        let mut rng = thread_rng();
        // Generate a new [`PIN`].
        let pin: PIN<RistrettoGroup> = PIN::new(&mut rng);
        // Extract the numerical value of the [`PIN`].
        let pin_value = pin.get_pin_value();
        // Generate a [`MaskedPIN`].
        let mask = pin.to_masked();
        // Serialize a [`MaskedPIN`] to a JSON.
        let json = serde_json::to_value(mask.clone()).unwrap();
        // Deserialize a JSON into a [`MaskedPIN`].
        let de: MaskedPIN<RistrettoGroup> = serde_json::from_value(json).unwrap();
        // Check that the generated [`MaskedPIN`] is equal to its deserialization.
        assert_eq!(mask, de);
        // Check that given the correct pin numerical value it is possible to restore the [`PIN`] from a [`MaskedPIN`].
        assert_eq!(pin, de.to_pin(pin_value));
    }

    /// ACC generation and proof of correct encryption verification.
    #[test]
    pub fn acc_gen() {
        // Setup

        // Generate a random rng.
        let mut rng = thread_rng();
        // Exploit the mock generation of the parameters.
        let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
        // Generate a M-Elgamal SecretKey
        let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
        // Generate a Registration Teller key pair.
        let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
        // Finally generate the Election Public Key from the Public Key of the Registration Teller.
        let election_pk: ElectionPublicKey<RistrettoGroup> =
            ElectionPublicKey::new(&rt_pair.pk, params);
        // Generate a [`PrivateACC`].
        let private: PrivateACC<RistrettoGroup> = PrivateACC::new(&rt_pair, &election_pk, &mut rng);

        //NOTE: the transcript is initialized inside the functions.

        // Generate a PublicACC completed with a proof that the encryption is actually of the signature included in the credential.
        let public: PublicACC<RistrettoGroup> =
            PublicACC::from_private(&election_pk, &private, &mut rng);
        // Verify the proof
        public.verify(&election_pk).unwrap();
    }

    // Generate a [`VotingCredential`] and check consistency of distributed pin and dvnizkp.
    #[test]
    pub fn voting_credential() {
        // Setup the ACC.
        let mut rng = thread_rng();
        let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
        let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
        let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
        let election_pk: ElectionPublicKey<RistrettoGroup> =
            ElectionPublicKey::new(&rt_pair.pk, params);
        let private: PrivateACC<RistrettoGroup> = PrivateACC::new(&rt_pair, &election_pk, &mut rng);
        let public: PublicACC<RistrettoGroup> =
            PublicACC::from_private(&election_pk, &private, &mut rng);
        public.verify(&election_pk).unwrap();

        // Generate a new keypair for the Designated Verifier.
        let (voter_sk, voter_pk) = VoterKeyPair::new(&election_pk, &mut rng).into_tuple();

        // From the Private ACC generate the VotingCredentialBuilder and distribute it to the Voter.
        let builder = VotingCredentialBuilder::new(&private);

        // Retrive the Designated Verifier Public key from the voter and finalize the builder.
        let voting_credential = builder
            .finalize(&rt_pair, &election_pk, &voter_pk, &mut rng)
            .unwrap();

        // Distribuite the pin.
        let pin = private.pin.get_pin_value();

        // Verify consistency of the retrived pin and distributed Designated Verifier ZKP.
        voting_credential
            .verify_pin(&election_pk, pin, &voter_pk)
            .unwrap();
    }

    // Generate a [`VotingCredential`] and check consistency of simulated pin and simulated dvnizkp.
    #[test]
    pub fn voting_credential_simulate() {
        // Setup the ACC.
        let mut rng = thread_rng();
        let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
        let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
        let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
        let election_pk: ElectionPublicKey<RistrettoGroup> =
            ElectionPublicKey::new(&rt_pair.pk, params);
        let private: PrivateACC<RistrettoGroup> = PrivateACC::new(&rt_pair, &election_pk, &mut rng);
        let public: PublicACC<RistrettoGroup> =
            PublicACC::from_private(&election_pk, &private, &mut rng);
        public.verify(&election_pk).unwrap();

        // Generate a new keypair for the Designated Verifier.
        let voter_pair = VoterKeyPair::new(&election_pk, &mut rng);

        // From the Private ACC generate the VotingCredentialBuilder and distribute it to the Voter.
        let builder = VotingCredentialBuilder::new(&private);

        // Generate a random pin.
        let pin: usize = rng.gen();

        // Retrive the Designated Verifier Public key from the voter and finalize the builder.
        let voting_credential = builder
            .simulate(&election_pk, pin, &voter_pair, &mut rng)
            .unwrap();

        // // Distribuite the pin.
        // let pin = private.pin.get_pin_value();

        // Generate a new keypair for the Designated Verifier.
        let (voter_sk, voter_pk) = voter_pair.into_tuple();

        // Verify consistency of the simulated pin and distributed Designated Verifier ZKP.
        voting_credential
            .verify_pin(&election_pk, pin, &voter_pk)
            .unwrap();
    }

    // Check correct failing of the [`VotingCredential`] verification process.
    #[test]
    pub fn voting_credential_fail() {
        // Setup the ACC.
        let mut rng = thread_rng();
        let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
        let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
        let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
        let election_pk: ElectionPublicKey<RistrettoGroup> =
            ElectionPublicKey::new(&rt_pair.pk, params);
        let private: PrivateACC<RistrettoGroup> = PrivateACC::new(&rt_pair, &election_pk, &mut rng);
        let public: PublicACC<RistrettoGroup> =
            PublicACC::from_private(&election_pk, &private, &mut rng);
        public.verify(&election_pk).unwrap();

        // Generate a new keypair for the Designated Verifier.
        let voter_pair = VoterKeyPair::new(&election_pk, &mut rng);

        // From the Private ACC generate the VotingCredentialBuilder and distribute it to the Voter.
        let builder = VotingCredentialBuilder::new(&private);

        // Generate a random pin.
        let pin: usize = rng.gen();

        // Retrive the Designated Verifier Public key from the voter and finalize the builder.
        let voting_credential = builder
            .simulate(&election_pk, pin, &voter_pair, &mut rng)
            .unwrap();

        // Distribuite the pin.
        let pin = private.pin.get_pin_value();

        // Generate a new keypair for the Designated Verifier.
        let (voter_sk, voter_pk) = voter_pair.into_tuple();

        // Verify in-consistency of the simulated pin and distributed Designated Verifier ZKP.
        assert_eq!(
            voting_credential.verify_pin(&election_pk, pin, &voter_pk),
            Err(Error::FailedVerification(
                dlog_sigma_primitives::error::Error::ChallengeMismatch
            )),
            "verification must fail for inconsistent simulated pin"
        );

        // Return the builder from the voting credential. Here we are cloning in order to compare it later, it should **NOT** be cloned.
        let builder1 = voting_credential.clone().to_builder();

        // Check that the original builder is the same as the one retrived from the voting credential.
        assert_eq!(builder, builder1);

        // Rebuild the voting credential using the correct pin.
        let voting_credential1 = builder
            .finalize(&rt_pair, &election_pk, &voter_pk, &mut rng)
            .unwrap();

        // Check that the two voting credentials are different.
        assert_ne!(voting_credential, voting_credential1);

        // Generate a random pin.
        let pin_random: usize = rng.gen();

        // Check that verification fails with a random pin
        assert_eq!(
            voting_credential1.verify_pin(&election_pk, pin_random, &voter_pk),
            Err(Error::FailedVerification(
                dlog_sigma_primitives::error::Error::ChallengeMismatch
            )),
            "verification must fail for inconsistent simulated pin"
        );

        // Verify consistency of the retrived pin and distributed Designated Verifier ZKP.
        voting_credential1
            .verify_pin(&election_pk, pin, &voter_pk)
            .unwrap();
    }

    //
    #[test]
    pub fn authentication_values() {
        // Setup the Voting Credential.
        let mut rng = thread_rng();
        let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
        let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
        let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(meg_sk, &params, &mut rng);
        let election_pk: ElectionPublicKey<RistrettoGroup> =
            ElectionPublicKey::new(&rt_pair.pk, params);
        let private: PrivateACC<RistrettoGroup> = PrivateACC::new(&rt_pair, &election_pk, &mut rng);
        let public: PublicACC<RistrettoGroup> =
            PublicACC::from_private(&election_pk, &private, &mut rng);
        public.verify(&election_pk).unwrap();
        let (voter_sk, voter_pk) = VoterKeyPair::new(&election_pk, &mut rng).into_tuple();
        let builder = VotingCredentialBuilder::new(&private);
        let voting_credential = builder
            .finalize(&rt_pair, &election_pk, &voter_pk, &mut rng)
            .unwrap();
        let pin = private.pin.get_pin_value();
        voting_credential
            .verify_pin(&election_pk, pin, &voter_pk)
            .unwrap();

        // Generate the Authentication values and proof from the voting credential and the valid pin.
        let enc_auth = ExtendedEncrAuthValues::new(&voting_credential, &election_pk, pin, &mut rng);
        let binding = enc_auth.clone().to_encrypted();
        let public = ProofAuthValuesPublic::new(&binding, &election_pk);
        let wit = ProofAuthValuesWitness::new(&enc_auth, &voting_credential, pin);
        let proof = ProofAuthValues::prove(public.clone(), &wit, &mut rng);
        proof.verify(public).unwrap();
    }
}

// endregion: ---Tests
