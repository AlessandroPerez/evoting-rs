//! Choice expression and its encryption
//! TODO: the transcript need to be passed between all the element of a proof, this means that all the element of the same macro proof, i.e. BALLOT casting must use the same transcript! this menas a good amount of staff to change.

use std::marker::PhantomData;

use dlog_group::group::Group;
use dlog_group::serde::ScalarHelper;
use dlog_sigma_primitives::{
    elgamal::{
        ciphertext::{Ciphertext, DiscreteLogTable, ExtendedCiphertext},
        keys::{ElGamalParams, PublicKey, SecretKey, SecretScalar},
    },
    proofs::{
        disjunctive::{Or, OrProtocol, OrPublicBorrowed, OrState, OrWitness},
        zero::{Zero, ZeroProtocol, ZeroPublicBorrowed, ZeroState},
        Proof, SigmaProtocol, TranscriptForGroup,
    },
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO: properly label the proofs
use crate::{
    constants::{CAI_POW, OR_VALUES, OR_VALUES_100},
    core::keys::ElectionPublicKey,
    error::Error,
};

// region: ---Choice

/// Represents the parameters for encoding a choice in a voting system.
///
/// * `n1`: The total number of parties in the election.
/// * `ln2`: A vector specifying the number of candidates for each party, where `ln2[i]` represents the number of candidates available in party `i`.
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChoiceParameters {
    /// Number of parties
    pub(crate) n1: usize,
    /// Number of candidates per party  
    pub(crate) ln2: Vec<usize>,
}

impl ChoiceParameters {
    /// Generation of a valid couple of [`ChoiceParameters`]
    ///
    /// # Arguments
    ///
    /// * `n1` - Number of first level choices, i.e. parties
    /// * `ln2` - Number of second level choices, i.e. preferences
    /// * `adjust` - FIX: add an initial prefernece possibly if there aren't any? idk
    ///
    pub fn new(n1: usize, ln2: Vec<usize>, adjust: bool) -> Result<Self, Error> {
        // Size consistency check, there must be one list of preferences for each party.
        if n1 != ln2.len() {
            return Err(Error::InvalidSize("The length of ln2, the number of second-level choices, should be equal to the number of first-level choices".to_string()));
        }

        // There should be at least one possible preference for each party
        for &n2 in &ln2 {
            if n2 < 1 {
                return Err(Error::InvalidSize(
                    "Invalid number of second-level choices in the sequence (should be all > 0)"
                        .to_string(),
                ));
            }
        }

        // TODO: small descr
        if adjust {
            let mut temp = vec![1];
            temp.extend(ln2);
            return Ok(Self {
                n1: n1 + 1,
                ln2: temp,
            });
        }

        Ok(Self { n1, ln2 })
    }
    /// FIX: idk
    /// Complete setup of class adding the fictious level2 choice which represents a blank choice for the second level
    pub(crate) fn add_no_preference_l2(&mut self) {
        // skip first level 1 choice which already represents a blank choice
        for i in 1..self.n1 {
            self.ln2[i] += 1;
        }
    }
}

/// Represents an encoded vote, where `l1` identifies the selected party and `l2` identifies the preferences for candidates within that party.
///
/// * `l1_value`: The index of the chosen party (e.g., `0` for Party 0, `1` for Party 1, etc.).
/// * `l2_value`: A list of indices representing the candidate preferences.
///
/// Additionally, the struct stores a binary-encoded version of the vote:
/// * `l1`: A one-hot encoded vector where the index set to `1` corresponds to `l1_value`.
/// * `l2`: A binary encoded matrix where each row represents a candidate, and `1`s indicate the preferences from `l2_value`.
///
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Choice {
    /// Selected party index
    pub(crate) l1_value: usize,
    /// Candidate preferences (index-based)
    pub(crate) l2_value: Vec<usize>,
    /// One-hot encoded party selection
    pub(crate) l1: Vec<usize>,
    /// Binary encoded candidate preferences
    pub(crate) l2: Vec<Vec<usize>>,
}

// TODO add limit LL2 but maybe this can be done in a trait outside everything
impl Choice {
    /// Generation of a valid [`Choice`]
    ///
    /// # Arguments
    ///
    /// * `l1` - First level choice, i.e. party
    /// * `l2` - Second level choices, i.e. preferences
    /// * `choice_params` - Parameters assuring the proper length of the encoded choice
    ///
    pub fn new(l1: usize, l2: Vec<usize>, choice_params: &ChoiceParameters) -> Result<Self, Error> {
        let mut l1_vec: Vec<usize> = vec![0; choice_params.n1];
        let mut l2_vec: Vec<Vec<usize>> = vec![];

        // Size consistency checks
        if l1 >= choice_params.n1 {
            return Err(Error::InvalidSize(
                format!(
                    "l1 choice given in input: {}, limit: {}",
                    l1,
                    choice_params.n1 - 1
                )
                .to_string(),
            ));
        }
        for i in 0..l2.len() {
            if l2[i] >= choice_params.ln2[l1] {
                return Err(Error::InvalidSize(
                    format!(
                        "l2 choice given in input: {}, limit: {}",
                        l2[i],
                        choice_params.ln2[l1] - 1
                    )
                    .to_string(),
                ));
            }
        }

        // Converison to binary encoding
        l1_vec[l1] = 1;
        for i in 0..choice_params.n1 {
            l2_vec.push(vec![0; choice_params.ln2[i]]);
        }
        for &j in &l2 {
            l2_vec[l1][j] = 1;
        }

        Ok(Self {
            l1_value: l1,
            l2_value: l2,

            l1: l1_vec,
            l2: l2_vec,
        })
    }
}

// endregion: ---Choice

// region: ---Encryption

/// Represents the choices encrypted with the Tally Pubilc-Key included in [`ElectionPublicKey`], **it also contains the randomness used for encryption**. `l1` and `l2` identify the encryption of the binary encoding of the corresponding field in [`Choice`].
///
/// * `l1`: Encryption of the first level choices, i.e. parties.
/// * `l2`: Encryption of the second level choices, i.e. preferences.
///
#[derive(Debug, Clone)]
pub(crate) struct ExtendedEncrChoice<G: Group> {
    /// Randomness and encryption of first level choice
    pub(crate) l1: Vec<ExtendedCiphertext<G>>,
    /// Randomness and encryption of second level choices
    pub(crate) l2: Vec<Vec<ExtendedCiphertext<G>>>,
}

impl<G: Group> ExtendedEncrChoice<G> {
    /// Encryption of [`Choice`]
    ///
    /// # Arguments
    ///
    /// * `choice` - Payload to be encrypted
    /// * `pk` - Public-Key used for ElGamal encryption
    /// * `rng` - Rng used to generate random values
    ///
    pub(crate) fn new<R: RngCore + CryptoRng>(
        choice: &Choice,
        pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let mut l1: Vec<ExtendedCiphertext<G>> = vec![];
        let mut l2: Vec<Vec<ExtendedCiphertext<G>>> = vec![vec![]; choice.l1.len()];
        // For the party and each preferences selected encrypt the generator of the group, this is equivalent to an exponential encryption of 1; otherwise encrypt the group identity, equivalent to an exponential encryption of 0
        for i in 0..choice.l1.len() {
            if choice.l1[i] == 1 {
                l1.push(pk.encrypt(G::generator(), rng));
            } else {
                l1.push(pk.encrypt(G::identity(), rng));
            }
            for j in 0..choice.l2[i].len() {
                if choice.l2[i][j] == 1 {
                    l2[i].push(pk.encrypt(G::generator(), rng));
                } else {
                    l2[i].push(pk.encrypt(G::identity(), rng));
                }
            }
        }
        ExtendedEncrChoice { l1, l2 }
    }

    /// Consumes the exteded encryption and return the inner ciphertext values without the randomness.
    pub(crate) fn to_encryption(self) -> EncrChoice<G> {
        let mut new_l1 = vec![];
        let mut new_l2 = vec![vec![]; self.l1.len()];
        for i in 0..self.l1.len() {
            new_l1.push(self.l1[i].inner);
            for j in 0..self.l2[i].len() {
                new_l2[i].push(self.l2[i][j].inner);
            }
        }
        EncrChoice {
            l1: new_l1,
            l2: new_l2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EncrChoice<G: Group> {
    /// Randomness and encryption of first level choice
    pub(crate) l1: Vec<Ciphertext<G>>,
    /// Randomness and encryption of second level choices
    pub(crate) l2: Vec<Vec<Ciphertext<G>>>,
}
// TODO: check this
impl<G: Group> std::ops::AddAssign for EncrChoice<G> {
    fn add_assign(&mut self, rhs: EncrChoice<G>) {
        for i in 0..self.l1.len() {
            self.l1[i] += rhs.l1[i];
            for j in 0..self.l2[i].len() {
                self.l2[i][j] += rhs.l2[i][j];
            }
        }
    }
}

impl<G: Group> EncrChoice<G> {
    /// Re-encrypt the choice and return the randomness used.
    ///
    /// # Arguments
    ///
    /// * `self` - Instance of [`EncrChoice`] which is **NOT** modified
    /// * `public_key` - M-ElGamal Public Key
    /// * `rng` - Rng used to generate random values
    ///
    /// # Outputs
    /// An [`ExtendedEncrChoice`] which includes the new randomness used for encryption.
    ///  
    pub(crate) fn re_encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        elg_params: &ElGamalParams<G>,
        rng: &mut R,
    ) -> ExtendedEncrChoice<G> {
        let mut out1: Vec<ExtendedCiphertext<G>> = vec![];
        let mut out2: Vec<Vec<ExtendedCiphertext<G>>> = vec![vec![]; self.l2.len()];
        for i in 0..self.l1.len() {
            out1.push(self.l1[i].re_encrypt(public_key, elg_params, rng));
            for j in 0..self.l2[i].len() {
                out2[i]
                    .push(ExtendedCiphertext::id_new(public_key, elg_params, rng) + self.l2[i][j]);
            }
        }
        ExtendedEncrChoice { l1: out1, l2: out2 }
    }

    pub(crate) fn identity(params: &ChoiceParameters) -> Self {
        let mut l1 = vec![];
        let mut l2 = vec![];
        for i in 0..params.n1 {
            l1.push(Ciphertext::<G>::zero());
            let mut temp = vec![];
            for _j in 0..params.ln2[i] {
                temp.push(Ciphertext::<G>::zero());
            }
            l2.push(temp);
        }
        Self { l1, l2 }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProofEncrChoicePublic<'a, G: Group> {
    pub(crate) one_l1_public: ZeroPublicBorrowed<'a, G>,
    pub(crate) l2_01_public: Vec<Vec<OrPublicBorrowed<'a, G>>>,
    pub(crate) l1_01_public: Vec<OrPublicBorrowed<'a, G>>,
    pub(crate) l1_eq_sum_l2_public: Vec<ZeroPublicBorrowed<'a, G>>,

    pub(crate) choice_params: &'a ChoiceParameters,
    pub(crate) election_pk: &'a ElectionPublicKey<G>,
    pub(crate) enc_choice: &'a EncrChoice<G>,
}

impl<'a, G: Group> ProofEncrChoicePublic<'a, G> {
    pub(crate) fn new(
        enc_choice: &'a EncrChoice<G>,
        election_pk: &'a ElectionPublicKey<G>,
        choice_params: &'a ChoiceParameters,
    ) -> Self {
        let sums_l2_list = enc_choice
            .l2
            .iter()
            .map(|list| list.iter().fold(Ciphertext::zero(), |acc, ct| acc + ct))
            .collect::<Vec<Ciphertext<G>>>();
        let one_l1_ct = enc_choice
            .l1
            .iter()
            .fold(Ciphertext::zero(), |acc, ct| acc + ct)
            .hom_sub(&G::generator());
        let one_l1_public = ZeroPublicBorrowed::new(
            &election_pk.params.tally,
            &election_pk.params.elgamal,
            one_l1_ct,
        );

        let mut l2_01_public: Vec<Vec<OrPublicBorrowed<'_, G>>> = vec![vec![]; choice_params.n1];
        let mut l1_01_public: Vec<OrPublicBorrowed<'_, G>> = vec![];
        let mut l1_eq_sum_l2_public: Vec<ZeroPublicBorrowed<'_, G>> = vec![];
        for i in 0..choice_params.n1 {
            for j in 0..choice_params.ln2[i] {
                l2_01_public[i].push(OrPublicBorrowed::new(
                    &election_pk.params.tally,
                    &election_pk.params.elgamal,
                    enc_choice.l2[i][j],
                    &OR_VALUES,
                ));
            }
            l1_01_public.push(OrPublicBorrowed::new(
                &election_pk.params.tally,
                &election_pk.params.elgamal,
                enc_choice.l1[i],
                &OR_VALUES,
            ));
            l1_eq_sum_l2_public.push(ZeroPublicBorrowed::new(
                &election_pk.params.tally,
                &election_pk.params.elgamal,
                enc_choice.l1[i] - sums_l2_list[i],
            ));
        }

        Self {
            one_l1_public,
            l2_01_public,
            l1_01_public,
            l1_eq_sum_l2_public,
            choice_params,
            election_pk,
            enc_choice,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct ProofEncrChoice<G: Group> {
    pub(crate) one_l1_nizkp: Zero<G>,
    pub(crate) l2_01_nizkp: Vec<Vec<Or<G>>>,
    pub(crate) l1_01_nizkp: Vec<Or<G>>,
    pub(crate) l1_eq_sum_l2_nizkp: Vec<Zero<G>>,
}

// We must wrap around option, in order to take ownership of the inners structure one at a time
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofEncrChoiceState<G: Group> {
    pub(crate) one_l1_state: Option<ZeroState<G>>,
    pub(crate) l2_01_state: Option<Vec<Vec<OrState<G>>>>,
    pub(crate) l1_01_state: Option<Vec<OrState<G>>>,
    pub(crate) l1_eq_sum_l2_state: Option<Vec<ZeroState<G>>>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofEncrChoiceWitness<G: Group> {
    // TODO: zero do not require any witness, think a better way to parse None, could be make witness an Option
    pub(crate) one_l1_wit: SecretScalar<G>,
    pub(crate) l2_01_wit: Vec<Vec<OrWitness<G>>>,
    pub(crate) l1_01_wit: Vec<OrWitness<G>>,
    pub(crate) l1_eq_sum_l2_wit: Vec<SecretScalar<G>>,
}

impl<G: Group> ProofEncrChoiceWitness<G> {
    // FIX: unwrap
    pub(crate) fn new(
        public: ProofEncrChoicePublic<G>,
        ext_choice: ExtendedEncrChoice<G>,
        choice: &Choice,
    ) -> ProofEncrChoiceWitness<G> {
        let one_l1_wit = ext_choice
            .l1
            .iter()
            .fold(SecretScalar::<G>::from(0u64), |acc, ct| acc + ct.expose());
        let mut l2_01_wit: Vec<Vec<OrWitness<G>>> = vec![vec![]; public.choice_params.n1];
        let mut l1_01_wit = vec![];
        let mut l1_eq_sum_l2_wit = vec![];
        let sums_l2r_list = ext_choice
            .l2
            .iter()
            .map(|list| {
                list.iter()
                    .fold(SecretScalar::<G>::from(0u64), |acc, ct| acc + ct.expose())
            })
            .collect::<Vec<SecretScalar<G>>>();
        for i in 0..public.choice_params.n1 {
            for j in 0..public.choice_params.ln2[i] {
                l2_01_wit[i].push(
                    OrWitness::<G>::new(
                        choice.l2[i][j],
                        ext_choice.l2[i][j].random_scalar.clone(),
                        2,
                    )
                    .unwrap(),
                );
            }
            l1_01_wit.push(
                OrWitness::<G>::new(choice.l1[i], ext_choice.l1[i].random_scalar.clone(), 2)
                    .unwrap(),
            );
            l1_eq_sum_l2_wit
                .push(ext_choice.l1[i].random_scalar.clone() - sums_l2r_list[i].expose());
        }

        Self {
            one_l1_wit,
            l2_01_wit,
            l1_01_wit,
            l1_eq_sum_l2_wit,
        }
    }
}

pub(crate) struct ProofEncrChoiceProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for ProofEncrChoiceProtocol<G> {
    const DOMAIN: &'static [u8] = b"PROOF";

    type Public<'a> = ProofEncrChoicePublic<'a, G>;
    type Witness = ProofEncrChoiceWitness<G>;
    type Proof = ProofEncrChoice<G>;
    type State = ProofEncrChoiceState<G>;

    fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript) {
        // Include the Election PK
        public.election_pk.into_transcript(transcript);
        transcript.append_bytes(b"CHOICE", &serde_cbor::to_vec(public.enc_choice).unwrap());
        transcript.append_bytes(b"PARAM", &serde_cbor::to_vec(public.choice_params).unwrap());
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        let one_l1_state = ZeroProtocol::<G>::init(public.one_l1_public, rng);
        let mut l2_01_state: Vec<Vec<_>> =
            (0..public.choice_params.n1).map(|_| Vec::new()).collect();
        let mut l1_01_state = vec![];
        let mut l1_eq_sum_l2_state = vec![];
        for i in 0..public.choice_params.n1 {
            for j in 0..public.choice_params.ln2[i] {
                l2_01_state[i].push(OrProtocol::<G>::init(public.l2_01_public[i][j], rng));
            }
            l1_01_state.push(OrProtocol::<G>::init(public.l1_01_public[i], rng));
            l1_eq_sum_l2_state.push(ZeroProtocol::<G>::init(public.l1_eq_sum_l2_public[i], rng));
        }

        Self::State {
            one_l1_state: Some(one_l1_state),
            l2_01_state: Some(l2_01_state),
            l1_01_state: Some(l1_01_state),
            l1_eq_sum_l2_state: Some(l1_eq_sum_l2_state),
        }
    }

    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) {
        // At this point the states must be well formed, so we can unwrap() with a clear coscience
        ZeroProtocol::<G>::commit(
            public.one_l1_public,
            state.one_l1_state.as_mut().unwrap(),
            &witness.one_l1_wit,
            transcript,
        );
        for i in 0..public.choice_params.n1 {
            for j in 0..public.choice_params.ln2[i] {
                OrProtocol::<G>::commit(
                    public.l2_01_public[i][j],
                    &mut state.l2_01_state.as_mut().unwrap()[i][j],
                    &witness.l2_01_wit[i][j],
                    transcript,
                );
            }
            OrProtocol::<G>::commit(
                public.l1_01_public[i],
                &mut state.l1_01_state.as_mut().unwrap()[i],
                &witness.l1_01_wit[i],
                transcript,
            );
            ZeroProtocol::<G>::commit(
                public.l1_eq_sum_l2_public[i],
                &mut state.l1_eq_sum_l2_state.as_mut().unwrap()[i],
                &witness.l1_eq_sum_l2_wit[i],
                transcript,
            );
        }
    }

    fn complete(
        mut state: Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) -> Self::Proof {
        // Moves in completely the state
        let l2_01_state = state.l2_01_state.take().unwrap();
        let l1_01_state = state.l1_01_state.take().unwrap();
        let l1_eq_sum_l2_state = state.l1_eq_sum_l2_state.take().unwrap();
        let one_l1_state = state.one_l1_state.take().unwrap();

        let one_l1_nizkp =
            ZeroProtocol::<G>::complete(one_l1_state, &witness.one_l1_wit, transcript);
        let mut l2_01_nizkp = Vec::with_capacity(l2_01_state.len());
        let mut l1_01_nizkp = Vec::with_capacity(l1_01_state.len());
        let mut l1_eq_sum_l2_nizkp = Vec::with_capacity(l1_eq_sum_l2_state.len());

        for (i, (row, l1_state, sum_state)) in l2_01_state
            .into_iter()
            .zip(l1_01_state.into_iter())
            .zip(l1_eq_sum_l2_state.into_iter())
            .enumerate()
            .map(|(i, ((row, l1), sum))| (i, (row, l1, sum)))
        {
            let mut row_out = Vec::with_capacity(row.len());

            for (j, or_state) in row.into_iter().enumerate() {
                row_out.push(OrProtocol::complete(
                    or_state,
                    &witness.l2_01_wit[i][j],
                    transcript,
                ));
            }

            l2_01_nizkp.push(row_out);

            l1_01_nizkp.push(OrProtocol::<G>::complete(
                l1_state,
                &witness.l1_01_wit[i],
                transcript,
            ));

            l1_eq_sum_l2_nizkp.push(ZeroProtocol::<G>::complete(
                sum_state,
                &witness.l1_eq_sum_l2_wit[i],
                transcript,
            ));
        }

        Self::Proof {
            one_l1_nizkp,
            l2_01_nizkp,
            l1_01_nizkp,
            l1_eq_sum_l2_nizkp,
        }
    }

    fn update_transcript(
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        ZeroProtocol::<G>::update_transcript(&proof.one_l1_nizkp, transcript)?;
        for i in 0..proof.l2_01_nizkp.len() {
            for j in 0..proof.l2_01_nizkp[i].len() {
                OrProtocol::<G>::update_transcript(&proof.l2_01_nizkp[i][j], transcript)?
            }
            OrProtocol::<G>::update_transcript(&proof.l1_01_nizkp[i], transcript)?;
            ZeroProtocol::<G>::update_transcript(&proof.l1_eq_sum_l2_nizkp[i], transcript)?;
        }
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        ZeroProtocol::<G>::verify_relation(public.one_l1_public, &proof.one_l1_nizkp, transcript)?;
        for i in 0..public.choice_params.n1 {
            for j in 0..public.choice_params.ln2[i] {
                OrProtocol::<G>::verify_relation(
                    public.l2_01_public[i][j],
                    &proof.l2_01_nizkp[i][j],
                    transcript,
                )?
            }
            OrProtocol::<G>::verify_relation(
                public.l1_01_public[i],
                &proof.l1_01_nizkp[i],
                transcript,
            )?;
            ZeroProtocol::<G>::verify_relation(
                public.l1_eq_sum_l2_public[i],
                &proof.l1_eq_sum_l2_nizkp[i],
                transcript,
            )?;
        }
        Ok(())
    }
}

impl<G: dlog_group::group::Group> Proof for ProofEncrChoice<G> {
    type Protocol = ProofEncrChoiceProtocol<G>;
}

#[derive(Debug, Clone)]
pub(crate) struct ValuesCAI {
    l1_code: u32,
    l1_sum: u32,
    l2_code: u32,
    l2_sum: u32,
}

impl ValuesCAI {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        choice: &Choice,
        n_digits: u32,
        rng: &mut R,
    ) -> ValuesCAI {
        let l1_code = rng.next_u32() % n_digits;
        let l2_code = rng.next_u32() % n_digits;

        // FIX: assuming 1 preference
        let l1_sum = l1_code + (choice.l1_value as u32);
        let l2c = match choice.l2.is_empty() {
            true => 0,
            false => choice.l2_value[0] as u32,
        };
        let l2_sum = l2_code + l2c;

        ValuesCAI {
            l1_code,
            l1_sum,
            l2_code,
            l2_sum,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExtendedEncrValuesCAI<G: Group> {
    l1_code_enc: ExtendedCiphertext<G>,
    l1_sum_enc: ExtendedCiphertext<G>,
    l2_code_enc: ExtendedCiphertext<G>,
    l2_sum_enc: ExtendedCiphertext<G>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub(crate) enum ChoiceRevealedCAI<G: Group> {
    Code {
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_v: G::Scalar,
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_r: G::Scalar,
    },
    Sum {
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_v: G::Scalar,
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_r: G::Scalar,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub(crate) struct RevealedCAI<G: Group> {
    l1: ChoiceRevealedCAI<G>,
    l2: ChoiceRevealedCAI<G>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub(crate) enum ChoiceDiscloseCAI<G: Group> {
    Code {
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_r: G::Scalar,
    },
    Sum {
        #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
        l_r: G::Scalar,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub(crate) struct DiscloseCAI<G: Group> {
    l1: ChoiceDiscloseCAI<G>,
    l2: ChoiceDiscloseCAI<G>,
}

impl<G: Group> DiscloseCAI<G> {
    pub(crate) fn from_reveal(reveal: RevealedCAI<G>) -> Self {
        let l1 = match reveal.l1 {
            ChoiceRevealedCAI::Code { l_r, .. } => ChoiceDiscloseCAI::Code { l_r },
            ChoiceRevealedCAI::Sum { l_r, .. } => ChoiceDiscloseCAI::Sum { l_r },
        };

        let l2 = match reveal.l2 {
            ChoiceRevealedCAI::Code { l_r, .. } => ChoiceDiscloseCAI::Code { l_r },
            ChoiceRevealedCAI::Sum { l_r, .. } => ChoiceDiscloseCAI::Sum { l_r },
        };

        DiscloseCAI { l1, l2 }
    }
}

impl<G: Group> ExtendedEncrValuesCAI<G> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        cai: &ValuesCAI,
        pk: &ElectionPublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let l1_code_enc: ExtendedCiphertext<G> =
            pk.exp_encrypt(&G::Scalar::from(cai.l1_code as u64), rng);
        let l1_sum_enc: ExtendedCiphertext<G> =
            pk.exp_encrypt(&G::Scalar::from((cai.l1_sum % CAI_POW) as u64), rng);
        let l2_code_enc: ExtendedCiphertext<G> =
            pk.exp_encrypt(&G::Scalar::from(cai.l2_code as u64), rng);
        let l2_sum_enc: ExtendedCiphertext<G> =
            pk.exp_encrypt(&G::Scalar::from((cai.l2_sum % CAI_POW) as u64), rng);

        Self {
            l1_code_enc,
            l1_sum_enc,
            l2_code_enc,
            l2_sum_enc,
        }
    }
    pub(crate) fn to_encrypted(self) -> EncrValuesCAI<G> {
        EncrValuesCAI {
            l1_code_enc: self.l1_code_enc.inner,
            l1_sum_enc: self.l1_sum_enc.inner,
            l2_code_enc: self.l2_code_enc.inner,
            l2_sum_enc: self.l2_sum_enc.inner,
        }
    }
    pub(crate) fn reveal(&self, values: ValuesCAI, l1_c: bool, l2_c: bool) -> RevealedCAI<G> {
        let (l1_v, l1_r) = if l1_c {
            (values.l1_code, *self.l1_code_enc.expose())
        } else {
            (values.l1_sum % CAI_POW, *self.l1_sum_enc.expose())
        };

        let (l2_v, l2_r) = if l2_c {
            (values.l2_code, *self.l2_code_enc.expose())
        } else {
            (values.l2_sum % CAI_POW, *self.l2_sum_enc.expose())
        };

        let (l1, l2) = match (l1_c, l2_c) {
            (true, true) => (
                ChoiceRevealedCAI::Code {
                    l_v: G::Scalar::from(l1_v.into()),
                    l_r: l1_r,
                },
                ChoiceRevealedCAI::Code {
                    l_v: G::Scalar::from(l2_v.into()),
                    l_r: l2_r,
                },
            ),
            (true, false) => (
                ChoiceRevealedCAI::Code {
                    l_v: G::Scalar::from(l1_v.into()),
                    l_r: l1_r,
                },
                ChoiceRevealedCAI::Sum {
                    l_v: G::Scalar::from(l2_v.into()),
                    l_r: l2_r,
                },
            ),
            (false, true) => (
                ChoiceRevealedCAI::Sum {
                    l_v: G::Scalar::from(l1_v.into()),
                    l_r: l1_r,
                },
                ChoiceRevealedCAI::Code {
                    l_v: G::Scalar::from(l2_v.into()),
                    l_r: l2_r,
                },
            ),
            (false, false) => (
                ChoiceRevealedCAI::Sum {
                    l_v: G::Scalar::from(l1_v.into()),
                    l_r: l1_r,
                },
                ChoiceRevealedCAI::Sum {
                    l_v: G::Scalar::from(l2_v.into()),
                    l_r: l2_r,
                },
            ),
        };

        RevealedCAI { l1, l2 }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub(crate) struct EncrValuesCAI<G: Group> {
    l1_code_enc: Ciphertext<G>,
    l1_sum_enc: Ciphertext<G>,
    l2_code_enc: Ciphertext<G>,
    l2_sum_enc: Ciphertext<G>,
}
// TODO: Proper result handling
impl<G: Group> EncrValuesCAI<G> {
    /// Extract the CAI control values from the encrypted values given CAI disclosure data and the public key
    pub(crate) fn extract_CAI_values(
        &self,
        discl: DiscloseCAI<G>,
        pk: &ElectionPublicKey<G>,
        table: &DiscreteLogTable<G>,
    ) -> Result<RevealedCAI<G>, Error> {
        let l1 = match discl.l1 {
            ChoiceDiscloseCAI::Code { l_r } => ChoiceRevealedCAI::Code {
                l_v: pk.params.tally.exp_dec_with_rnd(
                    &pk.params.elgamal,
                    table,
                    &self.l1_code_enc,
                    &l_r,
                )?,
                l_r,
            },
            ChoiceDiscloseCAI::Sum { l_r } => ChoiceRevealedCAI::Sum {
                l_v: pk.params.tally.exp_dec_with_rnd(
                    &pk.params.elgamal,
                    table,
                    &self.l1_sum_enc,
                    &l_r,
                )?,
                l_r,
            },
        };
        let l2 = match discl.l2 {
            ChoiceDiscloseCAI::Code { l_r } => ChoiceRevealedCAI::Code {
                l_v: pk.params.tally.exp_dec_with_rnd(
                    &pk.params.elgamal,
                    table,
                    &self.l2_code_enc,
                    &l_r,
                )?,
                l_r,
            },
            ChoiceDiscloseCAI::Sum { l_r } => ChoiceRevealedCAI::Sum {
                l_v: pk.params.tally.exp_dec_with_rnd(
                    &pk.params.elgamal,
                    table,
                    &self.l2_sum_enc,
                    &l_r,
                )?,
                l_r,
            },
        };

        Ok(RevealedCAI { l1, l2 })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProofCAIPublic<'a, G: Group> {
    pub(crate) l1_codesum_public: OrPublicBorrowed<'a, G>,
    pub(crate) l2_codesum_public: OrPublicBorrowed<'a, G>,
}

impl<'a, G: Group> ProofCAIPublic<'a, G> {
    pub(crate) fn new(
        pk: &'a ElectionPublicKey<G>,
        enc_cai: &'a EncrValuesCAI<G>,
        choice_enc: &'a EncrChoice<G>,
    ) -> Self {
        let ct1 = enc_cai.l1_code_enc
            + (Ciphertext::ranked_sum(&choice_enc.l1[1..]) - enc_cai.l1_sum_enc);
        let mut sum = enc_cai.l2_code_enc;
        for l2cts in &choice_enc.l2 {
            sum += Ciphertext::ranked_sum(&l2cts[1..]);
        }
        let ct2 = sum - enc_cai.l2_sum_enc;

        let l1_codesum_public =
            OrPublicBorrowed::new(&pk.params.tally, &pk.params.elgamal, ct1, &OR_VALUES_100);

        let l2_codesum_public =
            OrPublicBorrowed::new(&pk.params.tally, &pk.params.elgamal, ct2, &OR_VALUES_100);

        Self {
            l1_codesum_public,
            l2_codesum_public,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct ProofCAI<G: Group> {
    l1_codesum_nizkp: Or<G>,
    l2_codesum_nizkp: Or<G>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofCAIState<G: Group> {
    pub(crate) l1_codesum_state: Option<OrState<G>>,
    pub(crate) l2_codesum_state: Option<OrState<G>>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ProofCAIWitness<G: Group> {
    pub(crate) l1_codesum_wit: OrWitness<G>,
    pub(crate) l2_codesum_wit: OrWitness<G>,
}

impl<G: Group> ProofCAIWitness<G> {
    pub(crate) fn new(
        cai: &ValuesCAI,
        ext_cai: &ExtendedEncrValuesCAI<G>,
        choice_enc: &ExtendedEncrChoice<G>,
    ) -> Self {
        let l1_codesum_wit = OrWitness::new(
            (cai.l1_sum / CAI_POW) as usize,
            // TODO: here there is no point at all to do a sumover the ciphertext
            (ext_cai.l1_code_enc.clone()
                + (ExtendedCiphertext::ranked_sum(&choice_enc.l1[1..])
                    - ext_cai.l1_sum_enc.clone()))
            .random_scalar,
            2,
        )
        .unwrap();
        let mut sum = ext_cai.l2_code_enc.clone();
        for l2cts in &choice_enc.l2 {
            sum += ExtendedCiphertext::ranked_sum(&l2cts[1..]);
        }
        let l2_codesum_wit = OrWitness::new(
            (cai.l2_sum / CAI_POW) as usize,
            (sum - ext_cai.l2_sum_enc.clone()).random_scalar,
            2,
        )
        .unwrap();
        Self {
            l1_codesum_wit,
            l2_codesum_wit,
        }
    }
}

pub(crate) struct ProofCAIProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for ProofCAIProtocol<G> {
    const DOMAIN: &'static [u8] = b"cai";

    type Public<'a> = ProofCAIPublic<'a, G>;
    type Witness = ProofCAIWitness<G>;
    type Proof = ProofCAI<G>;
    type State = ProofCAIState<G>;

    fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript) {
        // FIX: Here we are doing nothing atm, it makes more sense this way and add only in the last external proof all the public parameters, here we still need to add something but not the public key
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        let l1_codesum_state = OrProtocol::<G>::init(public.l1_codesum_public, rng);
        let l2_codesum_state = OrProtocol::<G>::init(public.l2_codesum_public, rng);
        Self::State {
            l1_codesum_state: Some(l1_codesum_state),
            l2_codesum_state: Some(l2_codesum_state),
        }
    }

    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) {
        OrProtocol::<G>::commit(
            public.l1_codesum_public,
            state.l1_codesum_state.as_mut().unwrap(),
            &witness.l1_codesum_wit,
            transcript,
        );

        OrProtocol::<G>::commit(
            public.l2_codesum_public,
            state.l2_codesum_state.as_mut().unwrap(),
            &witness.l2_codesum_wit,
            transcript,
        );
    }

    fn complete(
        mut state: Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) -> Self::Proof {
        let l1_codesum_state = state.l1_codesum_state.take().unwrap();
        let l2_codesum_state = state.l2_codesum_state.take().unwrap();

        let l1_codesum_nizkp =
            OrProtocol::<G>::complete(l1_codesum_state, &witness.l1_codesum_wit, transcript);

        let l2_codesum_nizkp =
            OrProtocol::<G>::complete(l2_codesum_state, &witness.l2_codesum_wit, transcript);

        Self::Proof {
            l1_codesum_nizkp,
            l2_codesum_nizkp,
        }
    }

    fn update_transcript(
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        OrProtocol::<G>::update_transcript(&proof.l1_codesum_nizkp, transcript)?;
        OrProtocol::<G>::update_transcript(&proof.l2_codesum_nizkp, transcript)?;
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), dlog_sigma_primitives::error::Error> {
        OrProtocol::<G>::verify_relation(
            public.l1_codesum_public,
            &proof.l1_codesum_nizkp,
            transcript,
        )?;
        OrProtocol::<G>::verify_relation(
            public.l2_codesum_public,
            &proof.l2_codesum_nizkp,
            transcript,
        )?;
        Ok(())
    }
}

impl<G: dlog_group::group::Group> Proof for ProofCAI<G> {
    type Protocol = ProofCAIProtocol<G>;
}

// endregion: ---Cast-as-Intended

// region: --- Tests

#[cfg(test)]
mod tests {
    use std::{sync::LazyLock, time::Instant};

    use dlog_group::{group::GroupScalar, ristretto::RistrettoGroup};
    use dlog_sigma_primitives::elgamal::{ciphertext::DiscreteLogTable, keys::SecretKey};
    use rand::{thread_rng, Rng};

    use crate::core::keys::{ElectionParams, RTKeyPair};

    use super::*;

    static DLOG_TABLE: LazyLock<DiscreteLogTable<RistrettoGroup>> =
        LazyLock::new(|| DiscreteLogTable::new(0..100));

    // We can use OnceLock if there is a need to recompute the table (conditionally) for bigger exponents, or need additional logic
    // static DLOG_TABLE: OnceLock<DiscreteLogTable<RistrettoGroup>> = OnceLock::new();

    // fn get_dlog_table() -> &'static DiscreteLogTable<RistrettoGroup> {
    //     DLOG_TABLE.get_or_init(|| DiscreteLogTable::new(0..100))
    // }

    #[test]
    fn choice_expression() {
        let n1 = 10;
        let ln2 = vec![10; n1];
        // Generate new parameters for an election.
        let choice_parameters = ChoiceParameters::new(n1, ln2.clone(), false).unwrap();
        // Make a new valid choice.
        let mut rng = thread_rng();
        let choice = Choice::new(
            rng.gen_range(0..n1),
            vec![rng.gen_range(0..10)],
            &choice_parameters,
        )
        .unwrap();
        // Visual check that the encoding is in binary and well formed.
        print!("CHOSEN PARTY: ");
        for i in choice.l1.clone() {
            print!("{}", i);
        }
        print!("\nCHOSEN CANDIDATE:");
        for i in 0..choice.l2.clone().len() {
            print!(" ");
            for j in choice.l2[i].clone() {
                print!("{}", j);
            }
        }
        println! {"\n"}
    }

    #[test]
    fn choice_fail() {
        // Generate new parameters for an election.
        let choice_params = ChoiceParameters::new(
            3,              // 3 parties in the election;
            vec![9, 13, 5], // first party has 9 candidate, the second one 13 and the last one 5;
            false,          // FIX:
        )
        .unwrap(); // needs to be well formed namely len(ln2) == n1 and number of candidates must be positive.
                   // Not-existing party
        assert_eq!(
            Choice::new(4, vec![5], &choice_params),
            Err(Error::InvalidSize(
                "l1 choice given in input: 4, limit: 2".to_string()
            ))
        );
        // Existing party but not-existing candidate.
        assert_eq!(
            Choice::new(2, vec![5], &choice_params),
            Err(Error::InvalidSize(
                "l2 choice given in input: 5, limit: 4".to_string()
            ))
        );
    }

    #[test]
    fn choice_verifiable() {
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

        // Generate a new Choice.
        let choice_params = ChoiceParameters::new(3, vec![9, 13, 5], false).unwrap();
        let choice = Choice::new(2, vec![4], &choice_params).unwrap();

        // Encrypt the Choice adding the ZKPs needed in order to confirm the well formedness of the encryption (Confirms that the unencrypted choice was formed following the rules of the vote).
        let enc_choice = ExtendedEncrChoice::new(&choice, &election_pk, &mut rng);
        let binding = enc_choice.clone().to_encryption();
        let public = ProofEncrChoicePublic::new(&binding, &election_pk, &choice_params);

        let witness = ProofEncrChoiceWitness::new(public.clone(), enc_choice, &choice);
        let start = Instant::now();
        let proof = ProofEncrChoice::prove(public.clone(), &witness, &mut rng);
        let duration = start.elapsed();
        println!("ProofEncChoice prove: {:?}", duration);

        proof.verify(public).unwrap();
    }

    //     #[test]
    //     fn choice_verifiable_fail() {
    //         // Generate a random rng.
    //         let mut rng = thread_rng();
    //         // Exploit the mock generation of the parameters.
    //         let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
    //         // Generate a M-Elgamal SecretKey
    //         let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
    //         // Generate a Registration Teller key pair.
    //         let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(&meg_sk, &params, &mut rng);
    //         // Finally generate the Election Public Key from the Public Key of the Registration Teller.
    //         let election_pk: ElectionPublicKey<RistrettoGroup> = ElectionPublicKey::new(&rt_pair.pk, params);

    //         // Generate a new Choice.
    //         let choice_params = ChoiceParameters::new(
    //             3,
    //             vec![9, 13, 5],
    //             false
    //         ).unwrap();
    //         let choice = Choice::new(
    //             2,
    //             vec![4],
    //             &choice_params
    //         ).unwrap();

    //         // Encrypt the Choice adding the ZKPs necessaries in order to confirm the well formedness of the encryption (Confirms that the unencrypted choice was formed following the rules of the vote).
    //         let mut transcript = Transcript::new(b"test");
    //         let enc_choice = ExtendedEncrChoice::new(&choice, &election_pk, &mut rng);
    //         let builder = ProofEncrChoiceBuilder::new(
    //             &enc_choice,
    //             &election_pk,
    //             &choice,
    //             &mut transcript,
    //             &mut rng
    //         );
    //         // Complete the ZKP generating challenge and responses
    //         let proof = builder.complete(&mut transcript);

    //         // Verify the wellformedness of Choice.
    //         let mut transcript1 = Transcript::new(b"test");
    //         proof.update_transcript(&mut transcript1);
    //         proof.compose_verify(&enc_choice.clone().to_encryption(), &election_pk, &choice_params, &mut transcript1).unwrap();

    //         // Generate a different set of parameters in order to trigger a fail.
    //         // Exploit the mock generation of the parameters.
    //         let params: ElectionParams<RistrettoGroup> = ElectionParams::new_mock(&mut rng);
    //         // Generate a M-Elgamal SecretKey
    //         let meg_sk: SecretKey<RistrettoGroup> = SecretKey::new(&mut rng);
    //         // Generate a Registration Teller key pair.
    //         let rt_pair: RTKeyPair<RistrettoGroup> = RTKeyPair::new(&meg_sk, &params, &mut rng);
    //         // Finally generate the Election Public Key from the Public Key of the Registration Teller.
    //         let election_pk: ElectionPublicKey<RistrettoGroup> = ElectionPublicKey::new(&rt_pair.pk, params);

    //         // Under the new parameters the check must fail.
    //         let mut transcript1 = Transcript::new(b"test");
    //         proof.update_transcript(&mut transcript1);
    //         assert_eq!(
    //             proof.compose_verify(&enc_choice.to_encryption(), &election_pk, &choice_params, &mut transcript1),
    //             Err(VerificationError::CommitmentMismatch)
    //         );
    //     }

    #[test]
    fn cai() {
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

        let n1 = 10;
        let ln2 = vec![10; n1];
        // Generate new parameters for an election.
        let choice_parameters = ChoiceParameters::new(n1, ln2.clone(), false).unwrap();
        // Make a new valid choice.

        let mut rng = thread_rng();
        let choice = Choice::new(
            rng.gen_range(0..n1),
            vec![rng.gen_range(0..10)],
            &choice_parameters,
        )
        .unwrap();

        // Encrypt the Choice.
        let enc_choice = ExtendedEncrChoice::new(&choice, &election_pk, &mut rng);

        // From the encrypted choice generate the CAI values and related proofs.
        let cai = ValuesCAI::new(&choice, CAI_POW, &mut rng);
        let enc_cai = ExtendedEncrValuesCAI::<RistrettoGroup>::new(&cai, &election_pk, &mut rng);
        let binding0 = enc_cai.clone().to_encrypted();
        let binding = enc_choice.clone().to_encryption();
        let public = ProofCAIPublic::new(&election_pk, &binding0, &binding);

        let witness = ProofCAIWitness::new(&cai, &enc_cai, &enc_choice);
        let start = Instant::now();
        let proof = ProofCAI::prove(public.clone(), &witness, &mut rng);
        let duration = start.elapsed();
        println!("ProofEncChoice prove: {:?}", duration);

        proof.verify(public).unwrap();
    }

    #[test]
    fn disclose_cai() {
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

        let n1 = 10;
        let ln2 = vec![10; n1];
        // Generate new parameters for an election.
        let choice_parameters = ChoiceParameters::new(n1, ln2.clone(), false).unwrap();
        // Make a new valid choice.

        let mut rng = thread_rng();
        let choice = Choice::new(
            rng.gen_range(0..n1),
            vec![rng.gen_range(0..10)],
            &choice_parameters,
        )
        .unwrap();

        // Encrypt the Choice.
        let enc_choice = ExtendedEncrChoice::new(&choice, &election_pk, &mut rng);

        // From the encrypted choice generate the CAI values and related proofs.
        let cai = ValuesCAI::new(&choice, CAI_POW, &mut rng);
        let enc_cai = ExtendedEncrValuesCAI::<RistrettoGroup>::new(&cai, &election_pk, &mut rng);
        let discl = DiscloseCAI {
            l1: ChoiceDiscloseCAI::Sum {
                l_r: enc_cai.l1_sum_enc.expose().clone(),
            },
            l2: ChoiceDiscloseCAI::Code {
                l_r: enc_cai.l2_code_enc.expose().clone(),
            },
        };
        let reveal = enc_cai
            .to_encrypted()
            .extract_CAI_values(discl, &election_pk, &DLOG_TABLE)
            .unwrap();
        match reveal.l1 {
            ChoiceRevealedCAI::Sum { l_v, .. } => assert_eq!(
                l_v,
                <RistrettoGroup as GroupScalar>::Scalar::from(cai.l1_sum % CAI_POW)
            ),
            ChoiceRevealedCAI::Code { l_v, .. } => assert_eq!(
                l_v,
                <RistrettoGroup as GroupScalar>::Scalar::from(cai.l1_code)
            ),
        }

        match reveal.l2 {
            ChoiceRevealedCAI::Sum { l_v, .. } => assert_eq!(
                l_v,
                <RistrettoGroup as GroupScalar>::Scalar::from(cai.l2_sum % CAI_POW)
            ),
            ChoiceRevealedCAI::Code { l_v, .. } => assert_eq!(
                l_v,
                <RistrettoGroup as GroupScalar>::Scalar::from(cai.l2_code)
            ),
        }
    }
}
// endregion: --- Tests
