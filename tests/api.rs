use std::sync::LazyLock;

use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::{ciphertext::DiscreteLogTable, keys::ElGamalParams};
use rand::thread_rng;

use evoting::{
    api::client::Voter, // used in VoterMaterial
    api::prelude::{
        BallotBuilder, Choice, ChoiceParameters, ElectionParams, EncrChoice, RegistrationTeller,
        ShortPublicACC, TabulationTeller, TTSecretKey, VoterBuilder,
    },
    api::server::bb::{
        BulletinBoardStore, ElectionContext, ElectionManifest, InMemoryBB, PublicElection,
        PublicPipeline,
    },
};

const NUM_VOTERS: usize = 10;
const N1: usize = 4;
const LN2: [usize; N1] = [10; N1];

static DLOG_TABLE: LazyLock<DiscreteLogTable<RistrettoGroup>> =
    LazyLock::new(|| DiscreteLogTable::new(0..=1000));

fn setup() -> (
    RegistrationTeller<RistrettoGroup>,
    TabulationTeller<RistrettoGroup>,
    ElectionContext<RistrettoGroup>,
    ChoiceParameters,
    PublicPipeline<RistrettoGroup>,
) {
    let mut rng = thread_rng();

    // TT secret key; its public part is embedded in election params
    let tt_sk: TTSecretKey<RistrettoGroup> = TTSecretKey::new(&mut rng);

    // ElGamal parameters
    let elgamal = ElGamalParams::new(&mut rng);

    // Election parameters bind ElGamal + TT public key
    let params: ElectionParams<RistrettoGroup> =
        ElectionParams::new(&elgamal, &tt_sk.meg_sk.to_public(&elgamal), &mut rng);

    // RT
    let rt = RegistrationTeller::new(params, &mut rng);

    // Choice space
    let choice_params = ChoiceParameters::new(N1, LN2.to_vec(), false).unwrap();

    // Public manifest (for context hash binding)
    let manifest = ElectionManifest {
        election_id: "test-election".to_string(),
        title: "Integration test election".to_string(),
        authority: "test-authority".to_string(),
        version: 1,
    };

    // Election context: single public object everyone agrees on
    let ctx = rt.election_context(manifest, choice_params.clone());

    // TT bound to context
    let tt = TabulationTeller::new(tt_sk, &ctx);

    // BB public pipeline bound to public election
    let bb = PublicPipeline::new(PublicElection::new(ctx.clone()));

    (rt, tt, ctx, choice_params, bb)
}

#[derive(Clone)]
struct VoterMaterial<G: dlog_group::group::Group> {
    voter: Voter<G>,
    pin: usize,
    builder: BallotBuilder,
    pub_cred: ShortPublicACC<G>,
}

/// Create NUM_VOTERS legitimate voters and one deterministic ballot builder (same choice for all).
fn setup_voters(
    rt: &RegistrationTeller<RistrettoGroup>,
    ctx: &ElectionContext<RistrettoGroup>,
    choice_params: &ChoiceParameters,
) -> Vec<VoterMaterial<RistrettoGroup>> {
    let mut rng = thread_rng();

    let fixed_party = 1usize;
    let fixed_candidate = 0usize;

    let mut out = Vec::with_capacity(NUM_VOTERS);

    for _ in 0..NUM_VOTERS {
        // RT issues builder + pin + public acc
        let (cred_builder, pin, public_acc) = rt.gen_builder(&mut rng);

        // Client generates keys bound to ctx
        let vb = VoterBuilder::new(ctx, cred_builder.clone(), &mut rng);

        // RT finalizes credential bound to voter's pk
        let cred = rt
            .gen_credential(&vb.voter_pk(), &cred_builder, &mut rng)
            .unwrap();

        let voter = vb.finalize(cred);

        // Short form used by credential mixing
        let pub_cred = rt.short_public_acc(&public_acc).unwrap();

        // Deterministic choice so tally is predictable
        let choice = Choice::new(fixed_party, vec![fixed_candidate], choice_params).unwrap();
        let builder = BallotBuilder::new(choice);

        out.push(VoterMaterial {
            voter,
            pin,
            builder,
            pub_cred,
        });
    }

    out
}

/// Post ballots through the BB store so it can assign deterministic receipts/seq_no.
///
/// wrong_pin_extra:
/// - adds N ballots from voters[1] with pin+1 -> should be filtered by filter_invalid.
///
/// double_vote_extra:
/// - adds N additional ballots from voters[0] with correct pin.
/// - should be resolved by filter_illicit_keep_last ("last vote wins") into exactly 1 per credential.
fn post_ballots(
    store: &mut impl BulletinBoardStore<RistrettoGroup>,
    voters: &[VoterMaterial<RistrettoGroup>],
    wrong_pin_extra: usize,
    double_vote_extra: usize,
) -> Vec<ShortPublicACC<RistrettoGroup>> {
    let mut rng = thread_rng();

    // Honest ballots
    for vm in voters {
        let ballot = vm.voter.vote(&vm.builder, vm.pin, &mut rng);
        store.post_ballot(ballot).unwrap();
    }

    // Wrong PIN ballots
    if wrong_pin_extra > 0 {
        let vm = voters[1].clone();
        for _ in 0..wrong_pin_extra {
            let ballot = vm.voter.vote(&vm.builder, vm.pin + 1, &mut rng);
            store.post_ballot(ballot).unwrap();
        }
    }

    // Duplicate ballots
    if double_vote_extra > 0 {
        let vm = voters[0].clone();
        for _ in 0..double_vote_extra {
            let ballot = vm.voter.vote(&vm.builder, vm.pin, &mut rng);
            store.post_ballot(ballot).unwrap();
        }
    }

    voters.iter().map(|v| v.pub_cred.clone()).collect()
}

struct PipelineArtifacts<G: dlog_group::group::Group> {
    originals_len: usize,
    valid_len: usize,
    legitimate_len: usize,
    enc_tally: EncrChoice<G>,
}

/// Run the whole pipeline using the context bound BB + TT.
fn run_pipeline(
    rt: &RegistrationTeller<RistrettoGroup>,
    tt: &TabulationTeller<RistrettoGroup>,
    bb: &PublicPipeline<RistrettoGroup>,
    store: &impl BulletinBoardStore<RistrettoGroup>,
    pub_creds: &[ShortPublicACC<RistrettoGroup>],
) -> PipelineArtifacts<RistrettoGroup> {
    let mut rng = thread_rng();

    // Load posted ballots
    let ballots = store.list_ballots();

    // Verify ballots -> verified vote records (vote + receipt/seq_no)
    let originals = bb.verify_ballots(&ballots).unwrap();

    // Mix votes and verify proof
    let vote_mix = bb.mix_votes(&originals, &mut rng);
    bb.verify_vote_mix(&originals, &vote_mix).unwrap();

    // Controls/ACC checks run over the (mixed) vote list in the same order
    let shuffled_votes = vote_mix
        .shuffled
        .iter()
        .map(|r| r.vote.clone())
        .collect::<Vec<_>>();

    let controls = rt.gen_controls(&shuffled_votes, &mut rng);

    let acc_checks = tt
        .gen_acc_checks(&shuffled_votes, &controls, &mut rng)
        .unwrap();

    // Remove wrong PIN ballots but keep receipts
    let valid = bb
        .filter_invalid(&vote_mix.shuffled, &controls, &acc_checks)
        .unwrap();

    // Public audit: TT checks consistent with controls and votes
    bb.verify_acc_checks(&acc_checks, &controls, &vote_mix.shuffled)
        .unwrap();

    // Credential mixing
    let cred_mix = bb.mix_credentials(pub_creds, &mut rng);
    bb.verify_cred_mix(pub_creds, &cred_mix).unwrap();

    // Fingerprints binding vote list to credential list
    let fps = bb
        .gen_credential_fingerprints(pub_creds, &cred_mix, &valid, &mut rng)
        .unwrap();

    // TT decrypts fingerprints
    let valid_votes_vec = valid.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();

    let (dec_pub_fps, dec_votes_fps) = tt
        .decrypt_credential_fingerprints(&valid_votes_vec, &fps, &cred_mix.shuffled, &mut rng)
        .unwrap();

    // Resolve duplicates using last vote wins
    let legitimate = bb
        .filter_illicit_keep_last(&valid, &cred_mix, &fps, &dec_pub_fps, &dec_votes_fps)
        .unwrap();

    // Homomorphic tally
    let enc_tally = bb.homomorphic_sum(legitimate.clone());

    PipelineArtifacts {
        originals_len: originals.len(),
        valid_len: valid.len(),
        legitimate_len: legitimate.len(),
        enc_tally,
    }
}

fn decrypt_and_verify_tally(
    tt: &TabulationTeller<RistrettoGroup>,
    bb: &PublicPipeline<RistrettoGroup>,
    enc_tally: EncrChoice<RistrettoGroup>,
) {
    let mut rng = thread_rng();

    let decr_tally = tt
        .decrypt_tally(enc_tally.clone(), &DLOG_TABLE, &mut rng)
        .unwrap();

    bb.verify_decrypted_tally(&enc_tally, &decr_tally).unwrap();
}

#[test]
fn pipeline_no_filtering_expected() {
    let (rt, tt, ctx, choice_params, bb) = setup();
    let voters = setup_voters(&rt, &ctx, &choice_params);

    let mut store: InMemoryBB<RistrettoGroup> = InMemoryBB::default();
    let pub_creds = post_ballots(&mut store, &voters, 0, 0);

    let art = run_pipeline(&rt, &tt, &bb, &store, &pub_creds);

    assert_eq!(art.originals_len, NUM_VOTERS);
    assert_eq!(art.valid_len, NUM_VOTERS);
    assert_eq!(art.legitimate_len, NUM_VOTERS);

    decrypt_and_verify_tally(&tt, &bb, art.enc_tally);
}

#[test]
fn pipeline_filters_wrong_pin_only() {
    let wrong_pin_extra = 2usize;

    let (rt, tt, ctx, choice_params, bb) = setup();
    let voters = setup_voters(&rt, &ctx, &choice_params);

    let mut store: InMemoryBB<RistrettoGroup> = InMemoryBB::default();
    let pub_creds = post_ballots(&mut store, &voters, wrong_pin_extra, 0);

    let art = run_pipeline(&rt, &tt, &bb, &store, &pub_creds);

    // Wrong PIN ballots are still well formed ballots
    assert_eq!(art.originals_len, NUM_VOTERS + wrong_pin_extra);

    // Wrong PIN filtered here
    assert_eq!(art.valid_len, NUM_VOTERS);

    // No duplicates introduced
    assert_eq!(art.legitimate_len, NUM_VOTERS);

    decrypt_and_verify_tally(&tt, &bb, art.enc_tally);
}

#[test]
fn pipeline_filters_double_voting_only() {
    let double_vote_extra = 3usize;

    let (rt, tt, ctx, choice_params, bb) = setup();
    let voters = setup_voters(&rt, &ctx, &choice_params);

    let mut store: InMemoryBB<RistrettoGroup> = InMemoryBB::default();
    let pub_creds = post_ballots(&mut store, &voters, 0, double_vote_extra);

    let art = run_pipeline(&rt, &tt, &bb, &store, &pub_creds);

    // All are well formed ballots
    assert_eq!(art.originals_len, NUM_VOTERS + double_vote_extra);

    // Authentication valid -> invalid filter keeps duplicates
    assert_eq!(art.valid_len, NUM_VOTERS + double_vote_extra);

    // Duplicates resolved by keep last
    assert_eq!(art.legitimate_len, NUM_VOTERS);

    decrypt_and_verify_tally(&tt, &bb, art.enc_tally);
}

#[test]
fn pipeline_filters_wrong_pin_and_double_voting() {
    let wrong_pin_extra = 2usize;
    let double_vote_extra = 3usize;

    let (rt, tt, ctx, choice_params, bb) = setup();
    let voters = setup_voters(&rt, &ctx, &choice_params);

    let mut store: InMemoryBB<RistrettoGroup> = InMemoryBB::default();
    let pub_creds = post_ballots(&mut store, &voters, wrong_pin_extra, double_vote_extra);

    let art = run_pipeline(&rt, &tt, &bb, &store, &pub_creds);

    assert_eq!(
        art.originals_len,
        NUM_VOTERS + wrong_pin_extra + double_vote_extra
    );

    // Wrong PIN removed, duplicates remain
    assert_eq!(art.valid_len, NUM_VOTERS + double_vote_extra);

    // Duplicates resolved by keep last
    assert_eq!(art.legitimate_len, NUM_VOTERS);

    decrypt_and_verify_tally(&tt, &bb, art.enc_tally);
}