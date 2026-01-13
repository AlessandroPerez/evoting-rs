//! Integration test that prints timing and serialized sizes.
//!
//! This is not a microbenchmark. It is meant to give a rough idea of:
//! - which protocol steps dominate runtime
//! - approximate payload sizes for bulletin board publication
//!
//! It is ignored so it does not run on CI by default.
//! Run with:
//!   cargo test --release --test bench_pipeline -- --ignored --nocapture

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::{ciphertext::DiscreteLogTable, keys::ElGamalParams};
use rand::thread_rng;
use serde::Serialize;

use evoting::{
    api::client::Voter,
    api::prelude::{
        BallotBuilder, Choice, ChoiceParameters, ElectionParams, RegistrationTeller, ShortPublicACC,
        TabulationTeller, TTSecretKey, VoterBuilder,
    },
    api::server::bb::{
        BulletinBoardStore, ElectionContext, ElectionManifest, InMemoryBB, PublicElection,
        PublicPipeline,
    },
};

const NUM_VOTERS: usize = 10;
const N1: usize = 4;
const LN2: [usize; N1] = [10; N1];

// Extra adversarial load knobs
const WRONG_PIN_EXTRA: usize = 2;
const DOUBLE_VOTE_EXTRA: usize = 3;

// Repeat the entire pipeline this many times.
// Increase if you want smoother numbers.
const REPS: usize = 5;

static DLOG_TABLE: LazyLock<DiscreteLogTable<RistrettoGroup>> =
    LazyLock::new(|| DiscreteLogTable::new(0..=1000));

#[derive(Clone)]
struct VoterMaterial<G: dlog_group::group::Group> {
    voter: Voter<G>,
    pin: usize,
    builder: BallotBuilder,
    pub_cred: ShortPublicACC<G>,
}

fn cbor_len<T: Serialize>(x: &T) -> usize {
    serde_cbor::to_vec(x).expect("cbor serialization").len()
}

#[derive(Default, Clone)]
struct StepStats {
    durations: Vec<Duration>,
    bytes: Option<usize>,
}

impl StepStats {
    fn push(&mut self, d: Duration) {
        self.durations.push(d);
    }

    fn set_bytes_once(&mut self, b: usize) {
        if self.bytes.is_none() {
            self.bytes = Some(b);
        }
    }

    fn min(&self) -> Duration {
        *self.durations.iter().min().unwrap_or(&Duration::ZERO)
    }

    fn max(&self) -> Duration {
        *self.durations.iter().max().unwrap_or(&Duration::ZERO)
    }

    fn avg(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }
        let total_ns: u128 = self.durations.iter().map(|d| d.as_nanos()).sum();
        let avg_ns = total_ns / (self.durations.len() as u128);
        Duration::from_nanos(avg_ns as u64)
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn pad(s: &str, w: usize) -> String {
    format!("{:<width$}", s, width = w)
}

fn pad_r(s: &str, w: usize) -> String {
    format!("{:>width$}", s, width = w)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Client,
    BulletinBoard,
    RegistrationTeller,
    TabulationTeller,
    CryptoCore,
}

fn role_of(step: &str) -> Role {
    match step {
        // Client side
        "setup_voters" | "post_ballots" => Role::Client,

        // Bulletin board / public pipeline
        "verify_ballots"
        | "mix_votes"
        | "verify_vote_mix"
        | "filter_invalid"
        | "verify_acc_checks"
        | "mix_credentials"
        | "verify_cred_mix"
        | "gen_credential_fingerprints"
        | "filter_illicit_keep_last"
        | "homomorphic_sum"
        | "verify_decrypted_tally" => Role::BulletinBoard,

        // Registration Teller
        "rt.gen_controls" => Role::RegistrationTeller,

        // Tabulation Teller
        "tt.gen_acc_checks" | "decrypt_credential_fingerprints" | "decrypt_tally" => {
            Role::TabulationTeller
        }

        _ => Role::CryptoCore,
    }
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Client => "Client",
        Role::BulletinBoard => "BulletinBoard",
        Role::RegistrationTeller => "RegistrationTeller",
        Role::TabulationTeller => "TabulationTeller",
        Role::CryptoCore => "CryptoCore",
    }
}

fn setup() -> (
    RegistrationTeller<RistrettoGroup>,
    TabulationTeller<RistrettoGroup>,
    ElectionContext<RistrettoGroup>,
    ChoiceParameters,
    PublicPipeline<RistrettoGroup>,
) {
    let mut rng = thread_rng();

    let tt_sk: TTSecretKey<RistrettoGroup> = TTSecretKey::new(&mut rng);
    let elgamal = ElGamalParams::new(&mut rng);

    let params: ElectionParams<RistrettoGroup> =
        ElectionParams::new(&elgamal, &tt_sk.meg_sk.to_public(&elgamal), &mut rng);

    let rt = RegistrationTeller::new(params, &mut rng);

    let choice_params = ChoiceParameters::new(N1, LN2.to_vec(), false).unwrap();

    let manifest = ElectionManifest {
        election_id: "bench-election".to_string(),
        title: "Bench election".to_string(),
        authority: "bench".to_string(),
        version: 1,
    };

    let ctx = rt.election_context(manifest, choice_params.clone());
    let tt = TabulationTeller::new(tt_sk, &ctx);
    let bb = PublicPipeline::new(PublicElection::new(ctx.clone()));

    (rt, tt, ctx, choice_params, bb)
}

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
        let (cred_builder, pin, public_acc) = rt.gen_builder(&mut rng);

        let vb = VoterBuilder::new(ctx, cred_builder.clone(), &mut rng);

        let cred = rt
            .gen_credential(&vb.voter_pk(), &cred_builder, &mut rng)
            .unwrap();

        let voter = vb.finalize(cred);
        let pub_cred = rt.short_public_acc(&public_acc).unwrap();

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

fn post_ballots(
    store: &mut impl BulletinBoardStore<RistrettoGroup>,
    voters: &[VoterMaterial<RistrettoGroup>],
    wrong_pin_extra: usize,
    double_vote_extra: usize,
) -> Vec<ShortPublicACC<RistrettoGroup>> {
    let mut rng = thread_rng();

    for vm in voters {
        let ballot = vm.voter.vote(&vm.builder, vm.pin, &mut rng);
        store.post_ballot(ballot).unwrap();
    }

    if wrong_pin_extra > 0 {
        let vm = voters[1].clone();
        for _ in 0..wrong_pin_extra {
            let ballot = vm.voter.vote(&vm.builder, vm.pin + 1, &mut rng);
            store.post_ballot(ballot).unwrap();
        }
    }

    if double_vote_extra > 0 {
        let vm = voters[0].clone();
        for _ in 0..double_vote_extra {
            let ballot = vm.voter.vote(&vm.builder, vm.pin, &mut rng);
            store.post_ballot(ballot).unwrap();
        }
    }

    voters.iter().map(|v| v.pub_cred.clone()).collect()
}

#[test]
#[ignore]
fn pipeline_timings_and_sizes_pretty() {
    let build_mode = if cfg!(debug_assertions) {
        "DEBUG (not meaningful for performance)"
    } else {
        "RELEASE (optimized)"
    };

    println!();
    println!("============================================================");
    println!("Pipeline timing and size report");
    println!("Build mode: {}", build_mode);
    println!("Repetitions: {}", REPS);
    println!("Voters: {}", NUM_VOTERS);
    println!(
        "Extra ballots: wrong-pin = {}, double-vote = {}",
        WRONG_PIN_EXTRA, DOUBLE_VOTE_EXTRA
    );
    println!(
        "Total ballots posted per run: {}",
        NUM_VOTERS + WRONG_PIN_EXTRA + DOUBLE_VOTE_EXTRA
    );
    println!("Notes:");
    println!(" - This is protocol-level timing, not a microbenchmark.");
    println!(" - Absolute timings depend on CPU, OS, and randomness.");
    println!(" - Serialized sizes are exact for CBOR encoding, but depend on parameters.");
    println!("============================================================");
    println!();

    let (rt, tt, ctx, choice_params, bb) = setup();
    let ctx_bytes = cbor_len(&ctx);

    let mut stats: BTreeMap<&'static str, StepStats> = BTreeMap::new();

    let mut measure = |name: &'static str, f: &mut dyn FnMut() -> Option<usize>| {
        let start = Instant::now();
        let bytes = f();
        let elapsed = start.elapsed();

        let entry = stats.entry(name).or_default();
        entry.push(elapsed);
        if let Some(b) = bytes {
            entry.set_bytes_once(b);
        }
    };

    for _ in 0..REPS {
        let mut rng = thread_rng();

        let mut voters: Vec<VoterMaterial<RistrettoGroup>> = Vec::new();
        measure("setup_voters", &mut || {
            voters = setup_voters(&rt, &ctx, &choice_params);
            None
        });

        let mut store: InMemoryBB<RistrettoGroup> = InMemoryBB::default();
        let mut pub_creds: Vec<ShortPublicACC<RistrettoGroup>> = Vec::new();
        measure("post_ballots", &mut || {
            pub_creds = post_ballots(&mut store, &voters, WRONG_PIN_EXTRA, DOUBLE_VOTE_EXTRA);
            Some(cbor_len(&store.list_ballots()))
        });

        let ballots = store.list_ballots();
        let mut originals = Vec::new();
        measure("verify_ballots", &mut || {
            originals = bb.verify_ballots(&ballots).unwrap();
            None
        });

        let mut vote_mix = None;
        measure("mix_votes", &mut || {
            let vm = bb.mix_votes(&originals, &mut rng);
            let bytes = cbor_len(&vm);
            vote_mix = Some(vm);
            Some(bytes)
        });
        let vote_mix = vote_mix.unwrap();

        measure("verify_vote_mix", &mut || {
            bb.verify_vote_mix(&originals, &vote_mix).unwrap();
            None
        });

        let shuffled_votes = vote_mix
            .shuffled
            .iter()
            .map(|r| r.vote.clone())
            .collect::<Vec<_>>();

        let mut controls = Vec::new();
        measure("rt.gen_controls", &mut || {
            controls = rt.gen_controls(&shuffled_votes, &mut rng);
            Some(cbor_len(&controls))
        });

        let mut acc_checks = Vec::new();
        measure("tt.gen_acc_checks", &mut || {
            acc_checks = tt
                .gen_acc_checks(&shuffled_votes, &controls, &mut rng)
                .unwrap();
            Some(cbor_len(&acc_checks))
        });

        let mut valid = Vec::new();
        measure("filter_invalid", &mut || {
            valid = bb
                .filter_invalid(&vote_mix.shuffled, &controls, &acc_checks)
                .unwrap();
            Some(cbor_len(&valid))
        });

        measure("verify_acc_checks", &mut || {
            bb.verify_acc_checks(&acc_checks, &controls, &vote_mix.shuffled)
                .unwrap();
            None
        });

        let mut cred_mix = None;
        measure("mix_credentials", &mut || {
            let cm = bb.mix_credentials(&pub_creds, &mut rng);
            let bytes = cbor_len(&cm);
            cred_mix = Some(cm);
            Some(bytes)
        });
        let cred_mix = cred_mix.unwrap();

        measure("verify_cred_mix", &mut || {
            bb.verify_cred_mix(&pub_creds, &cred_mix).unwrap();
            None
        });

        let mut fps = None;
        measure("gen_credential_fingerprints", &mut || {
            let f = bb
                .gen_credential_fingerprints(&pub_creds, &cred_mix, &valid, &mut rng)
                .unwrap();
            let bytes = cbor_len(&f);
            fps = Some(f);
            Some(bytes)
        });
        let fps = fps.unwrap();

        let valid_votes_vec = valid.iter().map(|r| r.vote.clone()).collect::<Vec<_>>();
        let mut dec_pub_fps = Vec::new();
        let mut dec_votes_fps = Vec::new();
        measure("decrypt_credential_fingerprints", &mut || {
            let (a, b) = tt
                .decrypt_credential_fingerprints(&valid_votes_vec, &fps, &cred_mix.shuffled, &mut rng)
                .unwrap();
            let bytes = cbor_len(&a) + cbor_len(&b);
            dec_pub_fps = a;
            dec_votes_fps = b;
            Some(bytes)
        });

        let mut legitimate = Vec::new();
        measure("filter_illicit_keep_last", &mut || {
            legitimate = bb
                .filter_illicit_keep_last(&valid, &cred_mix, &fps, &dec_pub_fps, &dec_votes_fps)
                .unwrap();
            Some(cbor_len(&legitimate))
        });

        // Let compiler infer the opaque encrypted tally type
        let mut enc_tally = bb.homomorphic_sum(Vec::new());
        measure("homomorphic_sum", &mut || {
            enc_tally = bb.homomorphic_sum(legitimate.clone());
            Some(cbor_len(&enc_tally))
        });

        let mut decr_tally = None;
        measure("decrypt_tally", &mut || {
            let dt = tt
                .decrypt_tally(enc_tally.clone(), &DLOG_TABLE, &mut rng)
                .unwrap();
            let bytes = cbor_len(&dt);
            decr_tally = Some(dt);
            Some(bytes)
        });
        let decr_tally = decr_tally.unwrap();

        measure("verify_decrypted_tally", &mut || {
            bb.verify_decrypted_tally(&enc_tally, &decr_tally).unwrap();
            None
        });
    }

    // Totals
    let total_avg_ms: f64 = stats.values().map(|s| ms(s.avg())).sum();

    // Role totals
    let mut role_totals: BTreeMap<Role, Duration> = BTreeMap::new();
    for (name, st) in stats.iter() {
        let r = role_of(name);
        *role_totals.entry(r).or_insert(Duration::ZERO) += st.avg();
    }

    println!("Public context:");
    println!(" - ElectionContext cbor bytes: {}", ctx_bytes);
    println!();

    // Per-step table
    println!("==============================================================================================");
    println!("PIPELINE PERFORMANCE SUMMARY (average over {} runs)", REPS);
    println!("==============================================================================================");
    println!(
        "{} | {} | {} | {} | {} | {}",
        pad("STEP", 34),
        pad_r("AVG ms", 10),
        pad_r("MIN ms", 10),
        pad_r("MAX ms", 10),
        pad_r("% TOTAL", 9),
        pad_r("BYTES", 10),
    );
    println!("{}", "-".repeat(94));

    for (name, st) in stats.iter() {
        let avg = ms(st.avg());
        let min = ms(st.min());
        let max = ms(st.max());
        let pct = if total_avg_ms > 0.0 {
            100.0 * avg / total_avg_ms
        } else {
            0.0
        };

        let bytes = st.bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".to_string());

        println!(
            "{} | {} | {} | {} | {} | {}",
            pad(name, 34),
            pad_r(&format!("{:.3}", avg), 10),
            pad_r(&format!("{:.3}", min), 10),
            pad_r(&format!("{:.3}", max), 10),
            pad_r(&format!("{:>6.2}%", pct), 9),
            pad_r(&bytes, 10),
        );
    }

    println!("{}", "-".repeat(94));
    println!(
        "{} | {}",
        pad("TOTAL (avg)", 34),
        pad_r(&format!("{:.3} ms", total_avg_ms), 59)
    );
    println!("==============================================================================================");
    println!();

    // Role-level table
    println!("==============================================================");
    println!("ROLE-LEVEL TIME BREAKDOWN (average per run)");
    println!("==============================================================");
    println!(
        "{} | {} | {}",
        pad("ROLE", 24),
        pad_r("AVG ms", 12),
        pad_r("% TOTAL", 10),
    );
    println!("{}", "-".repeat(52));

    for (role, dur) in role_totals.iter() {
        let ms_role = ms(*dur);
        let pct = if total_avg_ms > 0.0 {
            100.0 * ms_role / total_avg_ms
        } else {
            0.0
        };

        println!(
            "{} | {} | {}",
            pad(role_name(*role), 24),
            pad_r(&format!("{:.3}", ms_role), 12),
            pad_r(&format!("{:>6.2}%", pct), 10),
        );
    }

    println!("{}", "-".repeat(52));
    println!(
        "{} | {}",
        pad("TOTAL", 24),
        pad_r(&format!("{:.3} ms", total_avg_ms), 23)
    );
    println!("==============================================================");
    println!();
}
