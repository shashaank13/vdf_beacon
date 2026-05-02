//! VDF benchmark harness.
//!
//! Runs Pietrzak, Wesolowski, and Hash+SNARK VDF constructions across a
//! configurable set of delay values, then writes results to a CSV file
//! (`results/bench.csv`) ready for `scripts/plot_results.py`.
//!
//! ## Usage
//! ```bash
//! cargo run --release -p vdf-bench
//! # Override T values:
//! T_VALUES="64,256,1024" cargo run --release -p vdf-bench
//! ```

use std::{
    env,
    fs,
    io::Write,
    path::Path,
    time::Duration,
};

use vdf_core::{VDF, VDFParams};
use vdf_pietrzak::PietrzakVDF;
use vdf_wesolowski::WesolowskiVDF;
use vdf_snark::SnarkVDF;

// ── Record type ───────────────────────────────────────────────────────────────

/// One row in the output CSV.
struct BenchRecord {
    /// Construction name.
    construction: String,
    /// Requested delay parameter.
    t_requested: u64,
    /// Effective delay (may differ for Pietrzak due to power-of-two rounding).
    t_effective: u64,
    /// Wall-clock evaluation time in milliseconds.
    eval_ms: f64,
    /// Wall-clock proof-generation time in milliseconds.
    prove_ms: f64,
    /// Proof size in bytes.
    proof_bytes: usize,
    /// Whether the verifier accepted the proof.
    verified: bool,
}

impl BenchRecord {
    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{:.4},{:.4},{},{}\n",
            self.construction,
            self.t_requested,
            self.t_effective,
            self.eval_ms,
            self.prove_ms,
            self.proof_bytes,
            self.verified,
        )
    }
}

// ── Benchmark runner ──────────────────────────────────────────────────────────

fn dur_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

/// Run one VDF construction and return a populated [`BenchRecord`].
fn bench_one<V: VDF>(name: &str, params: &VDFParams, x: &[u8]) -> BenchRecord {
    let vdf = V::setup(params);

    let (y, eval_time) = vdf.eval(x);
    let (out, prove_time) = vdf.prove(x, &y);
    let verified = vdf.verify(x, &out);

    // For Pietrzak, the effective T is rounded to the next power of two.
    // We detect this by checking whether the construction name contains
    // "Pietrzak" — a lightweight but sufficient approach for a bench harness.
    let t_effective = if name.contains("Pietrzak") {
        params.t.next_power_of_two().max(2)
    } else {
        params.t
    };

    BenchRecord {
        construction: name.to_string(),
        t_requested: params.t,
        t_effective,
        eval_ms: dur_ms(eval_time),
        prove_ms: dur_ms(prove_time),
        proof_bytes: out.proof.len(),
        verified,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // T values to sweep over.  Can be overridden via env var.
    let t_values: Vec<u64> = env::var("T_VALUES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|v| v.trim().parse().ok())
                .collect()
        })
        .unwrap_or_else(|| vec![64, 256, 1024, 4096, 16384, 65536]);


    let lambda: usize = env::var("LAMBDA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2048);

    let x: &[u8] = b"vdf-benchmark-input-2025";

    println!("VDF Benchmark");
    println!("=============");
    println!("λ = {lambda} bits   x = {:?}", std::str::from_utf8(x).unwrap());
    println!("T values: {t_values:?}");
    println!();

    let mut records: Vec<BenchRecord> = Vec::new();

    for &t in &t_values {
        let params = VDFParams { t, lambda };

        println!("── T = {t} ──────────────────────────────────────");

        // Pietrzak
        print!("  Pietrzak   ");
        let rec = bench_one::<PietrzakVDF>("Pietrzak", &params, x);
        println!(
            "eval={:.1}ms  prove={:.1}ms  proof={}B  ok={}",
            rec.eval_ms, rec.prove_ms, rec.proof_bytes, rec.verified
        );
        records.push(rec);

        // Wesolowski
        print!("  Wesolowski ");
        let rec = bench_one::<WesolowskiVDF>("Wesolowski", &params, x);
        println!(
            "eval={:.1}ms  prove={:.1}ms  proof={}B  ok={}",
            rec.eval_ms, rec.prove_ms, rec.proof_bytes, rec.verified
        );
        records.push(rec);

        // Hash+SNARK
        print!("  SNARK-SHA  ");
        let rec = bench_one::<SnarkVDF>("SNARK-SHA256", &params, x);
        println!(
            "eval={:.1}ms  prove={:.1}ms  proof={}B  ok={}",
            rec.eval_ms, rec.prove_ms, rec.proof_bytes, rec.verified
        );
        records.push(rec);
    }

    println!();

    // Write CSV
    let out_dir = Path::new("results");
    fs::create_dir_all(out_dir).expect("failed to create results/");
    let csv_path = out_dir.join("bench.csv");
    let mut file = fs::File::create(&csv_path).expect("failed to open CSV file");
    // Header
    writeln!(file, "construction,t_requested,t_effective,eval_ms,prove_ms,proof_bytes,verified")
        .expect("CSV write failed");
    for rec in &records {
        file.write_all(rec.to_csv_row().as_bytes()).expect("CSV write failed");
    }

    println!("Results written to {}", csv_path.display());
    println!("Run  python scripts/plot_results.py results/bench.csv  to plot.");
}
