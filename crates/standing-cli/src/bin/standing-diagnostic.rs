//! Closed, one-shot Standing-owned service diagnostic admission.
use clap::Parser;
use standing_store::{
    Store,
    diagnostic::{DiagnosticEnrollment, DiagnosticRequest, Signed},
};
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    store: PathBuf,
    /// Deployment-owned signed enrollment, never a browser field.
    #[arg(long)]
    enrollment: PathBuf,
    /// Deployment-pinned operator public key (64 lowercase hexadecimal bytes).
    #[arg(long)]
    operator_public_key: PathBuf,
    #[arg(long)]
    audience: String,
}

fn regular(path: &std::path::Path, max: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = f.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.len() > max as u64 {
        return Err("source is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut f)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = f.metadata().map_err(|e| e.to_string())?;
    if bytes.len() != before.len() as usize
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("source changed while reading".into());
    }
    Ok(bytes)
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let enrollment: Signed<DiagnosticEnrollment> =
        serde_json::from_slice(&regular(&args.enrollment, 32768)?).map_err(|e| e.to_string())?;
    let key =
        String::from_utf8(regular(&args.operator_public_key, 65)?).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 32768 {
        return Err("request exceeds bound".into());
    }
    let request: Signed<DiagnosticRequest> =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    // This consumer may use only an existing enrolled store. Store directory and
    // contents are trusted owner custody; this is not cross-UID store confinement.
    let meta = std::fs::symlink_metadata(&args.store).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("existing regular Standing store required".into());
    }
    let mut store = Store::open(args.store.to_str().ok_or("non-UTF8 store path")?)
        .map_err(|e| e.to_string())?;
    let result =
        store.admit_service_diagnostic(&enrollment, key.trim(), &args.audience, &request)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "schema": "standing.service-diagnostic-admission-result/v1",
            "receipt": result.receipt,
            "request_digest": standing_store::diagnostic::request_digest(&request.body)?,
            "provider_invoked": false
        }))
        .map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(reason) = run() {
        // Refusal is not an admission and never carries a reusable permission.
        println!(
            "{}",
            serde_json::json!({"schema":"standing.service-diagnostic-refusal/v1", "reason":reason, "provider_invoked":false})
        );
        std::process::exit(1);
    }
}
