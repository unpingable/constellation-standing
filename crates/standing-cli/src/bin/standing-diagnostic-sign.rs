//! Separate control-process signer for closed diagnostic mandate artifacts.
use clap::{Parser, ValueEnum};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use standing_store::diagnostic::{
    DiagnosticEnrollment, DiagnosticRequest, ENROLLMENT_SCHEMA, REQUEST_SCHEMA, Signed,
    signing_bytes,
};
use std::{io::Read as _, path::PathBuf};

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Enrollment,
    Request,
}

#[derive(Parser)]
#[command(about = "Sign one exact Standing service-diagnostic artifact")]
struct Args {
    #[arg(value_enum)]
    kind: Kind,
    /// Deployment-owned 32-byte Ed25519 seed as 64 lowercase hexadecimal characters.
    #[arg(long)]
    secret_key: PathBuf,
}

fn regular(path: &std::path::Path, max: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err("secret key is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if bytes.len() != metadata.len() as usize
        || metadata.len() != after.len()
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
        || metadata.ctime() != after.ctime()
        || metadata.ctime_nsec() != after.ctime_nsec()
        || metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
    {
        return Err("secret key changed while reading".into());
    }
    Ok(bytes)
}

fn key(path: &std::path::Path) -> Result<SigningKey, String> {
    let text = String::from_utf8(regular(path, 65)?).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = hex::decode(text.trim())
        .map_err(|_| "invalid secret key encoding")?
        .try_into()
        .map_err(|_| "secret key must contain exactly 32 bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn input() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 32768 {
        return Err("unsigned artifact exceeds bound".into());
    }
    Ok(bytes)
}

fn emit<T: Serialize>(schema: &str, body: T, key: &SigningKey) -> Result<(), String> {
    let signature = hex::encode(key.sign(&signing_bytes(schema, &body)?).to_bytes());
    println!(
        "{}",
        serde_json::to_string(&Signed { body, signature }).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let key = key(&args.secret_key)?;
    let bytes = input()?;
    match args.kind {
        Kind::Enrollment => {
            let body: DiagnosticEnrollment =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if body.schema != ENROLLMENT_SCHEMA {
                return Err("enrollment schema mismatch".into());
            }
            emit(ENROLLMENT_SCHEMA, body, &key)
        }
        Kind::Request => {
            let body: DiagnosticRequest =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if body.schema != REQUEST_SCHEMA {
                return Err("request schema mismatch".into());
            }
            emit(REQUEST_SCHEMA, body, &key)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("standing diagnostic signing refused: {error}");
        std::process::exit(1);
    }
}
