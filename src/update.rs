//! `mcp-ctl update`: report newer releases, and install one when this binary is
//! ours to replace.
//!
//! It only replaces a binary the install script put in place. Any other copy —
//! `cargo install`, a distribution package, a binary moved by hand — is left
//! alone and told to be updated the way it was installed: writing over a file
//! another tool owns puts that tool out of step with what is on disk.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const REPO: &str = "erikenz/mcp-ctl";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

pub fn run(check: bool) -> Result<u8> {
    let release = latest_release()?;
    if !is_newer(&release.version, CURRENT) {
        println!("mcp-ctl {CURRENT} is up to date.");
        return Ok(0);
    }
    println!("mcp-ctl {CURRENT} → {} is available.", release.version);

    if check {
        // Non-zero so a script can tell "up to date" from "there is more".
        return Ok(1);
    }

    if cfg!(windows) {
        // Replacing a running .exe is not something to be clever about; the
        // PowerShell installer already handles it.
        println!("Run the installer to update:");
        println!(
            "  irm https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.ps1 | iex"
        );
        return Ok(0);
    }

    let exe = std::env::current_exe().context("could not find the running binary")?;
    if !installer_owned(&exe) {
        println!("This copy was not installed by the install script, so it is left alone.");
        println!("Update it the way you installed it, or reinstall it with:");
        println!(
            "  curl -fsSL https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.sh | sh"
        );
        return Ok(0);
    }
    install(&release, &exe)?;
    println!("Updated to {}.", release.version);
    Ok(0)
}

/// Did the install script put this binary here?
///
/// The installer's default directory is the only one mcp-ctl may replace. An
/// install done with `--to` somewhere else is still safe, just not
/// self-updating.
fn installer_owned(exe: &Path) -> bool {
    exe.to_string_lossy()
        .replace('\\', "/")
        .ends_with("/.local/bin/mcp-ctl")
}

struct Release {
    version: String,
    /// (file name, download URL) for everything attached to the release.
    assets: Vec<(String, String)>,
}

fn latest_release() -> Result<Release> {
    let body = ureq::get(&format!(
        "https://api.github.com/repos/{REPO}/releases/latest"
    ))
    .header("User-Agent", "mcp-ctl")
    .header("Accept", "application/vnd.github+json")
    .call()
    .context("could not ask GitHub for the latest release")?
    .body_mut()
    .read_to_string()
    .context("could not read the GitHub response")?;

    let json: Value =
        serde_json::from_str(&body).context("GitHub returned something that is not JSON")?;
    let tag = json
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the latest release has no tag"))?;
    let assets = json
        .get("assets")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|asset| {
                    Some((
                        asset.get("name")?.as_str()?.to_string(),
                        asset.get("browser_download_url")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Release {
        version: tag.trim_start_matches('v').to_string(),
        assets,
    })
}

/// Is `candidate` a later version than `current`?
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(version: &str) -> Option<Vec<u64>> {
        version
            .trim_start_matches('v')
            .split('.')
            .map(|part| {
                part.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
            .collect()
    }
    match (parts(candidate), parts(current)) {
        (Some(a), Some(b)) => {
            for index in 0..a.len().max(b.len()) {
                let left = a.get(index).copied().unwrap_or(0);
                let right = b.get(index).copied().unwrap_or(0);
                if left != right {
                    return left > right;
                }
            }
            false
        }
        _ => candidate != current,
    }
}

/// The target triple of the running binary, matching the release asset names.
fn target_triple() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        (os, arch) => bail!("no release is built for {os} on {arch}"),
    }
}

fn install(release: &Release, exe: &Path) -> Result<()> {
    let triple = target_triple()?;
    let archive = format!("mcp-ctl-{}-{triple}.tar.gz", release.version);
    let url = asset(release, &archive)?;
    let checksum_url = asset(release, &format!("{archive}.sha256"))?;

    let bytes = download(&url)?;
    let expected = download(&checksum_url)?;
    verify(&bytes, &expected, &archive)?;
    let binary = extract(&bytes)?;
    replace(exe, &binary)
}

fn asset(release: &Release, name: &str) -> Result<String> {
    release
        .assets
        .iter()
        .find(|(asset, _)| asset == name)
        .map(|(_, url)| url.clone())
        .ok_or_else(|| anyhow!("release {} has no {name}", release.version))
}

fn download(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .header("User-Agent", "mcp-ctl")
        .call()
        .with_context(|| format!("could not download {url}"))?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {url}"))?;
    Ok(bytes)
}

/// Check the archive against the `.sha256` published beside it.
fn verify(bytes: &[u8], checksum: &[u8], archive: &str) -> Result<()> {
    let text = String::from_utf8_lossy(checksum);
    let expected = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("the checksum file for {archive} is empty"))?
        .to_lowercase();
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected {
        bail!("the checksum for {archive} does not match (expected {expected}, got {actual})");
    }
    Ok(())
}

/// Pull the binary out of the release tarball without touching the filesystem.
fn extract(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("could not read the archive")? {
        let mut entry = entry.context("could not read the archive")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().context("the archive has a bad path")?;
        if path.file_name().and_then(|name| name.to_str()) == Some("mcp-ctl") {
            let mut binary = Vec::new();
            entry
                .read_to_end(&mut binary)
                .context("could not read the binary from the archive")?;
            if binary.is_empty() {
                bail!("the archive contains an empty mcp-ctl");
            }
            return Ok(binary);
        }
    }
    bail!("the archive does not contain mcp-ctl")
}

/// Write beside the old binary and rename, so a failed update leaves a working
/// `mcp-ctl` behind rather than a truncated one.
fn replace(exe: &Path, binary: &[u8]) -> Result<()> {
    let staged = exe.with_extension("new");
    std::fs::write(&staged, binary)
        .with_context(|| format!("could not write {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("could not make {} executable", staged.display()))?;
    }
    std::fs::rename(&staged, exe)
        .with_context(|| format!("could not replace {}", exe.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_installer_directory_is_ours() {
        assert!(installer_owned(Path::new("/home/you/.local/bin/mcp-ctl")));
        assert!(!installer_owned(Path::new("/usr/bin/mcp-ctl")));
        assert!(!installer_owned(Path::new("/home/you/.cargo/bin/mcp-ctl")));
    }

    #[test]
    fn newer_versions_are_recognised() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
    }

    #[test]
    fn the_current_binary_has_a_release_asset() {
        assert!(!target_triple().unwrap().is_empty());
    }

    #[test]
    fn a_directory_named_mcp_ctl_is_not_the_binary() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_size(0);
        directory.set_mode(0o755);
        directory.set_cksum();
        builder
            .append_data(&mut directory, "mcp-ctl", std::io::empty())
            .unwrap();

        let mut file = tar::Header::new_gnu();
        file.set_size(4);
        file.set_mode(0o755);
        file.set_cksum();
        builder
            .append_data(&mut file, "mcp-ctl", &b"bin\0"[..])
            .unwrap();

        let tar = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        let archive = encoder.finish().unwrap();

        assert_eq!(extract(&archive).unwrap(), b"bin\0");
    }

    #[test]
    fn a_checksum_mismatch_is_refused() {
        let error = verify(b"archive", b"0000  file", "file.tar.gz").unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[test]
    fn a_matching_checksum_passes() {
        // sha256 of "archive"
        let digest = Sha256::digest(b"archive");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        verify(
            b"archive",
            format!("{hex}  file.tar.gz").as_bytes(),
            "file.tar.gz",
        )
        .expect("matching checksums pass");
    }
}
