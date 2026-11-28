//! Release checksum lookup, SHA-256 verification, release signature policy
//! verification, and safe gzipped USTAR/PAX/GNU tar binary extraction.

use std::{
    cmp::Ordering,
    io::{self, Read},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::HEXLOWER;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::update::version::{compare_version, parse_version, release_base};

/// Maximum `checksums.txt` body size (1 MiB).
pub const MAX_CHECKSUMS_BODY: u64 = 1 << 20;

/// Maximum detached signature file size (64 KiB).
pub const MAX_SIGNATURE_BODY: u64 = 64 << 10;

/// Maximum upgrade archive download/upload size (128 MiB).
pub const MAX_UPGRADE_ARCHIVE: u64 = 128 << 20;

/// Maximum extracted upgrade binary size (256 MiB).
pub const MAX_UPGRADE_BINARY: u64 = 256 << 20;

/// First formal FerrumGate release that carries a release signature.
///
/// Any release version `>= FIRST_SIGNED_RELEASE` without a signature file is
/// rejected. Older versions fall back to SHA-256 verification with an unsigned
/// warning.
pub const FIRST_SIGNED_RELEASE: &str = "v0.1.0";

const MAX_TAR_META_BYTES: usize = 64 << 10;
const MAX_DECOMPRESSED_STREAM_BYTES: u64 = MAX_UPGRADE_BINARY + (16 << 20);
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Single key verification closure: returns `Ok(())` iff `signature` is a valid
/// signature over `payload`.
pub type KeyVerifyFn = Arc<dyn Fn(&[u8], &[u8]) -> Result<()> + Send + Sync>;

/// Injectable release-signature verifier supporting multiple trusted keys
/// (e.g., primary key + rotation key from WP-93).
#[derive(Clone)]
pub struct SignatureVerifier {
    keys: Vec<KeyVerifyFn>,
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self { keys: Vec::new() }
    }
}

impl SignatureVerifier {
    /// Creates a verifier backed by a single verification function.
    pub fn from_fn(f: impl Fn(&[u8], &[u8]) -> Result<()> + Send + Sync + 'static) -> Self {
        Self {
            keys: vec![Arc::new(f)],
        }
    }

    /// Creates a verifier that succeeds if any trusted key verifies the
    /// signature (primary key + rotation key).
    pub fn from_keys(keys: Vec<KeyVerifyFn>) -> Self {
        Self { keys }
    }

    /// Verifies `signature` over `payload` against every configured trusted key.
    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        ensure!(
            !self.keys.is_empty(),
            "no trusted release signing keys configured"
        );
        let mut last_err = None;
        for key in &self.keys {
            match key(payload, signature) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("release signature verification failed")))
    }
}

/// Returns `true` if release `tag` is required to be signed given
/// `first_signed_release`.
///
/// Fails closed (`true`) if `tag` cannot be parsed as a version.
pub fn release_requires_signature(tag: &str, first_signed_release: &str) -> bool {
    let first_signed = first_signed_release.trim();
    if first_signed.is_empty() {
        return false;
    }
    let Some(first) = parse_version(release_base(first_signed)) else {
        return true;
    };
    let Some(ver) = parse_version(release_base(tag)) else {
        return true;
    };
    compare_version(&ver, &first) != Ordering::Less
}

/// Applies the WP-94 release signature policy to `checksums`:
/// - When `signature` is `Some`, it MUST verify with a trusted key (regardless
///   of version); returns `Ok(false)` (`unsigned = false`).
/// - When `signature` is `None` and `tag >= first_signed_release`, rejects the
///   upgrade.
/// - When `signature` is `None` and `tag < first_signed_release`, allows the
///   upgrade with `Ok(true)` (`unsigned = true` warning).
pub fn verify_release_signature(
    tag: &str,
    first_signed_release: &str,
    checksums: &[u8],
    signature: Option<&[u8]>,
    verifier: &SignatureVerifier,
) -> Result<bool> {
    if let Some(sig) = signature {
        verifier
            .verify(checksums, sig)
            .context("release signature verification failed")?;
        return Ok(false);
    }
    if release_requires_signature(tag, first_signed_release) {
        bail!("release {tag} is missing required signature");
    }
    Ok(true)
}

/// Looks up the SHA-256 hex digest for `name` in a `sha256sum`-formatted file
/// (`<64-hex>  <filename>` or `<64-hex> *<filename>`).
pub fn checksum_for(sums: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(sums).ok()?;
    let target = name.trim().trim_start_matches("./");
    if target.is_empty() {
        return None;
    }
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Standard sha256sum format separates digest and filename by two spaces
        // or space + '*' (binary mode). Also tolerate single whitespace.
        let (digest, rest) = if let Some((d, r)) = line.split_once("  ") {
            (d, r)
        } else if let Some((d, r)) = line.split_once(" *") {
            (d, r)
        } else {
            let mut parts = line.splitn(2, char::is_whitespace);
            (parts.next()?, parts.next()?.trim_start())
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let file = rest.trim().trim_start_matches('*').trim_start_matches("./");
        if file == target {
            return Some(digest.to_ascii_lowercase());
        }
    }
    None
}

/// Computes the SHA-256 of `data` and compares it in constant time against
/// `expected_hex`.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<()> {
    let expected = expected_hex.trim().to_ascii_lowercase();
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid expected SHA-256 digest"
    );
    let actual = HEXLOWER.encode(&Sha256::digest(data));
    if bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        bail!(
            "SHA-256 checksum mismatch (downloaded archive may be tampered or incomplete): expected {expected}, got {actual}"
        );
    }
}

/// Extracts the FerrumGate executable from either a gzipped tar archive
/// (`.tar.gz`) or a raw binary payload.
///
/// Enforces a strict 256 MiB extracted binary limit and rejects path traversal
/// entries inside tar archives.
pub fn extract_binary(archive: &[u8]) -> Result<Vec<u8>> {
    ensure!(!archive.is_empty(), "upgrade payload is empty");
    if archive.len() >= 2 && archive[..2] == GZIP_MAGIC {
        extract_binary_from_tar_gz(archive)
    } else {
        ensure!(
            archive.len() as u64 <= MAX_UPGRADE_BINARY,
            "upgrade binary exceeds {} bytes",
            MAX_UPGRADE_BINARY
        );
        Ok(archive.to_vec())
    }
}

fn extract_binary_from_tar_gz(archive: &[u8]) -> Result<Vec<u8>> {
    let gz = GzDecoder::new(archive);
    let mut reader = LimitedReader::new(gz, MAX_DECOMPRESSED_STREAM_BYTES);

    let mut header = [0u8; 512];
    let mut next_long_name: Option<String> = None;
    let mut next_pax_path: Option<String> = None;
    let mut next_pax_size: Option<u64> = None;
    let mut fallback_candidate: Option<Vec<u8>> = None;

    loop {
        if !read_tar_block(&mut reader, &mut header)? {
            break;
        }
        if header.iter().all(|&b| b == 0) {
            // End-of-archive zero block.
            break;
        }
        verify_tar_checksum(&header)?;

        let typeflag = header[156];
        let header_size = parse_tar_size(&header[124..136])?;
        let size = next_pax_size.take().unwrap_or(header_size);
        let mode = parse_tar_octal(&header[100..108]).unwrap_or(0);
        let raw_name = next_pax_path
            .take()
            .or_else(|| next_long_name.take())
            .unwrap_or_else(|| parse_tar_name(&header));

        let padded_skip = tar_padding(size);

        match typeflag {
            // GNU LongName ('L')
            b'L' => {
                ensure!(
                    size <= MAX_TAR_META_BYTES as u64,
                    "tar long filename entry exceeds limit"
                );
                let mut buf = vec![0u8; size as usize];
                reader
                    .read_exact(&mut buf)
                    .context("read GNU longname payload")?;
                skip_exact(&mut reader, padded_skip)?;
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                let name = String::from_utf8(buf).context("tar longname is not valid UTF-8")?;
                next_long_name = Some(name);
            }
            // PAX extended header ('x')
            b'x' => {
                ensure!(
                    size <= MAX_TAR_META_BYTES as u64,
                    "tar PAX header exceeds limit"
                );
                let mut buf = vec![0u8; size as usize];
                reader.read_exact(&mut buf).context("read PAX header")?;
                skip_exact(&mut reader, padded_skip)?;
                let (pax_path, pax_size) = parse_pax_records(&buf)?;
                if pax_path.is_some() {
                    next_pax_path = pax_path;
                }
                if pax_size.is_some() {
                    next_pax_size = pax_size;
                }
            }
            // PAX global header ('g') or GNU LongLink ('K') -> ignore payload safely.
            b'g' | b'K' => {
                ensure!(
                    size <= MAX_TAR_META_BYTES as u64,
                    "tar metadata entry exceeds limit"
                );
                skip_exact(&mut reader, size + padded_skip)?;
            }
            // Regular file ('0' or NUL).
            b'0' | 0 => {
                let basename = validate_tar_path(&raw_name)?;
                ensure!(
                    size <= MAX_UPGRADE_BINARY,
                    "tar entry {raw_name:?} exceeds {} bytes",
                    MAX_UPGRADE_BINARY
                );

                if is_named_binary(basename) {
                    ensure!(size > 0, "binary entry {raw_name:?} in archive is empty");
                    let mut bin = vec![0u8; size as usize];
                    reader
                        .read_exact(&mut bin)
                        .context("read binary entry from tar.gz")?;
                    return Ok(bin);
                }

                if fallback_candidate.is_none()
                    && (mode & 0o111) != 0
                    && !is_non_binary_doc(basename)
                    && size > 0
                {
                    let mut bin = vec![0u8; size as usize];
                    reader
                        .read_exact(&mut bin)
                        .context("read executable entry from tar.gz")?;
                    skip_exact(&mut reader, padded_skip)?;
                    fallback_candidate = Some(bin);
                } else {
                    skip_exact(&mut reader, size + padded_skip)?;
                }
            }
            // Directories / symlinks / other entries: still validate path traversal and skip.
            _ => {
                let _ = validate_tar_path(&raw_name)?;
                skip_exact(&mut reader, size + padded_skip)?;
            }
        }
    }

    fallback_candidate.ok_or_else(|| anyhow!("no executable binary found in archive"))
}

struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0u8; 1];
            let n = self.inner.read(&mut probe)?;
            if n == 0 {
                return Ok(0);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed archive exceeds size limit",
            ));
        }
        let max_read = (buf.len() as u64).min(self.remaining) as usize;
        let n = self.inner.read(&mut buf[..max_read])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn read_tar_block<R: Read>(reader: &mut R, block: &mut [u8; 512]) -> Result<bool> {
    let mut filled = 0usize;
    while filled < 512 {
        let n = reader
            .read(&mut block[filled..])
            .context("read tar header block")?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            bail!("unexpected EOF while reading tar header");
        }
        filled += n;
    }
    Ok(true)
}

fn skip_exact<R: Read>(reader: &mut R, mut remaining: u64) -> Result<()> {
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let to_read = (remaining as usize).min(scratch.len());
        let n = reader
            .read(&mut scratch[..to_read])
            .context("skip tar entry payload")?;
        ensure!(n > 0, "unexpected EOF in tar archive");
        remaining -= n as u64;
    }
    Ok(())
}

fn tar_padding(size: u64) -> u64 {
    let rem = size % 512;
    if rem == 0 { 0 } else { 512 - rem }
}

fn verify_tar_checksum(header: &[u8; 512]) -> Result<()> {
    let expected = parse_tar_octal(&header[148..156]).context("invalid tar header checksum")?;
    let mut unsigned_sum: u64 = 0;
    let mut signed_sum: i64 = 0;
    for (idx, &byte) in header.iter().enumerate() {
        let effective = if (148..156).contains(&idx) {
            b' '
        } else {
            byte
        };
        unsigned_sum += effective as u64;
        signed_sum += (effective as i8) as i64;
    }
    ensure!(
        expected == unsigned_sum || (signed_sum >= 0 && expected == signed_sum as u64),
        "corrupted tar header checksum"
    );
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let s = std::str::from_utf8(&field[..end])
        .context("non-UTF-8 tar octal field")?
        .trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).with_context(|| format!("invalid octal value {s:?}"))
}

fn parse_tar_size(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        // GNU base-256 encoding: clear top indicator bit and verify no overflow.
        ensure!(
            field[0] == 0x80 && field[1..4].iter().all(|&b| b == 0),
            "unsupported or oversized base-256 tar size"
        );
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&field[4..12]);
        Ok(u64::from_be_bytes(bytes))
    } else {
        parse_tar_octal(field)
    }
}

fn parse_tar_name(header: &[u8; 512]) -> String {
    let read_cstr = |slice: &[u8]| {
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).into_owned()
    };
    let name = read_cstr(&header[0..100]);
    let is_ustar = &header[257..262] == b"ustar";
    if is_ustar {
        let prefix = read_cstr(&header[345..500]);
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

fn parse_pax_records(data: &[u8]) -> Result<(Option<String>, Option<u64>)> {
    let mut path = None;
    let mut size = None;
    let mut cursor = data;
    while !cursor.is_empty() {
        let Some(space) = cursor.iter().position(|&b| b == b' ') else {
            break;
        };
        let len_str = std::str::from_utf8(&cursor[..space]).context("invalid PAX record length")?;
        let record_len: usize = len_str.parse().context("parse PAX record length")?;
        ensure!(
            record_len > space + 1 && record_len <= cursor.len(),
            "truncated PAX record"
        );
        let record = &cursor[space + 1..record_len];
        cursor = &cursor[record_len..];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            let key = &record[..eq];
            let val = &record[eq + 1..];
            if key == b"path" {
                path = Some(String::from_utf8(val.to_vec()).context("PAX path is not UTF-8")?);
            } else if key == b"size" {
                let s = std::str::from_utf8(val).context("PAX size is not UTF-8")?;
                size = Some(s.parse::<u64>().context("invalid PAX size")?);
            }
        }
    }
    Ok((path, size))
}

fn validate_tar_path(raw: &str) -> Result<&str> {
    ensure!(
        !raw.is_empty() && !raw.contains('\0') && !raw.contains('\\'),
        "invalid tar entry path {raw:?}"
    );
    ensure!(
        !raw.starts_with('/'),
        "tar entry path must not be absolute: {raw:?}"
    );
    let mut last_component = "";
    for segment in raw.split('/') {
        ensure!(
            segment != "..",
            "tar entry contains path traversal: {raw:?}"
        );
        if !segment.is_empty() && segment != "." {
            last_component = segment;
        }
    }
    Ok(last_component)
}

fn is_named_binary(basename: &str) -> bool {
    matches!(
        basename.to_ascii_lowercase().as_str(),
        "fgate" | "ferrumgate" | "gately"
    )
}

fn is_non_binary_doc(basename: &str) -> bool {
    let lower = basename.to_ascii_lowercase();
    [
        ".md", ".txt", ".json", ".sig", ".minisig", ".asc", ".yml", ".yaml", ".toml", ".sh",
        ".license",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
        || matches!(lower.as_str(), "readme" | "license" | "checksums")
}

/// Builds a valid USTAR `.tar.gz` archive containing the given `(name, mode, data)` entries.
#[cfg(test)]
pub(crate) fn build_test_tar_gz(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    for &(name, mode, data) in entries {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        write!(&mut header[100..107], "{mode:07o}").unwrap();
        write!(&mut header[108..115], "{:07o}", 0u32).unwrap();
        write!(&mut header[116..123], "{:07o}", 0u32).unwrap();
        write!(&mut header[124..135], "{:011o}", data.len()).unwrap();
        write!(&mut header[136..147], "{:011o}", 0u64).unwrap();
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write!(&mut header[148..154], "{checksum:06o}").unwrap();
        header[154] = 0;
        header[155] = b' ';

        enc.write_all(&header).unwrap();
        enc.write_all(data).unwrap();
        let pad = tar_padding(data.len() as u64) as usize;
        if pad > 0 {
            enc.write_all(&vec![0u8; pad]).unwrap();
        }
    }
    enc.write_all(&[0u8; 1024]).unwrap();
    enc.finish().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_for_parses_sha256sum_format() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sums = format!(
            "# comment\n{digest}  ferrumgate_v0.6.4_linux_amd64.tar.gz\n\
             ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789 *./gately_v0.6.4_linux_arm64.tar.gz\n"
        );
        assert_eq!(
            checksum_for(sums.as_bytes(), "ferrumgate_v0.6.4_linux_amd64.tar.gz").as_deref(),
            Some(digest)
        );
        assert_eq!(
            checksum_for(sums.as_bytes(), "gately_v0.6.4_linux_arm64.tar.gz").as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert!(checksum_for(sums.as_bytes(), "missing.tar.gz").is_none());
    }

    #[test]
    fn extract_binary_handles_tar_gz_raw_and_rejections() {
        // Tar.gz with README + named binary.
        let tar_gz = build_test_tar_gz(&[
            ("README.md", 0o644, b"docs"),
            ("bin/fgate", 0o755, b"ELF-BINARY-PAYLOAD"),
        ]);
        assert_eq!(extract_binary(&tar_gz).unwrap(), b"ELF-BINARY-PAYLOAD");

        // Raw binary passthrough.
        assert_eq!(extract_binary(b"\x7fELFraw").unwrap(), b"\x7fELFraw");

        // Tar.gz with no binary rejected.
        let docs_only = build_test_tar_gz(&[("README.md", 0o644, b"docs")]);
        assert!(extract_binary(&docs_only).is_err());

        // Path traversal rejected.
        let traversal = build_test_tar_gz(&[("../evil", 0o755, b"bad")]);
        assert!(extract_binary(&traversal).is_err());

        // Oversized entry rejected via crafted tar header claiming 300 MiB.
        let mut header = [0u8; 512];
        header[..5].copy_from_slice(b"fgate");
        use std::io::Write;
        write!(&mut header[100..107], "{:07o}", 0o755u32).unwrap();
        write!(&mut header[124..135], "{:011o}", (300u64 << 20)).unwrap();
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        let csum: u32 = header.iter().map(|&b| b as u32).sum();
        write!(&mut header[148..154], "{csum:06o}").unwrap();
        header[154] = 0;
        header[155] = b' ';
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&header).unwrap();
        let oversized = enc.finish().unwrap();
        assert!(extract_binary(&oversized).is_err());
    }
}
