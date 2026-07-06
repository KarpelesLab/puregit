//! Signature verification for signed commits and tags.
//!
//! Git can sign a commit or tag with SSH (the `gpg.format=ssh` mode): the signer
//! runs `ssh-keygen -Y sign` over the object's canonical bytes and stores the
//! resulting `SSHSIG` armor in the commit's `gpgsig` header (or at the end of a
//! tag). This module verifies such a signature — parsing the `SSHSIG` structure,
//! reconstructing the exact blob that was signed, and checking it with
//! [`purecrypto`]'s Ed25519 — so a caller can confirm an object was signed by a
//! given key.
//!
//! Ed25519 keys are supported (the overwhelmingly common SSH signing key today).
//! Other key types (`rsa-sha2-*`, ECDSA) parse but return
//! [`Error::Unsupported`]. PGP signatures are recognised but not verified here.
//!
//! The signed message for a commit is its bytes with the `gpgsig` header removed
//! ([`Commit::signed_payload`](crate::object::Commit::signed_payload)); for a tag
//! it is the bytes preceding the signature block.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use purecrypto::ec::ed25519::{Ed25519PublicKey, Ed25519Signature};
use purecrypto::hash::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// The SSH signature namespace git uses for commits and tags.
const GIT_NAMESPACE: &str = "git";

/// A successfully verified SSH signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSigner {
    /// The SSH key type, e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// The raw public key blob (for Ed25519, the 32-byte key).
    pub public_key: Vec<u8>,
}

impl SshSigner {
    /// The signer's public key as an OpenSSH authorized-keys line
    /// (`<type> <base64-of-the-full-key-blob>`), the form used in an
    /// `allowed_signers` file.
    pub fn openssh_line(&self) -> String {
        // The base64 covers the full SSH key blob (string keytype + key), which
        // we rebuild from the parsed parts.
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, self.key_type.as_bytes());
        write_ssh_string(&mut blob, &self.public_key);
        alloc::format!("{} {}", self.key_type, base64_encode(&blob))
    }
}

/// Which signing scheme an armor block uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// An `-----BEGIN SSH SIGNATURE-----` block.
    Ssh,
    /// An `-----BEGIN PGP SIGNATURE-----` block.
    Pgp,
    /// An unrecognised or absent signature.
    Unknown,
}

/// Classifies a signature armor block by its header line.
pub fn scheme_of(armor: &[u8]) -> SignatureScheme {
    let text = core::str::from_utf8(armor).unwrap_or("");
    if text.contains("BEGIN SSH SIGNATURE") {
        SignatureScheme::Ssh
    } else if text.contains("BEGIN PGP SIGNATURE") {
        SignatureScheme::Pgp
    } else {
        SignatureScheme::Unknown
    }
}

/// Verifies an SSH signature `armor` over `signed_message` in git's `"git"`
/// namespace, returning the signer on success.
///
/// This performs the full `SSHSIG` check: it hashes `signed_message` with the
/// signature's declared hash, rebuilds the `SSHSIG` signed blob, and verifies the
/// Ed25519 signature against the embedded public key. It does **not** decide
/// whether that key is *trusted* — the caller compares [`SshSigner`] against its
/// allowed-signers set.
pub fn verify_ssh(signed_message: &[u8], armor: &[u8]) -> Result<SshSigner> {
    let blob = dearmor_ssh_signature(armor)?;
    let sig = SshSig::parse(&blob)?;

    if sig.namespace != GIT_NAMESPACE {
        return Err(Error::Protocol(alloc::format!(
            "ssh signature: namespace is {:?}, expected \"git\"",
            sig.namespace
        )));
    }

    // The signed blob is: MAGIC, namespace, reserved, hash_algorithm, H(message).
    let message_hash = match sig.hash_algorithm.as_str() {
        "sha256" => Sha256::digest(signed_message).as_ref().to_vec(),
        "sha512" => Sha512::digest(signed_message).as_ref().to_vec(),
        other => {
            return Err(Error::Unsupported(alloc::format!(
                "ssh signature: unsupported hash {other:?}"
            )));
        }
    };
    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(b"SSHSIG");
    write_ssh_string(&mut to_verify, sig.namespace.as_bytes());
    write_ssh_string(&mut to_verify, b""); // reserved
    write_ssh_string(&mut to_verify, sig.hash_algorithm.as_bytes());
    write_ssh_string(&mut to_verify, &message_hash);

    if sig.key_type != "ssh-ed25519" {
        return Err(Error::Unsupported(alloc::format!(
            "ssh signature: unsupported key type {:?} (only ssh-ed25519)",
            sig.key_type
        )));
    }
    let key: [u8; 32] = sig
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Protocol("ssh signature: ed25519 key is not 32 bytes".into()))?;
    let signature: [u8; 64] =
        sig.signature.as_slice().try_into().map_err(|_| {
            Error::Protocol("ssh signature: ed25519 signature is not 64 bytes".into())
        })?;

    Ed25519PublicKey::from_bytes(key)
        .verify(&to_verify, &Ed25519Signature::from_bytes(signature))
        .map_err(|_| Error::Protocol("ssh signature: verification failed".into()))?;

    Ok(SshSigner {
        key_type: sig.key_type,
        public_key: sig.public_key,
    })
}

/// The parsed fields of an `SSHSIG` blob (the binary inside the armor).
struct SshSig {
    key_type: String,
    public_key: Vec<u8>,
    namespace: String,
    hash_algorithm: String,
    signature: Vec<u8>,
}

impl SshSig {
    /// Parses the binary `SSHSIG` structure (RFC-draft `PROTOCOL.sshsig`).
    fn parse(blob: &[u8]) -> Result<Self> {
        let mut r = SshReader::new(blob);
        let magic = r.take(6)?;
        if magic != b"SSHSIG" {
            return Err(Error::Protocol("ssh signature: bad magic".into()));
        }
        let version = r.u32()?;
        if version != 1 {
            return Err(Error::Protocol(alloc::format!(
                "ssh signature: unsupported version {version}"
            )));
        }
        let publickey = r.string()?;
        let namespace = r.string()?;
        let _reserved = r.string()?;
        let hash_algorithm = r.string()?;
        let signature = r.string()?;

        // The public-key blob is itself `string keytype, <key material>`; for
        // Ed25519 the material is one `string` holding the 32-byte key.
        let mut pk = SshReader::new(publickey);
        let key_type = String::from_utf8_lossy(pk.string()?).to_string();
        let public_key = pk.string()?.to_vec();

        // The signature blob is `string sigtype, string signature`.
        let mut sg = SshReader::new(signature);
        let _sig_type = sg.string()?;
        let signature = sg.string()?.to_vec();

        Ok(SshSig {
            key_type,
            public_key,
            namespace: String::from_utf8_lossy(namespace).to_string(),
            hash_algorithm: String::from_utf8_lossy(hash_algorithm).to_string(),
            signature,
        })
    }
}

/// Extracts and base64-decodes the body of an `-----BEGIN SSH SIGNATURE-----`
/// armor block into the raw `SSHSIG` bytes.
fn dearmor_ssh_signature(armor: &[u8]) -> Result<Vec<u8>> {
    let text = core::str::from_utf8(armor)
        .map_err(|_| Error::Protocol("ssh signature: not utf-8".into()))?;
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN SSH SIGNATURE-----" {
            inside = true;
        } else if line == "-----END SSH SIGNATURE-----" {
            inside = false;
        } else if inside {
            body.push_str(line);
        }
    }
    if body.is_empty() {
        return Err(Error::Protocol(
            "ssh signature: no armor block found".into(),
        ));
    }
    base64_decode(&body)
}

/// A cursor over SSH wire data (length-prefixed strings, big-endian integers).
struct SshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        SshReader { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| Error::Protocol("ssh signature: truncated".into()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `string`: a `u32` length followed by that many bytes.
    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// Appends an SSH `string` (u32 length prefix + bytes) to `out`.
fn write_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Standard base64 decoding (RFC 4648), ignoring embedded whitespace.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c).ok_or_else(|| Error::Protocol("ssh signature: bad base64".into()))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Standard base64 encoding (RFC 4648, padded), for [`SshSigner::openssh_line`].
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_detection() {
        assert_eq!(
            scheme_of(b"-----BEGIN SSH SIGNATURE-----\n..."),
            SignatureScheme::Ssh
        );
        assert_eq!(
            scheme_of(b"-----BEGIN PGP SIGNATURE-----\n..."),
            SignatureScheme::Pgp
        );
        assert_eq!(scheme_of(b"not a signature"), SignatureScheme::Unknown);
    }

    /// A real commit signed by `git commit -S` with `gpg.format=ssh` and an
    /// Ed25519 key (captured from git 2.51 + OpenSSH); verifying it exercises the
    /// whole path — `gpgsig` extraction, payload reconstruction, `SSHSIG`
    /// parsing, and Ed25519 — hermetically, with no external tools.
    #[test]
    fn verifies_a_real_git_ssh_signed_commit() {
        use crate::object::Commit;
        use crate::oid::HashAlgo;

        const RAW: &[u8] = include_bytes!("testdata/signed_commit_ssh_ed25519.bin");
        let commit = Commit::parse(HashAlgo::Sha1, RAW).unwrap();

        let armor = commit.signature().expect("commit is signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Ssh);

        let signer = verify_ssh(&commit.signed_payload(), &armor).expect("signature verifies");
        assert_eq!(signer.key_type, "ssh-ed25519");
        // The recovered key matches the signer's published OpenSSH public key.
        assert_eq!(
            signer.openssh_line(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFblPc+7+IChl5s1dQVCY4xKLyZU9fiMwjs9O/dEvVJH"
        );

        // Any change to the signed bytes must break verification.
        let mut tampered = commit.signed_payload();
        tampered.push(b'!');
        assert!(verify_ssh(&tampered, &armor).is_err());
    }

    #[test]
    fn base64_round_trips() {
        for v in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foobar"[..],
            &[0u8, 255, 128, 1, 2, 3][..],
        ] {
            assert_eq!(base64_decode(&base64_encode(v)).unwrap(), v);
        }
    }
}
