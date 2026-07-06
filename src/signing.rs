//! SSH signing and verification for commits and tags.
//!
//! Git can sign a commit or tag with SSH (the `gpg.format=ssh` mode): the signer
//! runs `ssh-keygen -Y sign` over the object's canonical bytes and stores the
//! resulting `SSHSIG` armor in the commit's `gpgsig` header (or at the end of a
//! tag). This module both **verifies** such a signature ([`verify_ssh`]) — parsing
//! the `SSHSIG` structure, reconstructing the exact blob that was signed, and
//! checking it with [`purecrypto`]'s Ed25519 — and **produces** one
//! ([`sign_ssh_ed25519`] / [`sign_commit_ssh`]), so a caller can confirm *or*
//! create a signature.
//!
//! Ed25519 keys are supported (the overwhelmingly common SSH signing key today).
//! Other SSH key types (`rsa-sha2-*`, ECDSA) parse but return
//! [`Error::Unsupported`]. OpenPGP **EdDSA**, **RSA**, and **ECDSA** (NIST
//! P-256/384/521) signatures are also verified ([`verify_pgp`]) — covering the
//! common GnuPG-signed commit whatever the key type — and an OpenPGP EdDSA
//! signature can be **produced** ([`sign_pgp_ed25519`] / [`sign_commit_pgp_ed25519`]),
//! yielding a `gpgsig` block real `git verify-commit` accepts.
//!
//! The signed message for a commit is its bytes with the `gpgsig` header removed
//! ([`Commit::signed_payload`](crate::object::Commit::signed_payload)); for a tag
//! it is the bytes preceding the signature block.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use purecrypto::ec::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
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

/// Signs `message` with an Ed25519 key (its 32-byte seed) in git's `"git"`
/// namespace, producing the armored `SSHSIG` block a `gpgsig` header carries.
///
/// This is the inverse of [`verify_ssh`]: it hashes `message` with SHA-512 (as
/// `git`/`ssh-keygen` do by default), signs the wrapped `SSHSIG` blob, and wraps
/// the result in `-----BEGIN SSH SIGNATURE-----` armor. The produced signature
/// verifies with `verify_ssh`, real `ssh-keygen -Y verify`, and `git`.
pub fn sign_ssh_ed25519(message: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    const HASH_ALGORITHM: &[u8] = b"sha512";
    let key = Ed25519PrivateKey::from_bytes(*seed);
    let public = key.public_key().to_bytes();

    // The signed blob: MAGIC, namespace, reserved, hash_algorithm, H(message).
    let message_hash = Sha512::digest(message).as_ref().to_vec();
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(b"SSHSIG");
    write_ssh_string(&mut to_sign, GIT_NAMESPACE.as_bytes());
    write_ssh_string(&mut to_sign, b"");
    write_ssh_string(&mut to_sign, HASH_ALGORITHM);
    write_ssh_string(&mut to_sign, &message_hash);
    let signature = key.sign(&to_sign).to_bytes();

    // The public-key blob (`string keytype, string key`).
    let mut public_blob = Vec::new();
    write_ssh_string(&mut public_blob, b"ssh-ed25519");
    write_ssh_string(&mut public_blob, &public);
    // The signature blob (`string sigtype, string signature`).
    let mut signature_blob = Vec::new();
    write_ssh_string(&mut signature_blob, b"ssh-ed25519");
    write_ssh_string(&mut signature_blob, &signature);

    // The SSHSIG structure.
    let mut sshsig = Vec::new();
    sshsig.extend_from_slice(b"SSHSIG");
    sshsig.extend_from_slice(&1u32.to_be_bytes()); // version
    write_ssh_string(&mut sshsig, &public_blob);
    write_ssh_string(&mut sshsig, GIT_NAMESPACE.as_bytes());
    write_ssh_string(&mut sshsig, b""); // reserved
    write_ssh_string(&mut sshsig, HASH_ALGORITHM);
    write_ssh_string(&mut sshsig, &signature_blob);

    // Armor: base64 wrapped at 70 columns between the BEGIN/END markers.
    let body = base64_encode(&sshsig);
    let mut armor = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in body.as_bytes().chunks(70) {
        armor.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        armor.push('\n');
    }
    armor.push_str("-----END SSH SIGNATURE-----\n");
    armor.into_bytes()
}

/// Returns a copy of `commit` signed with an Ed25519 key (its 32-byte seed):
/// its serialization is signed and the armor stored in a `gpgsig` header, exactly
/// as `git commit -S` does with `gpg.format=ssh`.
///
/// The commit must be unsigned (no existing `gpgsig`). The result round-trips
/// through [`Commit::signature`](crate::object::Commit::signature) /
/// [`signed_payload`](crate::object::Commit::signed_payload) and verifies with
/// [`verify_ssh`], `ssh-keygen -Y verify`, and `git verify-commit`.
pub fn sign_commit_ssh(commit: &crate::object::Commit, seed: &[u8; 32]) -> crate::object::Commit {
    let armor = sign_ssh_ed25519(&commit.serialize(), seed);

    // Append a `gpgsig` header: the first armor line after `gpgsig `, each
    // following line indented by one space (git's multi-line header form).
    let mut extra = commit.extra_headers.clone();
    for (i, line) in armor
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        extra.extend_from_slice(if i == 0 { b"gpgsig " } else { b" " });
        extra.extend_from_slice(line);
        extra.push(b'\n');
    }

    crate::object::Commit {
        extra_headers: extra,
        ..commit.clone()
    }
}

/// Signs `message` as an OpenPGP **EdDSA (Ed25519)** binary-document signature,
/// producing an armored `-----BEGIN PGP SIGNATURE-----` block.
///
/// `seed` is the 32-byte Ed25519 secret; `created` is the signature's creation
/// time (Unix seconds, hashed into a type-2 subpacket — the crate is sans-clock,
/// so the caller supplies it). `issuer` is the optional 8-byte OpenPGP key id,
/// embedded as an unhashed issuer subpacket so a verifier (`gpg`, `git
/// verify-commit`) can locate the key in its keyring. The digest is SHA-256.
///
/// This is the inverse of the EdDSA branch of [`verify_pgp`]: the produced armor
/// round-trips through it, and — with the matching `issuer` key id — verifies
/// with real `gpg --verify` and `git verify-commit`.
pub fn sign_pgp_ed25519(
    message: &[u8],
    seed: &[u8; 32],
    created: u32,
    issuer: Option<[u8; 8]>,
) -> Vec<u8> {
    let key = Ed25519PrivateKey::from_bytes(*seed);

    // The hashed area: version(1) sig_type(1=binary is 0x00) pubkey_algo(22)
    // hash_algo(8=SHA-256), then a 2-byte length and the hashed subpackets. The
    // only hashed subpacket is the signature creation time (type 2).
    let mut hashed_sub = Vec::new();
    hashed_sub.push(5); // subpacket length: 1 type byte + 4 data bytes
    hashed_sub.push(2); // type 2: signature creation time
    hashed_sub.extend_from_slice(&created.to_be_bytes());

    // version 4, signature type 0 (binary document), pubkey algo 22 (EdDSA),
    // hash algo 8 (SHA-256), then the hashed-subpacket length and bytes.
    let mut hashed = alloc::vec![0x04u8, 0x00, 22, 8];
    hashed.extend_from_slice(&(hashed_sub.len() as u16).to_be_bytes());
    hashed.extend_from_slice(&hashed_sub);

    // The signed data covers `message || hashed || v4-trailer`.
    let mut data = Vec::with_capacity(message.len() + hashed.len() + 6);
    data.extend_from_slice(message);
    data.extend_from_slice(&hashed);
    data.push(0x04);
    data.push(0xff);
    data.extend_from_slice(&(hashed.len() as u32).to_be_bytes());
    let digest = Sha256::digest(&data);
    let digest = digest.as_ref();

    // OpenPGP EdDSA signs the digest with Ed25519; the value is the two MPIs R, S.
    let signature = key.sign(digest).to_bytes();

    // The unhashed area: an issuer key-id subpacket (type 16), if supplied.
    let mut unhashed_sub = Vec::new();
    if let Some(key_id) = issuer {
        unhashed_sub.push(9); // 1 type byte + 8 key-id bytes
        unhashed_sub.push(16); // type 16: issuer key id
        unhashed_sub.extend_from_slice(&key_id);
    }

    let mut body = hashed;
    body.extend_from_slice(&(unhashed_sub.len() as u16).to_be_bytes());
    body.extend_from_slice(&unhashed_sub);
    body.push(digest[0]); // left 16 bits of the digest (a quick reject hint)
    body.push(digest[1]);
    encode_mpi(&mut body, &signature[..32]); // R
    encode_mpi(&mut body, &signature[32..]); // S

    // Frame it as a new-format signature packet (tag 2) and armor it.
    let mut packet = Vec::with_capacity(body.len() + 6);
    packet.push(0xc2); // 0x80 | 0x40 (new format) | 2 (signature tag)
    push_pgp_new_length(&mut packet, body.len());
    packet.extend_from_slice(&body);
    armor_pgp(&packet)
}

/// Returns a copy of `commit` signed with an OpenPGP EdDSA (Ed25519) key,
/// storing the armor in a `gpgsig` header exactly as `git commit -S` does with
/// GnuPG.
///
/// See [`sign_pgp_ed25519`] for the parameters. The commit must be unsigned. The
/// result round-trips through [`Commit::signature`](crate::object::Commit::signature)
/// / [`signed_payload`](crate::object::Commit::signed_payload), verifies with
/// [`verify_pgp`], and — with the matching `issuer` key id in a keyring — passes
/// real `git verify-commit`.
pub fn sign_commit_pgp_ed25519(
    commit: &crate::object::Commit,
    seed: &[u8; 32],
    created: u32,
    issuer: Option<[u8; 8]>,
) -> crate::object::Commit {
    let armor = sign_pgp_ed25519(&commit.serialize(), seed, created, issuer);

    // Append a `gpgsig` header. Unlike SSH armor, a PGP block has a blank line
    // after the header, which git stores as an empty continuation line — so we
    // keep interior blank lines (only the trailing one from the final newline is
    // dropped).
    let mut lines: Vec<&[u8]> = armor.split(|&b| b == b'\n').collect();
    if lines.last() == Some(&&b""[..]) {
        lines.pop();
    }
    let mut extra = commit.extra_headers.clone();
    for (i, line) in lines.iter().enumerate() {
        extra.extend_from_slice(if i == 0 { b"gpgsig " } else { b" " });
        extra.extend_from_slice(line);
        extra.push(b'\n');
    }

    crate::object::Commit {
        extra_headers: extra,
        ..commit.clone()
    }
}

/// Appends `bytes` as an OpenPGP MPI (2-byte bit length + minimal big-endian
/// value, leading zero bytes stripped) to `out`.
fn encode_mpi(out: &mut Vec<u8>, bytes: &[u8]) {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[first_nonzero..];
    if value.is_empty() {
        out.extend_from_slice(&[0, 0]); // a zero MPI has bit length 0
        return;
    }
    let bits = (value.len() - 1) * 8 + (8 - value[0].leading_zeros() as usize);
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Appends a new-format OpenPGP packet length (RFC 4880 §4.2.2) for `len` bytes.
fn push_pgp_new_length(out: &mut Vec<u8>, len: usize) {
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push(((l >> 8) + 192) as u8);
        out.push((l & 0xff) as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

/// Wraps a raw OpenPGP `packet` in `-----BEGIN PGP SIGNATURE-----` armor with the
/// RFC 4880 CRC-24 checksum line, as `gpg` emits.
fn armor_pgp(packet: &[u8]) -> Vec<u8> {
    let mut out = String::from("-----BEGIN PGP SIGNATURE-----\n\n");
    let b64 = base64_encode(packet);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    let crc = crc24(packet);
    let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
    out.push('=');
    out.push_str(&base64_encode(&crc_bytes));
    out.push('\n');
    out.push_str("-----END PGP SIGNATURE-----\n");
    out.into_bytes()
}

/// The RFC 4880 CRC-24 over `data` (init `0xB704CE`, polynomial `0x1864CFB`).
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00b7_04ce;
    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

/// A NIST prime curve an OpenPGP ECDSA key may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpCurve {
    /// NIST P-256 (`1.2.840.10045.3.1.7`).
    P256,
    /// NIST P-384 (`1.3.132.0.34`).
    P384,
    /// NIST P-521 (`1.3.132.0.35`).
    P521,
}

impl PgpCurve {
    /// The OpenPGP curve OID (the bytes following the length octet) for this curve.
    pub fn oid(self) -> &'static [u8] {
        match self {
            PgpCurve::P256 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            PgpCurve::P384 => &[0x2b, 0x81, 0x04, 0x00, 0x22],
            PgpCurve::P521 => &[0x2b, 0x81, 0x04, 0x00, 0x23],
        }
    }

    /// Maps a raw OpenPGP curve OID to the matching curve, if recognised.
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        [PgpCurve::P256, PgpCurve::P384, PgpCurve::P521]
            .into_iter()
            .find(|c| c.oid() == oid)
    }
}

/// A signer's OpenPGP public key, supplied by the caller (puregit manages no
/// keyring).
pub enum PgpKey<'a> {
    /// An EdDSA (Ed25519) key: the 32-byte public point.
    Ed25519(&'a [u8; 32]),
    /// An RSA key: the modulus `n` and public exponent `e`, big-endian.
    Rsa {
        /// The RSA modulus (big-endian).
        n: &'a [u8],
        /// The RSA public exponent (big-endian).
        e: &'a [u8],
    },
    /// An ECDSA key on a NIST prime curve: the SEC1-encoded public point
    /// (`0x04 || x || y`).
    Ecdsa {
        /// The curve the key lives on.
        curve: PgpCurve,
        /// The uncompressed SEC1 point (`0x04 || x || y`).
        point: &'a [u8],
    },
}

/// Verifies an OpenPGP **EdDSA (Ed25519)** signature — a thin wrapper over
/// [`verify_pgp`] with a [`PgpKey::Ed25519`] key.
pub fn verify_pgp_eddsa(signed_message: &[u8], armor: &[u8], public_key: &[u8; 32]) -> Result<()> {
    verify_pgp(signed_message, armor, PgpKey::Ed25519(public_key))
}

/// Verifies an OpenPGP signature `armor` over `signed_message` against a caller-
/// supplied public `key`.
///
/// Handles the common GnuPG commit/tag cases — a v4 signature packet with
/// **EdDSA** (Ed25519), **RSA** (PKCS#1 v1.5), or **ECDSA** (NIST P-256/384/521)
/// and a SHA-256/512 digest — by de-armoring, parsing the packet and its MPIs,
/// rebuilding the signed digest (`message || hashed-fields || v4-trailer`), and
/// checking it. The `key` variant must match the signature's algorithm.
pub fn verify_pgp(signed_message: &[u8], armor: &[u8], key: PgpKey<'_>) -> Result<()> {
    let packet = dearmor_pgp(armor)?;
    let sig = PgpSignature::parse(&packet)?;

    // The signed data covers `message || hashed-fields || v4-trailer`.
    let mut data = Vec::with_capacity(signed_message.len() + sig.hashed.len() + 6);
    data.extend_from_slice(signed_message);
    data.extend_from_slice(&sig.hashed);
    data.push(0x04);
    data.push(0xff);
    data.extend_from_slice(&(sig.hashed.len() as u32).to_be_bytes());

    match (&sig.value, key) {
        (PgpSigValue::EdDsa { r, s }, PgpKey::Ed25519(public)) => {
            // OpenPGP EdDSA signs the digest with Ed25519; the signature is R||S.
            let digest = pgp_digest(sig.hash_algo, &data)?;
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(r);
            signature[32..].copy_from_slice(s);
            Ed25519PublicKey::from_bytes(*public)
                .verify(&digest, &Ed25519Signature::from_bytes(signature))
                .map_err(|_| Error::Protocol("pgp signature: verification failed".into()))
        }
        (PgpSigValue::Rsa(sig_mpi), PgpKey::Rsa { n, e }) => {
            verify_rsa(sig.hash_algo, &data, sig_mpi, n, e)
        }
        (PgpSigValue::Ecdsa { r, s }, PgpKey::Ecdsa { curve, point }) => {
            let digest = pgp_digest(sig.hash_algo, &data)?;
            verify_ecdsa(curve, point, r, s, &digest)
        }
        _ => Err(Error::Unsupported(
            "pgp signature: key type does not match the signature algorithm".into(),
        )),
    }
}

/// Hashes `data` with the OpenPGP hash-algorithm id (8 = SHA-256, 10 = SHA-512).
fn pgp_digest(hash_algo: u8, data: &[u8]) -> Result<Vec<u8>> {
    match hash_algo {
        8 => Ok(Sha256::digest(data).as_ref().to_vec()),
        10 => Ok(Sha512::digest(data).as_ref().to_vec()),
        other => Err(Error::Unsupported(alloc::format!(
            "pgp signature: unsupported hash algorithm {other}"
        ))),
    }
}

/// Verifies an RSA PKCS#1 v1.5 OpenPGP signature over `data` (hash `hash_algo`)
/// against the key `(n, e)`. The signature MPI is left-padded to the modulus size.
fn verify_rsa(hash_algo: u8, data: &[u8], sig_mpi: &[u8], n: &[u8], e: &[u8]) -> Result<()> {
    use purecrypto::bignum::BoxedUint;
    use purecrypto::rsa::BoxedRsaPublicKey;

    let key = BoxedRsaPublicKey::new(BoxedUint::from_be_bytes(n), BoxedUint::from_be_bytes(e));
    // The RSA signature is a modulus-sized big-endian integer; MPIs drop leading
    // zeros, so left-pad it to the modulus length.
    if sig_mpi.len() > n.len() {
        return Err(Error::Protocol(
            "pgp signature: RSA signature too long".into(),
        ));
    }
    let mut sig = alloc::vec![0u8; n.len()];
    sig[n.len() - sig_mpi.len()..].copy_from_slice(sig_mpi);

    let result = match hash_algo {
        8 => key.verify_pkcs1v15::<Sha256>(data, &sig),
        10 => key.verify_pkcs1v15::<Sha512>(data, &sig),
        other => {
            return Err(Error::Unsupported(alloc::format!(
                "pgp signature: unsupported hash algorithm {other}"
            )));
        }
    };
    result.map_err(|_| Error::Protocol("pgp signature: verification failed".into()))
}

/// Verifies an ECDSA OpenPGP signature `(r, s)` over the message digest
/// `prehash` against the SEC1 `point` on `curve`. The signature MPIs are the raw
/// big-endian `r` and `s` scalars.
fn verify_ecdsa(curve: PgpCurve, point: &[u8], r: &[u8], s: &[u8], prehash: &[u8]) -> Result<()> {
    use purecrypto::bignum::BoxedUint;
    use purecrypto::ec::{BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId};

    let curve_id = match curve {
        PgpCurve::P256 => CurveId::P256,
        PgpCurve::P384 => CurveId::P384,
        PgpCurve::P521 => CurveId::P521,
    };
    let key = BoxedEcdsaPublicKey::from_sec1(curve_id, point)
        .map_err(|_| Error::Protocol("pgp signature: invalid ECDSA public point".into()))?;
    let sig = BoxedEcdsaSignature::from_components(
        BoxedUint::from_be_bytes(r),
        BoxedUint::from_be_bytes(s),
    );
    key.verify_prehash(prehash, &sig)
        .map_err(|_| Error::Protocol("pgp signature: verification failed".into()))
}

/// The signature value of a parsed OpenPGP signature packet.
enum PgpSigValue {
    /// EdDSA `(R, S)`, each left-padded to 32 bytes.
    EdDsa {
        /// The `R` component.
        r: [u8; 32],
        /// The `S` component.
        s: [u8; 32],
    },
    /// The RSA signature MPI value (big-endian).
    Rsa(Vec<u8>),
    /// ECDSA `(r, s)`, each the raw big-endian MPI value.
    Ecdsa {
        /// The `r` component (big-endian).
        r: Vec<u8>,
        /// The `s` component (big-endian).
        s: Vec<u8>,
    },
}

/// A parsed OpenPGP v4 signature packet.
struct PgpSignature {
    hash_algo: u8,
    /// The hashed prefix (`version…end of hashed subpackets`) fed into the digest.
    hashed: Vec<u8>,
    /// The signature value, by algorithm.
    value: PgpSigValue,
}

impl PgpSignature {
    fn parse(packet: &[u8]) -> Result<Self> {
        let body = pgp_signature_body(packet)?;
        if body.first() != Some(&4) {
            return Err(Error::Unsupported(
                "pgp signature: only version 4 packets are supported".into(),
            ));
        }
        // version(1) sig_type(1) pubkey_algo(1) hash_algo(1)
        let pubkey_algo = *body.get(2).ok_or_else(pgp_trunc)?;
        let hash_algo = *body.get(3).ok_or_else(pgp_trunc)?;

        // hashed subpackets: 2-byte length, then that many bytes.
        let hashed_len = u16::from_be_bytes([
            *body.get(4).ok_or_else(pgp_trunc)?,
            *body.get(5).ok_or_else(pgp_trunc)?,
        ]) as usize;
        let hashed_end = 6 + hashed_len;
        if body.len() < hashed_end {
            return Err(pgp_trunc());
        }
        // The digest hashes the fields from `version` through the hashed subpackets.
        let hashed = body[..hashed_end].to_vec();

        // Skip unhashed subpackets (2-byte length + bytes) and the 2-byte
        // left-16 hash preview, then read the signature MPI(s).
        let unhashed_len = u16::from_be_bytes([
            *body.get(hashed_end).ok_or_else(pgp_trunc)?,
            *body.get(hashed_end + 1).ok_or_else(pgp_trunc)?,
        ]) as usize;
        let mut pos = hashed_end + 2 + unhashed_len + 2; // + left16

        let value = match pubkey_algo {
            // EdDSA: two MPIs (R, S).
            22 => {
                let r = read_mpi_padded(body, &mut pos)?;
                let s = read_mpi_padded(body, &mut pos)?;
                PgpSigValue::EdDsa { r, s }
            }
            // RSA (sign-only, or sign+encrypt): one MPI.
            1 | 3 => PgpSigValue::Rsa(read_mpi(body, &mut pos)?),
            // ECDSA: two MPIs (r, s).
            19 => {
                let r = read_mpi(body, &mut pos)?;
                let s = read_mpi(body, &mut pos)?;
                PgpSigValue::Ecdsa { r, s }
            }
            other => {
                return Err(Error::Unsupported(alloc::format!(
                    "pgp signature: pubkey algorithm {other} is not EdDSA, RSA, or ECDSA"
                )));
            }
        };

        Ok(PgpSignature {
            hash_algo,
            hashed,
            value,
        })
    }
}

/// Reads an OpenPGP MPI (2-byte bit length + big-endian value) as raw bytes.
fn read_mpi(data: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let bits = u16::from_be_bytes([
        *data.get(*pos).ok_or_else(pgp_trunc)?,
        *data.get(*pos + 1).ok_or_else(pgp_trunc)?,
    ]) as usize;
    let bytes = bits.div_ceil(8);
    let start = *pos + 2;
    let end = start + bytes;
    let out = data.get(start..end).ok_or_else(pgp_trunc)?.to_vec();
    *pos = end;
    Ok(out)
}

/// The truncated-packet error.
fn pgp_trunc() -> Error {
    Error::Protocol("pgp signature: truncated packet".into())
}

/// Reads an OpenPGP MPI (2-byte bit length + big-endian value) and left-pads it
/// into a 32-byte array (an Ed25519 `R`/`S` component).
fn read_mpi_padded(data: &[u8], pos: &mut usize) -> Result<[u8; 32]> {
    let bits = u16::from_be_bytes([
        *data.get(*pos).ok_or_else(pgp_trunc)?,
        *data.get(*pos + 1).ok_or_else(pgp_trunc)?,
    ]) as usize;
    let bytes = bits.div_ceil(8);
    let start = *pos + 2;
    let end = start + bytes;
    if bytes > 32 || data.len() < end {
        return Err(Error::Protocol("pgp signature: bad EdDSA MPI".into()));
    }
    let mut out = [0u8; 32];
    out[32 - bytes..].copy_from_slice(&data[start..end]);
    *pos = end;
    Ok(out)
}

/// Extracts the body of the OpenPGP signature packet (tag 2), handling both the
/// old and new packet-header framings.
fn pgp_signature_body(packet: &[u8]) -> Result<&[u8]> {
    let tag_byte = *packet.first().ok_or_else(pgp_trunc)?;
    if tag_byte & 0x80 == 0 {
        return Err(Error::Protocol("pgp signature: bad packet header".into()));
    }
    let (tag, body_start, body_len) = if tag_byte & 0x40 != 0 {
        // New format: tag in the low 6 bits, then a length octet.
        let (len, used) = pgp_new_length(&packet[1..])?;
        (tag_byte & 0x3f, 1 + used, len)
    } else {
        // Old format: tag in bits 5..2, length type in the low 2 bits.
        let tag = (tag_byte >> 2) & 0x0f;
        let (len, used) = pgp_old_length(&packet[1..], tag_byte & 0x03)?;
        (tag, 1 + used, len)
    };
    if tag != 2 {
        return Err(Error::Protocol(
            "pgp signature: not a signature packet".into(),
        ));
    }
    packet
        .get(body_start..body_start + body_len)
        .ok_or_else(pgp_trunc)
}

/// Decodes an old-format packet length for the given 2-bit length type.
fn pgp_old_length(data: &[u8], length_type: u8) -> Result<(usize, usize)> {
    match length_type {
        0 => Ok((*data.first().ok_or_else(pgp_trunc)? as usize, 1)),
        1 => Ok((
            u16::from_be_bytes([
                *data.first().ok_or_else(pgp_trunc)?,
                *data.get(1).ok_or_else(pgp_trunc)?,
            ]) as usize,
            2,
        )),
        2 => {
            let b: [u8; 4] = data.get(..4).ok_or_else(pgp_trunc)?.try_into().unwrap();
            Ok((u32::from_be_bytes(b) as usize, 4))
        }
        _ => Err(Error::Unsupported(
            "pgp signature: indeterminate packet length".into(),
        )),
    }
}

/// Decodes a new-format packet length (RFC 4880 §4.2.2), rejecting partial
/// lengths (a signature packet is never chunked).
fn pgp_new_length(data: &[u8]) -> Result<(usize, usize)> {
    let first = *data.first().ok_or_else(pgp_trunc)?;
    match first {
        0..=191 => Ok((first as usize, 1)),
        192..=223 => {
            let second = *data.get(1).ok_or_else(pgp_trunc)?;
            Ok((((first as usize - 192) << 8) + second as usize + 192, 2))
        }
        255 => {
            let b: [u8; 4] = data.get(1..5).ok_or_else(pgp_trunc)?.try_into().unwrap();
            Ok((u32::from_be_bytes(b) as usize, 5))
        }
        _ => Err(Error::Unsupported(
            "pgp signature: partial packet length".into(),
        )),
    }
}

/// Extracts and base64-decodes an OpenPGP `-----BEGIN PGP SIGNATURE-----` armor
/// block into the raw packet bytes, dropping the blank lines and the `=CRC`
/// checksum line.
fn dearmor_pgp(armor: &[u8]) -> Result<Vec<u8>> {
    let text = core::str::from_utf8(armor)
        .map_err(|_| Error::Protocol("pgp signature: not utf-8".into()))?;
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN PGP SIGNATURE-----" {
            inside = true;
        } else if line == "-----END PGP SIGNATURE-----" {
            break;
        } else if inside && !line.is_empty() && !line.starts_with('=') {
            // A `=`-prefixed line is the CRC-24 checksum, not packet data.
            body.push_str(line);
        }
    }
    if body.is_empty() {
        return Err(Error::Protocol("pgp signature: no armor block".into()));
    }
    base64_decode(&body)
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
    fn sign_then_verify_round_trips() {
        // A fixed seed → deterministic key; sign a message and verify it back.
        let seed = [7u8; 32];
        let armor = sign_ssh_ed25519(b"the signed payload\n", &seed);
        assert_eq!(scheme_of(&armor), SignatureScheme::Ssh);

        let signer = verify_ssh(b"the signed payload\n", &armor).expect("self-verify");
        assert_eq!(signer.key_type, "ssh-ed25519");
        // The recovered key matches the signing key's public half.
        let expected = Ed25519PrivateKey::from_bytes(seed).public_key().to_bytes();
        assert_eq!(signer.public_key, expected);

        // A different message does not verify against the same signature.
        assert!(verify_ssh(b"tampered\n", &armor).is_err());
    }

    #[test]
    fn signs_a_commit_that_round_trips() {
        use crate::object::{Commit, Signature};
        use crate::oid::{HashAlgo, ObjectId};

        let sig = Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 1_700_000_000,
            tz: b"+0000".to_vec(),
        };
        let tree = ObjectId::from_hex(HashAlgo::Sha1, &"a".repeat(40)).unwrap();
        let commit = Commit {
            tree,
            parents: alloc::vec![],
            author: sig.clone(),
            committer: sig,
            extra_headers: Vec::new(),
            message: b"a signed commit\n".to_vec(),
        };

        let signed = sign_commit_ssh(&commit, &[9u8; 32]);
        // The commit now carries a signature, and the signed payload is the
        // original (unsigned) serialization.
        let armor = signed.signature().expect("signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Ssh);
        assert_eq!(signed.signed_payload(), commit.serialize());
        // The signature verifies against that payload.
        verify_ssh(&signed.signed_payload(), &armor).expect("verifies");
        // The signed commit still parses back to itself byte-for-byte.
        assert_eq!(
            Commit::parse(HashAlgo::Sha1, &signed.serialize()).unwrap(),
            signed
        );
    }

    /// Signs a commit with OpenPGP EdDSA and verifies it back through
    /// [`verify_pgp`] — the inverse of the real-gpg verification tests, run
    /// hermetically. (The same signature is separately confirmed to pass real
    /// `git verify-commit`; the seed/key here come from that GnuPG key.)
    #[test]
    fn signs_a_pgp_commit_that_round_trips() {
        use crate::object::{Commit, Signature};
        use crate::oid::{HashAlgo, ObjectId};

        // The seed and public point of a real GnuPG Ed25519 key; the produced
        // signature verifies with `git verify-commit` under this key.
        let seed: [u8; 32] =
            hex::decode("136d658c45677821f9de4520fe01de4f36d111f949608f730f2ff1f7bd73e57d")
                .unwrap()
                .try_into()
                .unwrap();
        let public: [u8; 32] =
            hex::decode("a8ab936072899271104ac18612341183f7e6e4cc2ec1a895a904bae833d8cbdb")
                .unwrap()
                .try_into()
                .unwrap();
        let key_id: [u8; 8] = hex::decode("c28d29664944fd96").unwrap().try_into().unwrap();

        let sig = Signature {
            name: b"T".to_vec(),
            email: b"t@e".to_vec(),
            time: 1_700_000_000,
            tz: b"+0000".to_vec(),
        };
        let tree = ObjectId::from_hex(HashAlgo::Sha1, &"b".repeat(40)).unwrap();
        let commit = Commit {
            tree,
            parents: alloc::vec![],
            author: sig.clone(),
            committer: sig,
            extra_headers: Vec::new(),
            message: b"a pgp-signed commit\n".to_vec(),
        };

        let signed = sign_commit_pgp_ed25519(&commit, &seed, 1_783_400_000, Some(key_id));
        let armor = signed.signature().expect("signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Pgp);
        // The signed payload is the original (unsigned) serialization.
        assert_eq!(signed.signed_payload(), commit.serialize());
        // It verifies against the signer's public key…
        verify_pgp(&signed.signed_payload(), &armor, PgpKey::Ed25519(&public)).expect("verifies");
        // …but not against a tampered payload or the wrong key.
        let mut tampered = signed.signed_payload();
        tampered.push(b'!');
        assert!(verify_pgp(&tampered, &armor, PgpKey::Ed25519(&public)).is_err());
        assert!(
            verify_pgp(
                &signed.signed_payload(),
                &armor,
                PgpKey::Ed25519(&[0u8; 32])
            )
            .is_err()
        );
        // The signed commit still parses back to itself byte-for-byte.
        assert_eq!(
            Commit::parse(HashAlgo::Sha1, &signed.serialize()).unwrap(),
            signed
        );
    }

    /// A real commit signed by `git commit -S` with a GnuPG Ed25519 (EdDSA) key
    /// (captured from git 2.51 + GnuPG 2.4). Verifying it exercises the whole PGP
    /// path — armor de-armoring, OpenPGP packet + MPI parsing, and the v4 digest
    /// construction — hermetically, with no external tools.
    #[test]
    fn verifies_a_real_gpg_ed25519_signed_commit() {
        use crate::object::Commit;
        use crate::oid::HashAlgo;

        const RAW: &[u8] = include_bytes!("testdata/signed_commit_pgp_ed25519.bin");
        const PUB: &[u8; 32] = include_bytes!("testdata/signed_commit_pgp_ed25519.pub");
        let commit = Commit::parse(HashAlgo::Sha1, RAW).unwrap();

        let armor = commit.signature().expect("commit is PGP-signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Pgp);

        verify_pgp_eddsa(&commit.signed_payload(), &armor, PUB).expect("signature verifies");

        // Any change to the signed bytes breaks verification.
        let mut tampered = commit.signed_payload();
        tampered.push(b'!');
        assert!(verify_pgp_eddsa(&tampered, &armor, PUB).is_err());
        // A wrong key is rejected too.
        assert!(verify_pgp_eddsa(&commit.signed_payload(), &armor, &[0u8; 32]).is_err());
    }

    /// A real commit signed by `git commit -S` with a GnuPG RSA-2048 key.
    /// Verifying it exercises the RSA branch (MPI parse + PKCS#1 v1.5) against a
    /// committed fixture (the signed commit and the key's `n`/`e`).
    #[test]
    fn verifies_a_real_gpg_rsa_signed_commit() {
        use crate::object::Commit;
        use crate::oid::HashAlgo;

        const RAW: &[u8] = include_bytes!("testdata/signed_commit_pgp_rsa.bin");
        const N: &[u8] = include_bytes!("testdata/signed_commit_pgp_rsa_n.bin");
        const E: &[u8] = include_bytes!("testdata/signed_commit_pgp_rsa_e.bin");
        let commit = Commit::parse(HashAlgo::Sha1, RAW).unwrap();

        let armor = commit.signature().expect("commit is PGP-signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Pgp);

        verify_pgp(&commit.signed_payload(), &armor, PgpKey::Rsa { n: N, e: E }).expect("verifies");

        // A tampered payload is rejected.
        let mut tampered = commit.signed_payload();
        tampered.push(b'!');
        assert!(verify_pgp(&tampered, &armor, PgpKey::Rsa { n: N, e: E }).is_err());
    }

    /// A real commit signed by `git commit -S` with a GnuPG ECDSA NIST P-256
    /// key. Verifying it exercises the ECDSA branch (two-MPI parse + SEC1 point +
    /// `verify_prehash`) against a committed fixture (the signed commit and the
    /// key's SEC1 public point).
    #[test]
    fn verifies_a_real_gpg_ecdsa_p256_signed_commit() {
        use crate::object::Commit;
        use crate::oid::HashAlgo;

        const RAW: &[u8] = include_bytes!("testdata/signed_commit_pgp_ecdsa_p256.bin");
        const POINT: &[u8] = include_bytes!("testdata/signed_commit_pgp_ecdsa_p256_point.bin");
        let commit = Commit::parse(HashAlgo::Sha1, RAW).unwrap();

        let armor = commit.signature().expect("commit is PGP-signed");
        assert_eq!(scheme_of(&armor), SignatureScheme::Pgp);

        let key = PgpKey::Ecdsa {
            curve: PgpCurve::P256,
            point: POINT,
        };
        verify_pgp(&commit.signed_payload(), &armor, key).expect("verifies");

        // A tampered payload is rejected.
        let mut tampered = commit.signed_payload();
        tampered.push(b'!');
        let key = PgpKey::Ecdsa {
            curve: PgpCurve::P256,
            point: POINT,
        };
        assert!(verify_pgp(&tampered, &armor, key).is_err());
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
