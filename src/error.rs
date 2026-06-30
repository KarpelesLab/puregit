//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`], an alias for
//! `core::result::Result<T, Error>`. [`Error`] is `no_std`-friendly (it carries
//! only owned `alloc` data) and implements [`core::fmt::Display`]; the
//! `std::error::Error` impl is gated on the `std` feature.

use alloc::string::String;

/// A specialized [`Result`](core::result::Result) for puregit operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced anywhere in the crate.
///
/// Variants are intentionally coarse — each names a *layer* (parsing,
/// compression, the object database, the protocol, I/O) rather than every
/// possible cause, with a `String` detail for the specifics. This keeps the
/// surface small while still giving callers something to match on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A buffer did not parse as the git structure it was expected to be
    /// (a malformed object header, tree entry, index record, pkt-line, …).
    Parse(String),

    /// A zlib (RFC 1950) stream failed to inflate or deflate.
    Compression(String),

    /// An object id was not the expected length, not valid hex, or referred to
    /// a different hash algorithm than the repository uses.
    InvalidOid(String),

    /// The object database has no object with the requested id.
    NotFound(ObjectKindHint),

    /// An object was found but had a different type than the caller required
    /// (e.g. dereferencing a blob as a tree). Holds `(expected, actual)`.
    UnexpectedType {
        /// The type the caller required.
        expected: crate::object::ObjectType,
        /// The type actually stored.
        actual: crate::object::ObjectType,
    },

    /// A reference name was malformed or a ref operation failed
    /// (lock contention, non-fast-forward update, dangling symref, …).
    Reference(String),

    /// A packfile or pack index was corrupt, truncated, or used an
    /// unsupported version, or delta resolution failed.
    Pack(String),

    /// The smart-transport peer violated the protocol, advertised an
    /// unsupported capability set, or sent an `ERR` line.
    Protocol(String),

    /// The repository configuration was malformed or referenced an
    /// unsupported value.
    Config(String),

    /// An underlying I/O operation failed (filesystem via [`crate::vfs`], or a
    /// network transport). Carries a human-readable description; the original
    /// `std::io::Error` kind is preserved on `std` via [`Error::from`].
    Io(String),

    /// The caller asked for something this build does not support — a feature
    /// compiled out, an unimplemented protocol version, or a SHA-256 repository
    /// where only SHA-1 is wired up.
    Unsupported(String),
}

/// A hint about what kind of object id failed a [`Error::NotFound`] lookup,
/// for nicer error messages without forcing the lookup site to format an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectKindHint {
    /// Lookup of a specific object id (hex form).
    Object(String),
    /// Lookup of a named reference.
    Reference(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Compression(m) => write!(f, "compression error: {m}"),
            Error::InvalidOid(m) => write!(f, "invalid object id: {m}"),
            Error::NotFound(ObjectKindHint::Object(id)) => write!(f, "object not found: {id}"),
            Error::NotFound(ObjectKindHint::Reference(r)) => write!(f, "reference not found: {r}"),
            Error::UnexpectedType { expected, actual } => {
                write!(f, "expected a {expected} object, found a {actual}")
            }
            Error::Reference(m) => write!(f, "reference error: {m}"),
            Error::Pack(m) => write!(f, "packfile error: {m}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::Io(m) => write!(f, "io error: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        use alloc::string::ToString;
        Error::Io(e.to_string())
    }
}

impl From<compcol::Error> for Error {
    fn from(e: compcol::Error) -> Self {
        use alloc::format;
        Error::Compression(format!("{e:?}"))
    }
}
