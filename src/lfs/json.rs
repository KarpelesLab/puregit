//! A minimal JSON reader/writer for the LFS batch API.
//!
//! The LFS transfer protocol exchanges small, well-shaped JSON documents. Rather
//! than pull in a serialization framework (and to keep the no-C / minimal-deps
//! guarantee), this is a compact, dependency-free recursive-descent parser plus
//! a tiny string escaper — enough for the batch request/response shapes in
//! `batch`. It is `no_std` (operates on `&str` / `String`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number (LFS sizes fit in `f64`/`u64`; stored as `f64`).
    Num(f64),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object (insertion-ordered key/value pairs).
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Parses a complete JSON document.
    pub fn parse(input: &str) -> Result<Json> {
        let mut p = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(Error::Parse("json: trailing data".into()));
        }
        Ok(v)
    }

    /// For an object, the value under `key`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The array elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// The value as a `u64`, if this is a non-negative integer number.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            // Integrality check without `f64::fract` (which is std-only): a
            // non-negative value that round-trips through `u64` is an integer.
            Json::Num(n) if *n >= 0.0 && *n == (*n as u64) as f64 => Some(*n as u64),
            _ => None,
        }
    }
}

/// Escapes a string into a JSON string literal (including the surrounding
/// quotes).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&alloc::format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Json> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => Err(Error::Parse("json: unexpected token".into())),
        }
    }

    fn object(&mut self) -> Result<Json> {
        self.pos += 1; // '{'
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(Error::Parse("json: expected ':'".into()));
            }
            self.pos += 1;
            let val = self.value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(Error::Parse("json: expected ',' or '}'".into())),
            }
        }
    }

    fn array(&mut self) -> Result<Json> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let val = self.value()?;
            items.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(Error::Parse("json: expected ',' or ']'".into())),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        if self.peek() != Some(b'"') {
            return Err(Error::Parse("json: expected string".into()));
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self
                .peek()
                .ok_or_else(|| Error::Parse("json: unterminated string".into()))?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self
                        .peek()
                        .ok_or_else(|| Error::Parse("json: bad escape".into()))?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'u' => {
                            let cp = self.hex4()?;
                            out.push(char::from_u32(cp as u32).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(Error::Parse("json: bad escape".into())),
                    }
                }
                // UTF-8 continuation bytes pass through; we rebuild via bytes.
                _ => {
                    // Collect this byte and any UTF-8 continuation bytes.
                    let start = self.pos - 1;
                    let mut end = self.pos;
                    while let Some(&c) = self.bytes.get(end) {
                        if c & 0xC0 == 0x80 {
                            end += 1;
                        } else {
                            break;
                        }
                    }
                    if end > self.pos {
                        self.pos = end;
                    }
                    out.push_str(
                        core::str::from_utf8(&self.bytes[start..end])
                            .map_err(|_| Error::Parse("json: bad utf-8 in string".into()))?,
                    );
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16> {
        let mut v = 0u16;
        for _ in 0..4 {
            let b = self
                .peek()
                .ok_or_else(|| Error::Parse("json: short \\u escape".into()))?;
            self.pos += 1;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(Error::Parse("json: bad \\u hex".into())),
            };
            v = (v << 4) | d as u16;
        }
        Ok(v)
    }

    fn boolean(&mut self) -> Result<Json> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err(Error::Parse("json: invalid literal".into()))
        }
    }

    fn null(&mut self) -> Result<Json> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err(Error::Parse("json: invalid literal".into()))
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = core::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| Error::Parse("json: bad number".into()))?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| Error::Parse("json: bad number".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lfs_batch_response() {
        let src = r#"{
            "transfer": "basic",
            "objects": [
                {
                    "oid": "abc123",
                    "size": 5000,
                    "actions": {
                        "download": {
                            "href": "https://cdn.example.com/abc123",
                            "header": { "Authorization": "Bearer xyz" }
                        }
                    }
                }
            ]
        }"#;
        let v = Json::parse(src).unwrap();
        let objs = v.get("objects").unwrap().as_array().unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].get("oid").unwrap().as_str(), Some("abc123"));
        assert_eq!(objs[0].get("size").unwrap().as_u64(), Some(5000));
        let href = objs[0]
            .get("actions")
            .unwrap()
            .get("download")
            .unwrap()
            .get("href")
            .unwrap()
            .as_str();
        assert_eq!(href, Some("https://cdn.example.com/abc123"));
    }

    #[test]
    fn escapes_strings() {
        assert_eq!(escape("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn parses_scalars_and_errors() {
        assert_eq!(Json::parse("true").unwrap(), Json::Bool(true));
        assert_eq!(Json::parse("null").unwrap(), Json::Null);
        assert_eq!(Json::parse("-12").unwrap().as_u64(), None);
        assert_eq!(Json::parse("12").unwrap().as_u64(), Some(12));
        assert!(Json::parse("{bad}").is_err());
        assert!(Json::parse("[1,2").is_err());
    }
}
