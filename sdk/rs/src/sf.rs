//! HTTP Structured Field Values (RFC 8941): Signature-Input, Signature,
//! Signature-Agent, component identifiers, and fields covered with sf or key.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

/// A bare item. A decimal is held in thousandths, so serializing it never
/// depends on floating point.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Bare {
    Int(i64),
    Dec(i64),
    Str(String),
    Tok(String),
    Bin(Vec<u8>),
    Bool(bool),
}

/// Parameters in order; keys are unique.
pub(crate) type Params = Vec<(String, Bare)>;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Item {
    pub bare: Bare,
    pub params: Params,
}

/// A list or dictionary member: an item, or an inner list with its parameters.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Member {
    Item(Item),
    Inner(Vec<Item>, Params),
}

/// Dictionary members in order; keys are unique (a repeated key keeps its
/// first position and its last value).
pub(crate) type Dictionary = Vec<(String, Member)>;

pub(crate) fn param<'a>(ps: &'a Params, key: &str) -> Option<&'a Bare> {
    ps.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub(crate) fn member<'a>(d: &'a Dictionary, key: &str) -> Option<&'a Member> {
    d.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Set key in an ordered pair list; true if it was already there.
fn set<V>(pairs: &mut Vec<(String, V)>, key: String, v: V) -> bool {
    if let Some(e) = pairs.iter_mut().find(|(k, _)| *k == key) {
        e.1 = v;
        return true;
    }
    pairs.push((key, v));
    false
}

// --- parsing (RFC 8941 §4.2) ---

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Result<Self, String> {
        if !s.is_ascii() {
            return Err("structured field is not ASCII".into());
        }
        let mut p = Parser {
            s: s.as_bytes(),
            i: 0,
        };
        p.skip(b" ");
        Ok(p)
    }
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }
    fn peek(&self) -> u8 {
        self.s[self.i]
    }
    fn skip(&mut self, chars: &[u8]) {
        while !self.eof() && chars.contains(&self.peek()) {
            self.i += 1;
        }
    }
    fn end(&mut self) -> Result<(), String> {
        self.skip(b" ");
        if self.eof() {
            Ok(())
        } else {
            Err(format!(
                "unexpected {:?} at {}",
                self.peek() as char,
                self.i
            ))
        }
    }
    /// Moves past the comma between members; true at the end.
    fn next(&mut self) -> Result<bool, String> {
        self.skip(b" \t");
        if self.eof() {
            return Ok(true);
        }
        if self.peek() != b',' {
            return Err(format!("expected a comma at {}", self.i));
        }
        self.i += 1;
        self.skip(b" \t");
        if self.eof() {
            return Err("trailing comma".into());
        }
        Ok(false)
    }
    fn member(&mut self) -> Result<Member, String> {
        if !self.eof() && self.peek() == b'(' {
            return self.inner_list();
        }
        Ok(Member::Item(self.item()?))
    }
    fn inner_list(&mut self) -> Result<Member, String> {
        self.i += 1;
        let mut items = Vec::new();
        while !self.eof() {
            self.skip(b" ");
            if self.eof() {
                break;
            }
            if self.peek() == b')' {
                self.i += 1;
                return Ok(Member::Inner(items, self.params()?));
            }
            items.push(self.item()?);
            if !self.eof() && self.peek() != b' ' && self.peek() != b')' {
                return Err(format!("expected a space or ) at {}", self.i));
            }
        }
        Err("unterminated inner list".into())
    }
    fn item(&mut self) -> Result<Item, String> {
        let bare = self.bare()?;
        Ok(Item {
            bare,
            params: self.params()?,
        })
    }
    fn params(&mut self) -> Result<Params, String> {
        let mut ps = Params::new();
        while !self.eof() && self.peek() == b';' {
            self.i += 1;
            self.skip(b" ");
            let key = self.key()?;
            let mut v = Bare::Bool(true);
            if !self.eof() && self.peek() == b'=' {
                self.i += 1;
                v = self.bare()?;
            }
            set(&mut ps, key, v);
        }
        Ok(ps)
    }
    fn key(&mut self) -> Result<String, String> {
        if self.eof() || !(self.peek().is_ascii_lowercase() || self.peek() == b'*') {
            return Err(format!("expected a key at {}", self.i));
        }
        let start = self.i;
        while !self.eof() {
            let c = self.peek();
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c)) {
                break;
            }
            self.i += 1;
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }
    fn bare(&mut self) -> Result<Bare, String> {
        if self.eof() {
            return Err("expected an item".into());
        }
        let c = self.peek();
        if c == b'-' || c.is_ascii_digit() {
            return self.number();
        }
        if c == b'"' {
            return self.string();
        }
        if c == b'*' || c.is_ascii_alphabetic() {
            return Ok(self.token());
        }
        if c == b':' {
            return self.bytes();
        }
        if c == b'?' {
            if let Some(&b) = self.s.get(self.i + 1) {
                if b == b'0' || b == b'1' {
                    self.i += 2;
                    return Ok(Bare::Bool(b == b'1'));
                }
            }
            return Err(format!("bad boolean at {}", self.i));
        }
        Err(format!("unexpected {:?} at {}", c as char, self.i))
    }
    fn number(&mut self) -> Result<Bare, String> {
        let neg = self.peek() == b'-';
        if neg {
            self.i += 1;
        }
        if self.eof() || !self.peek().is_ascii_digit() {
            return Err(format!("expected a digit at {}", self.i));
        }
        let start = self.i;
        let mut dot: Option<usize> = None;
        while !self.eof() {
            let c = self.peek();
            if c.is_ascii_digit() {
                self.i += 1;
            } else if c == b'.' && dot.is_none() {
                if self.i - start > 12 {
                    return Err("decimal has too many integer digits".into());
                }
                dot = Some(self.i);
                self.i += 1;
            } else {
                break;
            }
            if dot.is_none() && self.i - start > 15 {
                return Err("integer has too many digits".into());
            }
            if dot.is_some() && self.i - start > 16 {
                return Err("decimal has too many digits".into());
            }
        }
        let num = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("0");
        let sign = if neg { -1 } else { 1 };
        match dot {
            None => Ok(Bare::Int(
                sign * num.parse::<i64>().map_err(|e| e.to_string())?,
            )),
            Some(d) => {
                let (whole, frac) = (&num[..d - start], &num[d - start + 1..]);
                if frac.is_empty() || frac.len() > 3 {
                    return Err("decimal needs 1 to 3 fractional digits".into());
                }
                let w: i64 = whole.parse().map_err(|_| "bad decimal")?;
                let f: i64 = format!("{frac}00")[..3]
                    .parse()
                    .map_err(|_| "bad decimal")?;
                Ok(Bare::Dec(sign * (w * 1000 + f)))
            }
        }
    }
    fn string(&mut self) -> Result<Bare, String> {
        self.i += 1;
        let mut out = String::new();
        while !self.eof() {
            let c = self.peek();
            self.i += 1;
            match c {
                b'\\' => {
                    if self.eof() || (self.peek() != b'"' && self.peek() != b'\\') {
                        return Err("bad escape in string".into());
                    }
                    out.push(self.peek() as char);
                    self.i += 1;
                }
                b'"' => return Ok(Bare::Str(out)),
                c if c < 0x20 || c == 0x7f => return Err("control character in string".into()),
                c => out.push(c as char),
            }
        }
        Err("unterminated string".into())
    }
    fn token(&mut self) -> Bare {
        let start = self.i;
        self.i += 1;
        while !self.eof() && (is_tchar(self.peek()) || self.peek() == b':' || self.peek() == b'/') {
            self.i += 1;
        }
        Bare::Tok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }
    fn bytes(&mut self) -> Result<Bare, String> {
        self.i += 1;
        let rest = &self.s[self.i..];
        let end = rest
            .iter()
            .position(|&c| c == b':')
            .ok_or("unterminated byte sequence")?;
        let content = &rest[..end];
        self.i += end + 1;
        if !content
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
        {
            return Err("bad base64 in byte sequence".into());
        }
        let trimmed: Vec<u8> = content.iter().copied().take_while(|&c| c != b'=').collect();
        STANDARD_NO_PAD
            .decode(trimmed)
            .map(Bare::Bin)
            .map_err(|_| "bad base64 in byte sequence".into())
    }
}

pub(crate) fn parse_item(s: &str) -> Result<Item, String> {
    let mut p = Parser::new(s)?;
    let it = p.item()?;
    p.end()?;
    Ok(it)
}

pub(crate) fn parse_list(s: &str) -> Result<Vec<Member>, String> {
    let mut p = Parser::new(s)?;
    let mut out = Vec::new();
    while !p.eof() {
        out.push(p.member()?);
        if p.next()? {
            break;
        }
    }
    Ok(out)
}

/// Parse a dictionary; also return the keys that occurred more than once.
pub(crate) fn parse_dictionary(s: &str) -> Result<(Dictionary, Vec<String>), String> {
    let mut p = Parser::new(s)?;
    let mut d = Dictionary::new();
    let mut dups = Vec::new();
    while !p.eof() {
        let key = p.key()?;
        let m = if !p.eof() && p.peek() == b'=' {
            p.i += 1;
            p.member()?
        } else {
            Member::Item(Item {
                bare: Bare::Bool(true),
                params: p.params()?,
            })
        };
        if set(&mut d, key.clone(), m) {
            dups.push(key);
        }
        if p.next()? {
            break;
        }
    }
    Ok((d, dups))
}

// --- serializing (RFC 8941 §4.1) ---

pub(crate) fn valid_key(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_lowercase() || b[0] == b'*')
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c))
}

pub(crate) fn valid_string(s: &str) -> bool {
    s.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

impl Bare {
    pub(crate) fn ser(&self) -> String {
        match self {
            Bare::Int(n) => n.to_string(),
            Bare::Dec(n) => {
                let a = n.unsigned_abs();
                let frac = format!("{:03}", a % 1000);
                let frac = frac.trim_end_matches('0');
                let frac = if frac.is_empty() { "0" } else { frac };
                format!("{}{}.{}", if *n < 0 { "-" } else { "" }, a / 1000, frac)
            }
            Bare::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            Bare::Tok(s) => s.clone(),
            Bare::Bin(b) => format!(":{}:", STANDARD.encode(b)),
            Bare::Bool(b) => if *b { "?1" } else { "?0" }.to_string(),
        }
    }
}

pub(crate) fn ser_params(ps: &Params) -> String {
    ps.iter()
        .map(|(k, v)| match v {
            Bare::Bool(true) => format!(";{k}"),
            v => format!(";{k}={}", v.ser()),
        })
        .collect()
}

impl Item {
    pub(crate) fn ser(&self) -> String {
        self.bare.ser() + &ser_params(&self.params)
    }
}

impl Member {
    pub(crate) fn ser(&self) -> String {
        match self {
            Member::Item(it) => it.ser(),
            Member::Inner(items, ps) => {
                let inner: Vec<String> = items.iter().map(Item::ser).collect();
                format!("({}){}", inner.join(" "), ser_params(ps))
            }
        }
    }
}

pub(crate) fn ser_list(l: &[Member]) -> String {
    l.iter().map(Member::ser).collect::<Vec<_>>().join(", ")
}

pub(crate) fn ser_dictionary(d: &Dictionary) -> String {
    d.iter()
        .map(|(k, m)| match m {
            Member::Item(Item {
                bare: Bare::Bool(true),
                params,
            }) => format!("{k}{}", ser_params(params)),
            m => format!("{k}={}", m.ser()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_field_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/http-message-signatures.json"
        );
        let Ok(text) = std::fs::read_to_string(path) else {
            return; // the vectors live in the messh repo
        };
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        for c in doc["structured_fields"].as_array().unwrap() {
            let (name, input) = (c["name"].as_str().unwrap(), c["input"].as_str().unwrap());
            let got = match c["type"].as_str().unwrap() {
                "dictionary" => parse_dictionary(input).map(|(d, _)| ser_dictionary(&d)),
                "list" => parse_list(input).map(|l| ser_list(&l)),
                _ => parse_item(input).map(|it| it.ser()),
            };
            if c["error"].as_bool().unwrap_or(false) {
                assert!(got.is_err(), "{name}: parsed {got:?}, want an error");
            } else {
                assert_eq!(
                    got.as_deref(),
                    Ok(c["canonical"].as_str().unwrap()),
                    "{name}"
                );
            }
        }
    }
}
