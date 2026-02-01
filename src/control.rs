/// Utilities for parsing Debian control files (control fields).
/// See <https://www.debian.org/doc/debian-policy/ch-controlfields.html> for the
/// official specification.
///
/// This parser focuses on machine-readable package metadata (for example,
/// binary package descriptions and Packages index files). It does not
/// interpret Debian-style comments and is not a full implementation of the
/// Debian policy — it is intended for parsing and extracting fields rather
/// than preserving formatting or comments when serializing.
use {
    crate::packages::Packages,
    serde::{Deserialize, Serialize},
    std::{borrow::Cow, sync::Arc},
};

/// Represents parsing error
#[derive(Debug, Clone)]
pub struct ParseError {
    msg: Cow<'static, str>,
}

impl std::error::Error for ParseError {}

impl From<&'static str> for ParseError {
    fn from(msg: &'static str) -> Self {
        Self { msg: msg.into() }
    }
}

impl From<String> for ParseError {
    fn from(msg: String) -> Self {
        Self { msg: msg.into() }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.msg, f)
    }
}

impl From<ParseError> for std::io::Error {
    fn from(err: ParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.msg.into_owned())
    }
}

/// Represents an immutable field in the Debian Control File.
/// Internally, ControlField holds references to a slice of
/// parsed block.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlField<'a> {
    name: &'a str,
    value: &'a str,
}

impl std::fmt::Display for ControlField<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.as_bytes().iter().next() == Some(&b'\n') {
            writeln!(f, "{}:{}", self.name, self.value)
        } else {
            writeln!(f, "{}: {}", &self.name, &self.value)
        }
    }
}

/// Represents the Debian Control File mutable field.
#[derive(Debug, Clone, PartialEq)]
pub struct MutableControlField<'a> {
    name: Cow<'a, str>,
    value: Cow<'a, str>,
}

impl std::fmt::Display for MutableControlField<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.as_bytes().iter().next() == Some(&b'\n') {
            writeln!(f, "{}:{}", self.name, self.value)
        } else {
            writeln!(f, "{}: {}", &self.name, &self.value)
        }
    }
}

impl<'a> MutableControlField<'a> {
    /// Sets the field value
    pub fn set<S: Into<Cow<'a, str>>>(&mut self, value: S) {
        self.value = value.into()
    }
}

impl<'a> From<ControlField<'a>> for MutableControlField<'a> {
    fn from(field: ControlField<'a>) -> Self {
        Self {
            name: field.name.into(),
            value: field.value.into(),
        }
    }
}

impl<'a> From<&ControlField<'a>> for MutableControlField<'a> {
    fn from(field: &ControlField<'a>) -> Self {
        Self {
            name: field.name.into(),
            value: field.value.into(),
        }
    }
}

/// Represents the single immutable Debian Control Stanza (a.k.a. Paragraph)
#[derive(Debug, Clone, PartialEq)]
pub struct ControlStanza<'a> {
    src: &'a str,
    fields: Vec<ControlField<'a>>,
}

impl std::fmt::Display for ControlStanza<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for field in &self.fields {
            write!(f, "{}", field)?;
        }
        Ok(())
    }
}

impl<'a> ControlStanza<'a> {
    /// Parses a string into a ControlStanza, ensuring that the entire `src` is fully parsed.
    pub fn parse(src: &'a str) -> Result<Self, ParseError> {
        let fields =
            ControlParser::new(src).collect::<Result<Vec<ControlField<'a>>, ParseError>>()?;
        if fields.is_empty() {
            Err("Empty control stanza".into())
        } else {
            Ok(ControlStanza { src, fields })
        }
    }
    /// Returns the value of the `name` field if it is present in the stanza
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value)
    }
    /// Provides an iterator over the fields of a ControlStanza.
    pub fn fields(&self) -> impl Iterator<Item = &'_ ControlField<'a>> {
        self.fields.iter()
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.src.len()
    }
}

/// Represents the single mutable Debian Control Stanza (a.k.a. Paragraph)
pub struct MutableControlStanza {
    inner: MutableControlStanzaInner,
}

#[ouroboros::self_referencing]
struct MutableControlStanzaInner {
    src: Arc<str>,
    #[borrows(src)]
    #[not_covariant]
    fields: Vec<MutableControlField<'this>>,
}

impl std::fmt::Display for MutableControlStanza {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for field in self.fields() {
            write!(f, "{}", field)?;
        }
        Ok(())
    }
}

impl Default for MutableControlStanza {
    fn default() -> Self {
        Self::new()
    }
}

impl MutableControlStanza {
    /// Creates new empty Stanza
    pub fn new() -> Self {
        MutableControlStanza {
            inner: MutableControlStanzaInnerBuilder {
                src: Arc::from("".to_string()),
                fields_builder: |_| vec![],
            }
            .build(),
        }
    }
    /// Parses a string into a ControlStanza, ensuring that the entire `src` string is consumed.
    pub fn parse<S: Into<Arc<str>>>(src: S) -> Result<Self, ParseError> {
        Ok(MutableControlStanza {
            inner: MutableControlStanzaInnerTryBuilder {
                src: src.into(),
                #[allow(clippy::borrowed_box)]
                fields_builder: |src: &'_ Arc<str>| {
                    let fields = ControlParser::new(src)
                        .map(|f| match f {
                            Ok(f) => Ok(MutableControlField::from(f)),
                            Err(e) => Err(e),
                        })
                        .collect::<Result<Vec<MutableControlField<'_>>, ParseError>>()?;
                    if fields.is_empty() {
                        Err(ParseError::from("Empty control stanza"))
                    } else {
                        Ok(fields)
                    }
                },
            }
            .try_build()?,
        })
    }
    pub fn len(&self) -> usize {
        self.fields()
            .map(|field| field.name.len() + 1 + field.value.len())
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.with_fields(|fields| fields.is_empty())
    }
    /// Returns the value of the `name` field if it is present in the stanza
    pub fn field(&self, name: &str) -> Option<&str> {
        self.inner.with_fields(|fields| {
            fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.as_ref())
        })
    }
    /// Provides an iterator over the fields of ControlStanza.
    pub fn fields(&self) -> impl Iterator<Item = &'_ MutableControlField<'_>> {
        self.inner.with_fields(|fields| fields.iter())
    }
    /// Sets the value of a field, adding the field if it does not already exist.
    pub fn set<N: Into<Cow<'static, str>> + AsRef<str>, V: Into<Cow<'static, str>>>(
        &mut self,
        name: N,
        value: V,
    ) -> &mut Self {
        self.inner.with_fields_mut(|fields| {
            for f in fields.iter_mut() {
                if f.is_a(name.as_ref()) {
                    f.set(value.into());
                    return;
                }
            }
            fields.push(MutableControlField {
                name: name.into(),
                value: value.into(),
            })
        });
        self
    }
    /// Removes field from the Stanza.
    pub fn remove<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        self.inner.with_fields_mut(|fields| {
            for (i, f) in fields.iter().enumerate() {
                if f.is_a(name.as_ref()) {
                    fields.remove(i);
                    return;
                }
            }
        });
        self
    }
    /// Retains fields matching filter `f`, while removing others.
    pub fn retain<F: FnMut(&MutableControlField) -> bool>(&mut self, f: F) -> &mut Self {
        self.inner.with_fields_mut(|fields| fields.retain(f));
        self
    }
    /// Sorts fields by name using provided comparator.
    pub fn sort_fields_by_name<F: FnMut(&str, &str) -> std::cmp::Ordering>(
        &mut self,
        mut compare: F,
    ) {
        self.inner.with_fields_mut(|fields| {
            fields.sort_by(|left, right| compare(left.name().as_ref(), right.name().as_ref()));
        });
    }
    /// Sorts fields by name in the order usually present on dpkg's status file.
    pub fn sort_fields_deb_order(&mut self) {
        self.sort_fields_by_name(|left, right| {
            match deb_sort_order(left).cmp(&deb_sort_order(right)) {
                std::cmp::Ordering::Equal => cmp_ascii_ignore_case(left, right),
                ne => ne,
            }
        })
    }
    pub fn package_name(&self) -> std::result::Result<String, ParseError> {
        let (arch, name, ver) =
            self.fields()
                .find_fields(("Architecture", "Package", "Version"))?;
        Ok(format!("{}_{}_{}", &name, &ver, &arch))
    }
}

impl Serialize for MutableControlStanza {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for MutableControlStanza {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        MutableControlStanza::parse(s).map_err(serde::de::Error::custom)
    }
}

pub trait Field<R> {
    fn is_a<N: AsRef<str>>(&self, name: N) -> bool;
    fn name(&self) -> R;
    fn value(&self) -> R;
}

impl<'a> Field<&'a str> for ControlField<'a> {
    /// True if this is field is a `name`
    fn is_a<N: AsRef<str>>(&self, name: N) -> bool {
        self.name.eq_ignore_ascii_case(name.as_ref())
    }
    /// Returns field's name
    fn name(&self) -> &'a str {
        self.name
    }
    /// Returns field's value
    fn value(&self) -> &'a str {
        self.value
    }
}

impl<'a> Field<Cow<'a, str>> for &MutableControlField<'a> {
    /// True if this is field is a `name`
    fn is_a<N: AsRef<str>>(&self, name: N) -> bool {
        self.name.eq_ignore_ascii_case(name.as_ref())
    }
    /// Returns field's name
    fn name(&self) -> Cow<'a, str> {
        self.name.clone()
    }
    /// Returns field's value
    fn value(&self) -> Cow<'a, str> {
        self.value.clone()
    }
}

impl<'a> Field<Cow<'a, str>> for MutableControlField<'a> {
    /// True if this is field is a `name`
    fn is_a<N: AsRef<str>>(&self, name: N) -> bool {
        self.name.eq_ignore_ascii_case(name.as_ref())
    }
    /// Returns field's name
    fn name(&self) -> Cow<'a, str> {
        self.name.clone()
    }
    /// Returns field's value
    fn value(&self) -> Cow<'a, str> {
        self.value.clone()
    }
}

pub trait FindFields<M, R, E> {
    fn find_fields(self, matches: M) -> std::result::Result<R, E>;
}

impl<'m, I, F, R> FindFields<&'m str, R, &'m str> for I
where
    F: Field<R>,
    I: Iterator<Item = F>,
{
    fn find_fields(self, m: &'m str) -> std::result::Result<R, &'m str> {
        self.fold(None, |found, field| {
            if field.is_a(m) {
                Some(field.value())
            } else {
                found
            }
        })
        .ok_or(m)
    }
}

impl<'m, I, F, R> FindFields<(&'m str, &'m str), (R, R), &'m str> for I
where
    F: Field<R>,
    I: Iterator<Item = F>,
{
    fn find_fields(self, m: (&'m str, &'m str)) -> std::result::Result<(R, R), &'m str> {
        let r = self.fold((None, None), |found, field| {
            if field.is_a(m.0) {
                (Some(field.value()), found.1)
            } else if field.is_a(m.1) {
                (found.0, Some(field.value()))
            } else {
                found
            }
        });
        Ok((r.0.ok_or(m.0)?, r.1.ok_or(m.1)?))
    }
}

impl<'m, I, F, R> FindFields<(&'m str, &'m str, &'m str), (R, R, R), &'m str> for I
where
    F: Field<R>,
    I: Iterator<Item = F>,
{
    fn find_fields(
        self,
        m: (&'m str, &'m str, &'m str),
    ) -> std::result::Result<(R, R, R), &'m str> {
        let r = self.fold((None, None, None), |found, field| {
            if field.is_a(m.0) {
                (Some(field.value()), found.1, found.2)
            } else if field.is_a(m.1) {
                (found.0, Some(field.value()), found.2)
            } else if field.is_a(m.2) {
                (found.0, found.1, Some(field.value()))
            } else {
                found
            }
        });
        Ok((r.0.ok_or(m.0)?, r.1.ok_or(m.1)?, r.2.ok_or(m.2)?))
    }
}

fn cmp_ascii_ignore_case(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left = left.as_bytes().iter();
    let mut right = right.as_bytes().iter();
    loop {
        if let Some(l) = left.next() {
            if let Some(r) = right.next() {
                match l.to_ascii_lowercase().cmp(&r.to_ascii_lowercase()) {
                    std::cmp::Ordering::Equal => continue,
                    ne => break ne,
                }
            } else {
                break std::cmp::Ordering::Greater;
            }
        } else if right.next().is_some() {
            break std::cmp::Ordering::Less;
        } else {
            break std::cmp::Ordering::Equal;
        }
    }
}

const DEB_SORT_ORDER: [&str; 23] = [
    "Package",
    "Status",
    "Version",
    "Provides",
    "Architecture",
    "Multi-Arch",
    "Priority",
    "Essential",
    "Section",
    "Pre-Depends",
    "Depends",
    "Section",
    "Breaks",
    "Conflicts",
    "Replaces",
    "Recommends",
    "Suggests",
    "Installed-Size",
    "Homepage",
    "Maintainer",
    "Source",
    "Description",
    "Conffiles",
];

fn deb_sort_order(name: &str) -> usize {
    DEB_SORT_ORDER
        .iter()
        .enumerate()
        .find(|(_, &s)| s.eq_ignore_ascii_case(name))
        .map_or(usize::MAX, |(i, _)| i)
}

impl<'a> From<&ControlStanza<'a>> for MutableControlStanza {
    fn from(stanza: &ControlStanza<'a>) -> Self {
        MutableControlStanza::parse(stanza.src).unwrap()
    }
}

/// Represents a mutable Control File consisting of multiple Stanzas
pub struct MutableControlFile {
    stanzas: Vec<MutableControlStanza>,
}

impl std::fmt::Display for MutableControlFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        self.stanzas
            .iter()
            .try_for_each(|stanza| writeln!(f, "{}", stanza))
    }
}

impl Default for MutableControlFile {
    fn default() -> Self {
        Self::new()
    }
}

impl MutableControlFile {
    /// Creats a new Control File
    pub fn new() -> Self {
        Self { stanzas: vec![] }
    }
    /// Returns an iterator over stanzas
    pub fn stanzas(&self) -> impl Iterator<Item = &'_ MutableControlStanza> {
        self.stanzas.iter()
    }
    /// Adds a new stanza
    pub fn add(&mut self, stanza: MutableControlStanza) {
        self.stanzas.push(stanza)
    }
    pub fn set_at(&mut self, index: usize, stanza: MutableControlStanza) {
        self.stanzas[index] = stanza
    }
    /// Creates a new stanza and returns a mutable reference to it.
    pub fn new_stanza(&mut self) -> &'_ mut MutableControlStanza {
        let l = self.stanzas.len();
        self.stanzas.push(MutableControlStanza::new());
        &mut self.stanzas[l]
    }
}

impl TryFrom<MutableControlFile> for Packages {
    type Error = ParseError;
    fn try_from(cf: MutableControlFile) -> std::result::Result<Self, ParseError> {
        Packages::new(cf.to_string().into(), None)
    }
}

impl From<MutableControlFile> for Vec<u8> {
    fn from(cf: MutableControlFile) -> Self {
        cf.to_string().into_bytes()
    }
}

/// Represents an immutable Debian Control File consisting of multiple Stanzas
pub struct ControlFile<'a> {
    pub stanzas: Vec<ControlStanza<'a>>,
}

impl std::iter::FromIterator<MutableControlStanza> for MutableControlFile {
    fn from_iter<T: IntoIterator<Item = MutableControlStanza>>(iter: T) -> Self {
        let stanzas: Vec<MutableControlStanza> = iter.into_iter().collect();
        Self { stanzas }
    }
}
impl std::iter::Extend<MutableControlStanza> for MutableControlFile {
    fn extend<T: IntoIterator<Item = MutableControlStanza>>(&mut self, iter: T) {
        self.stanzas.extend(iter)
    }
}

impl std::fmt::Display for ControlFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for stanza in &self.stanzas {
            write!(f, "{}", stanza)?;
        }
        writeln!(f)
    }
}

impl<'a> ControlFile<'a> {
    /// Parses a string into ControlFile
    pub fn parse<S: ?Sized + AsRef<str>>(src: &'a S) -> Result<Self, ParseError> {
        let mut parser = ControlParser::new(src.as_ref());
        let mut stanzas: Vec<ControlStanza<'a>> = vec![];
        loop {
            let snap = unsafe { parser.snap() };
            let mut fields: Vec<ControlField<'a>> = vec![];
            while let Some(field) = parser.field()? {
                fields.push(field)
            }
            if fields.is_empty() {
                break;
            } else {
                stanzas.push(ControlStanza {
                    src: unsafe { snap.into_slice(&parser) },
                    fields,
                })
            }
        }
        Ok(Self { stanzas })
    }
    /// Returns an interator over stanzas
    pub fn stanzas(&self) -> impl Iterator<Item = &'_ ControlStanza<'a>> {
        self.stanzas.iter()
    }
}

/// Provides a Debian Control format parser.
pub struct ControlParser<'a> {
    src: &'a str,
}

pub(crate) struct ControlParserSnapshot<'a> {
    src: &'a str,
}

impl<'a> ControlParser<'a> {
    pub(crate) unsafe fn snap(&self) -> ControlParserSnapshot<'a> {
        ControlParserSnapshot { src: self.src }
    }
}

impl<'a> ControlParserSnapshot<'a> {
    pub(crate) unsafe fn into_slice(self, cur: &ControlParser<'a>) -> &'a str {
        &self.src[..unsafe { cur.src.as_ptr().offset_from(self.src.as_ptr()) } as usize]
    }
}

#[inline]
fn valid_field_name_char(c: u8) -> bool {
    (b';'..=b'~').contains(&c) || (b'!'..=b'9').contains(&c)
}

#[inline]
fn valid_field_name_first_char(c: u8) -> bool {
    (b';'..=b'~').contains(&c) || ((b'!'..=b'9').contains(&c) && c != b'-' && c != b'#')
}

#[inline]
fn is_ws(c: &u8) -> bool {
    *c == b' ' || *c == b'\t'
}

impl<'a> ControlParser<'a> {
    /// Creates a new parser from the `src`
    pub fn new<S: ?Sized + AsRef<str>>(src: &'a S) -> Self {
        Self { src: src.as_ref() }
    }
    fn quote_err(&self) -> String {
        match self.src.char_indices().nth(20) {
            None => self.src,
            Some((n, _)) => &self.src[..n],
        }
        .to_string()
    }
    // take `take` bytes and the also skip `skip` bytes
    #[inline]
    fn advance(&mut self, take: usize, skip: usize) -> &'a str {
        let ret = &self.src[..take];
        self.src = &self.src[take + skip..];
        ret
    }
    #[inline]
    fn skip(&mut self, skip: usize) {
        self.src = &self.src[skip..];
    }
    fn field_name(&mut self) -> Result<Option<&'a str>, ParseError> {
        let mut inp = self.src.as_bytes();
        if let [b, rest @ ..] = inp {
            if *b == b'\n' {
                self.skip(1);
                return Ok(None);
            } else if !valid_field_name_first_char(*b) {
                return Err(format!("Invalid field name {}", self.quote_err()).into());
            } else {
                inp = rest;
            }
        } else {
            return Ok(None);
        }
        let mut pos = 1usize;
        while let [b, rest @ ..] = inp {
            if valid_field_name_char(*b) {
                inp = rest;
                pos += 1;
            } else if *b == b':' {
                return Ok(Some(self.advance(pos, 1)));
            } else {
                return Err(format!("Invalid field name {}", self.quote_err()).into());
            }
        }
        Err(format!("unterminated field name {}", self.quote_err()).into())
    }
    fn field_value(&mut self) -> Result<&'a str, ParseError> {
        let mut inp = self.src.as_bytes();
        // skip spaces on first line
        while let [b, rest @ ..] = inp {
            if is_ws(b) {
                inp = rest;
            } else {
                self.src = unsafe { std::str::from_utf8_unchecked(inp) };
                break;
            }
        }
        // let start = inp;
        let mut pos = match memchr::memchr(b'\n', inp) {
            Some(p) => p + 1,
            None => {
                return Ok(self.advance(inp.len(), 0));
            }
        };
        inp = &inp[pos..];
        // rest
        loop {
            let mut ws = 0;
            while let [b, rest @ ..] = inp {
                if is_ws(b) {
                    ws += 1;
                    inp = rest;
                } else {
                    break;
                }
            }
            if ws == 0 {
                break;
            }
            pos += ws;
            match memchr::memchr(b'\n', inp) {
                None => {
                    // end of input
                    return Ok(self.advance(pos + inp.len(), 0));
                }
                Some(n) => {
                    pos += n + 1;
                    inp = &inp[n + 1..];
                    if n == 0 {
                        break;
                    }
                }
            }
        }
        Ok(self.advance(pos - 1, 1))
    }
    /// Returns the next parsed field, or None if at the end of the stanza.
    /// The next call either returns None at the end of the file or the first field of the next stanza.
    pub fn field(&mut self) -> Result<Option<ControlField<'a>>, ParseError> {
        match self.field_name()? {
            None => Ok(None),
            Some(name) => Ok(Some(ControlField {
                name,
                value: self.field_value()?,
            })),
        }
    }
}

impl<'a> Iterator for ControlParser<'a> {
    type Item = Result<ControlField<'a>, ParseError>;
    /// Implements iterator interface over fields.
    fn next(&mut self) -> Option<Self::Item> {
        self.field().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_field_name() {
        assert!(valid_field_name_char(b'A'));
        assert!(valid_field_name_char(b'z'));
        assert!(valid_field_name_char(b'1'));
        assert!(valid_field_name_char(b'-'));
        assert!(!valid_field_name_char(b' '));
    }

    #[test]
    fn test_multiline() {
        let data = "Base:\n Value1\n Value2\nField:\n Value\n\n";
        match ControlFile::parse(data) {
            Ok(file) => {
                let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
                assert_eq!(file.stanzas.len(), 1);
                assert_eq!(stanzas[0].fields.len(), 2);
                assert_eq!(stanzas[0].field("Field").unwrap(), "\n Value");
            }
            Err(err) => panic!("Failed to parse control file {:?}", err),
        }
    }

    #[test]
    fn test_parse_control_file() {
        let data = "\
FieldName: FieldValue

Simple: simple value
Folded: line
 continuation
Multi-Line:
 Line one
 .
 Line two


";
        match ControlFile::parse(data) {
            Ok(file) => {
                let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
                assert_eq!(file.stanzas.len(), 2);
                assert_eq!(stanzas[0].fields.len(), 1);
                assert_eq!(stanzas[1].fields.len(), 3);
                assert_eq!(stanzas[1].field("Simple").unwrap(), "simple value");
                assert_eq!(stanzas[1].field("folded").unwrap(), "line\n continuation");
                assert_eq!(
                    stanzas[1].field("multi-line").unwrap(),
                    "\n Line one\n .\n Line two"
                );
            }
            Err(err) => panic!("Failed to parse control file {:?}", err),
        }
    }

    #[test]
    fn test_multiline_eof() {
        let data = "Base:\n Value1\n Value2\nField:\n Value";
        match ControlFile::parse(data) {
            Ok(file) => {
                let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
                assert_eq!(file.stanzas.len(), 1);
                assert_eq!(stanzas[0].fields.len(), 2);
                assert_eq!(stanzas[0].field("Field").unwrap(), "\n Value");
            }
            Err(err) => panic!("Failed to parse control file {:?}", err),
        }
    }

    #[test]
    fn test_single_eof() {
        let data = "Base:\n Value1\n Value2\nField: Value";
        match ControlFile::parse(data) {
            Ok(file) => {
                let stanzas: Vec<&ControlStanza> = file.stanzas.iter().collect();
                assert_eq!(file.stanzas.len(), 1);
                assert_eq!(stanzas[0].fields.len(), 2);
                assert_eq!(stanzas[0].field("Field").unwrap(), "Value");
            }
            Err(err) => panic!("Failed to parse control file {:?}", err),
        }
    }

    #[test]
    fn test_mulitple() {
        let data: Vec<&str> = vec!["A: B\n\n", "A: B\n\n"];
        let parsed: Vec<ControlFile<'_>> = data
            .iter()
            .map(|d| ControlFile::parse(d).unwrap())
            .collect();
        assert!(&parsed[0]
            .stanzas()
            .next()
            .unwrap()
            .fields()
            .next()
            .unwrap()
            .is_a("a"))
    }

    #[test]
    fn test_add_stanza() {
        let mut cf = MutableControlFile::new();
        let s = cf.new_stanza();
        s.set("A", "B");
        let d = "D".to_string();
        s.set("C", d);
        assert_eq!(format!("{}", cf), "A: B\nC: D\n\n");
    }

    #[test]
    fn test_add_field() {
        let data = "\
Package: test
Arch: i386
Description:
 Test description
";
        let mut stanza = MutableControlStanza::parse(data).unwrap();
        stanza.set("NewField", "NewValue");
        assert_eq!(stanza.field("NewField").unwrap(), "NewValue");
        stanza.set("Field1", "Value1");
        assert_eq!(stanza.field("Field1").unwrap(), "Value1");
        let mut it = stanza.fields();
        let f = it.next().unwrap();
        assert_eq!(f.name(), "Package");
        assert_eq!(f.value(), "test");
        let f = it.next().unwrap();
        assert_eq!(f.name(), "Arch");
        assert_eq!(f.value(), "i386");
    }
}
