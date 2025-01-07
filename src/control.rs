/// Provides interface to work with Debian Control files
/// see <https://www.debian.org/doc/debian-policy/ch-controlfields.html>
///
/// The parser does not process comments and is suitable only
/// for parsing then binary packages descriptions.
use {crate::idmap::IntoBoxed, std::borrow::Cow};

/// Parsing error
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
        write!(f, "error parsing {}", self.msg)
    }
}

/// Represents the Debian Control File field.
/// Internally ControlField contains references to a slice of
/// parsed Control File.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlField<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> std::fmt::Display for ControlField<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.as_bytes().iter().next() == Some(&b'\n') {
            writeln!(f, "{}:{}", self.name, self.value)
        } else {
            writeln!(f, "{}: {}", &self.name, &self.value)
        }
    }
}

impl<'a> ControlField<'a> {
    /// True if this is field is a `name`
    pub fn is_a(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
    /// Returns field's name
    pub fn name(&self) -> &'a str {
        self.name
    }
    /// Returns field's value
    pub fn value(&self) -> &'a str {
        self.value
    }
}

/// Represents the Debian Control File field.
/// Internally ControlField contains references to a slice of
/// parsed Control File.
#[derive(Debug, Clone, PartialEq)]
pub struct MutableControlField<'a> {
    name: Cow<'a, str>,
    value: Cow<'a, str>,
}

impl<'a> std::fmt::Display for MutableControlField<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.as_bytes().iter().next() == Some(&b'\n') {
            writeln!(f, "{}:{}", self.name, self.value)
        } else {
            writeln!(f, "{}: {}", &self.name, &self.value)
        }
    }
}

impl<'a> MutableControlField<'a> {
    /// True if this is field is a `name`
    pub fn is_a(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
    /// Returns field's name
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns field's value
    pub fn value(&self) -> &str {
        &self.value
    }
    ///
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

/// Represents the single Debian Control Stanza (a.k.a. Paragraph)
#[derive(Debug, Clone, PartialEq)]
pub struct ControlStanza<'a> {
    src: &'a str,
    fields: Vec<ControlField<'a>>,
}

impl<'a> std::fmt::Display for ControlStanza<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for field in &self.fields {
            write!(f, "{}", field)?;
        }
        Ok(())
    }
}

impl<'a> ControlStanza<'a> {
    /// Parses a string into a ControlStanza. Requires that the `src` is completely parsed.
    pub fn parse(src: &'a str) -> Result<Self, ParseError> {
        let fields =
            ControlParser::new(src).collect::<Result<Vec<ControlField<'a>>, ParseError>>()?;
        if fields.is_empty() {
            Err("Empty control stanza".into())
        } else {
            Ok(ControlStanza { src, fields })
        }
    }
    /// Returns the value of the field `name` if present in the stanza
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value.as_ref())
    }
    /// Returns an iterator over the ControlStanza fields.
    pub fn fields(&self) -> impl Iterator<Item = &'_ ControlField<'a>> {
        self.fields.iter()
    }
}

/// Represents the single Debian Control Stanza (a.k.a. Paragraph)
pub struct MutableControlStanza {
    inner: MutableControlStanzaInner,
}

#[ouroboros::self_referencing]
struct MutableControlStanzaInner {
    src: Box<str>,
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

impl MutableControlStanza {
    pub fn new() -> Self {
        MutableControlStanza {
            inner: MutableControlStanzaInnerBuilder {
                src: "".into_boxed(),
                fields_builder: |_| vec![],
            }
            .build(),
        }
    }
    /// Parses a string into a ControlStanza. Requires that the `src` is completely parsed.
    pub fn parse<S: IntoBoxed<str>>(src: S) -> Result<Self, ParseError> {
        Ok(MutableControlStanza {
            inner: MutableControlStanzaInnerTryBuilder {
                src: src.into_boxed(),
                fields_builder: |src: &'_ Box<str>| {
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
    /// Returns the value of the field `name` if present in the stanza
    pub fn field(&self, name: &str) -> Option<&str> {
        self.inner.with_fields(|fields| {
            fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.as_ref())
        })
    }
    /// Returns an iterator over the ControlStanza fields.
    pub fn fields(&self) -> impl Iterator<Item = &'_ MutableControlField> {
        self.inner.with_fields(|fields| fields.iter())
    }
    /// Sets a field.
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
    pub fn remove<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        self.inner.with_fields_mut(|fields| {
            for (i, f) in fields.iter().enumerate() {
                if f.is_a(name.as_ref()) {
                    fields.remove(i);
                    return
                }
            }
        });
        self
    }
    pub fn retain<F: FnMut(&MutableControlField) -> bool>(&mut self, f: F) -> &mut Self {
        self.inner.with_fields_mut(|fields| {
            fields.retain(f)
        });
        self
    }
}

impl<'a> From<&ControlStanza<'a>> for MutableControlStanza {
    fn from(stanza: &ControlStanza<'a>) -> Self {
        MutableControlStanza::parse(stanza.src).unwrap()
    }
}

pub struct MutableControlFile {
    stanzas: Vec<MutableControlStanza>,
}

impl std::fmt::Display for MutableControlFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for stanza in &self.stanzas {
            write!(f, "{}", stanza)?;
        }
        write!(f, "\n")
    }
}

impl MutableControlFile {
    pub fn new() -> Self {
        Self { stanzas: vec![] }
    }
    pub fn stanzas(&self) -> impl Iterator<Item = &'_ MutableControlStanza> {
        self.stanzas.iter()
    }
    pub fn add(&mut self, stanza: MutableControlStanza) {
        self.stanzas.push(stanza)
    }
    pub fn new_stanza(&mut self) -> &'_ mut MutableControlStanza {
        let l = self.stanzas.len();
        self.stanzas.push(MutableControlStanza::new());
        &mut self.stanzas[l]
    }
}

/// Represents the Debian Control File, containing a number of Stanzas
pub struct ControlFile<'a> {
    pub stanzas: Vec<ControlStanza<'a>>,
}

impl<'a> std::fmt::Display for ControlFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for stanza in &self.stanzas {
            write!(f, "{}", stanza)?;
        }
        write!(f, "\n")
    }
}

impl<'a> ControlFile<'a> {
    pub fn parse(src: &'a str) -> Result<Self, ParseError> {
        let mut parser = ControlParser::new(src);
        let mut stanzas: Vec<ControlStanza<'a>> = vec![];
        loop {
            let snap = unsafe { parser.snap() };
            let mut fields: Vec<ControlField<'a>> = vec![];
            while let Some(field) = parser.field()? {
                fields.push(field.into())
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
    pub fn stanzas(&self) -> impl Iterator<Item = &'_ ControlStanza<'a>> {
        self.stanzas.iter()
    }
}

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
    (c >= b';' && c <= b'~') || (c >= b'!' && c <= b'9')
}

#[inline]
fn valid_field_name_first_char(c: u8) -> bool {
    (c >= b';' && c <= b'~') || (c >= b'!' && c <= b'9' && c != b'-' && c != b'#')
}

#[inline]
fn is_ws(c: &u8) -> bool {
    *c == b' ' || *c == b'\t'
}

impl<'a> ControlParser<'a> {
    pub fn new(src: &'a str) -> Self {
        Self { src }
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
        Err(format!("Unterminated field name {}", self.quote_err()).into())
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
        let mut pos = 1 + memchr::memchr(b'\n', inp)
            .ok_or_else(|| ParseError::from(format!("Unterminated field {}", self.quote_err())))?;
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
            let n = memchr::memchr(b'\n', inp).ok_or_else(|| {
                ParseError::from(format!("Unterminated field {}", self.quote_err()))
            })?;
            pos += n + 1;
            inp = &inp[n + 1..];
            if n == 0 {
                break;
            }
        }
        Ok(self.advance(pos - 1, 1))
    }
    pub fn field(&mut self) -> Result<Option<ControlField<'a>>, ParseError> {
        match self.field_name()? {
            None => return Ok(None),
            Some(name) => Ok(Some(ControlField {
                name,
                value: self.field_value()?,
            })),
        }
    }
}

impl<'a> Iterator for ControlParser<'a> {
    type Item = Result<ControlField<'a>, ParseError>;
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
