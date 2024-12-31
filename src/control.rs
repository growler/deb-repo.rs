/// Provides interface to work with Debian Control files
/// see https://www.debian.org/doc/debian-policy/ch-controlfields.html
///
/// The parser does not process comments
use crate::error::{Error, Result};

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
    pub fn new<'b: 'a, 'c: 'a>(name: &'b str, value: &'c str) -> ControlField<'a> {
        ControlField { name, value }
    }
    pub fn is_a(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
    pub fn name(&self) -> &'a str {
        self.name
    }
    pub fn value(&self) -> &'a str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ControlStanza<'a> {
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
    pub fn parse(src: &'a str) -> Result<Self> {
        let fields = ControlParser::new(src).collect::<Result<Vec<ControlField<'a>>>>()?;
        if fields.is_empty() {
            Err(Error::EmptyControl)
        } else {
            Ok(ControlStanza { fields })
        }
    }
    pub fn field(&self, name: &str) -> Option<&'a str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value)
    }
    pub fn set<'b: 'a, 'c: 'a>(&mut self, name: &'b str, value: &'c str) -> &Self {
        if let Some(item) = self
            .fields
            .iter_mut()
            .find(|f| f.name.eq_ignore_ascii_case(&name))
        {
            item.value = value;
        } else {
            self.fields.push(ControlField { name, value });
        };
        self
    }
    pub fn fields<'b: 'a>(&'b self) -> impl Iterator<Item = &'b ControlField<'a>> {
        self.fields.iter()
    }
    pub fn fields_mut<'b: 'a>(&'b mut self) -> impl Iterator<Item = &'b mut ControlField<'a>> {
        self.fields.iter_mut()
    }
}

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
    pub fn new() -> Self {
        ControlFile { stanzas: vec![] }
    }
    pub fn parse(src: &'a str) -> Result<Self> {
        let mut parser = ControlParser::new(src);
        let mut stanzas: Vec<ControlStanza<'a>> = vec![];
        loop {
            let mut fields: Vec<ControlField<'a>> = vec![];
            while let Some(field) = parser.field()? {
                fields.push(field)
            }
            if fields.is_empty() {
                break;
            } else {
                stanzas.push(ControlStanza { fields })
            }
        }
        Ok(Self { stanzas })
    }
    pub fn new_stanza(&self) -> ControlStanza<'static> {
        ControlStanza { fields: vec![] }
    }
    pub fn add<'b: 'a>(&mut self, stanza: ControlStanza<'b>) {
        self.stanzas.push(stanza)
    }
    pub fn stazas<'b: 'a>(&'b self) -> impl Iterator<Item = &'b ControlStanza<'a>> {
        self.stanzas.iter()
    }
    pub fn fields_mut<'b: 'a>(&'b mut self) -> impl Iterator<Item = &'b mut ControlStanza<'a>> {
        self.stanzas.iter_mut()
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
        ControlParserSnapshot {
            src: self.src,
        }
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
    fn field_name(&mut self) -> Result<Option<&'a str>> {
        let mut inp = self.src.as_bytes();
        if let [b, rest @ ..] = inp {
            if *b == b'\n' {
                self.skip(1);
                return Ok(None);
            } else if !valid_field_name_first_char(*b) {
                return Err(Error::InvalidFieldName(self.quote_err()));
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
                return Err(Error::InvalidFieldName(self.quote_err()));
            }
        }
        Err(Error::UnterminatedField(self.quote_err()))
    }
    fn field_value(&mut self) -> Result<&'a str> {
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
            .ok_or_else(|| Error::UnterminatedField(self.quote_err()))?;
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
            let n = memchr::memchr(b'\n', inp)
                .ok_or_else(|| Error::UnterminatedField(self.quote_err()))?;
            pos += n + 1;
            inp = &inp[n + 1..];
            if n == 0 {
                break;
            }
        }
        Ok(self.advance(pos - 1, 1))
    }
    pub fn field(&mut self) -> Result<Option<ControlField<'a>>> {
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
    type Item = std::result::Result<ControlField<'a>, Error>;
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
            .stazas()
            .next()
            .unwrap()
            .fields()
            .next()
            .unwrap()
            .is_a("a"))
    }

    #[test]
    fn test_add_stanza() {
        let mut cf = ControlFile::new();
        let mut s = cf.new_stanza();
        s.set("A", "B".try_into().unwrap());
        let d = "D".to_string();
        s.set("C", &d);
        let f = "F".to_string();
        s.set("E", f.as_str().try_into().unwrap());
        cf.add(s);
        assert_eq!(format!("{}", cf), "A: B\nC: D\nE: F\n\n");
    }

    #[test]
    fn test_add_field() {
        let data = "\
Package: test
Arch: i386
Description:
 Test description
";
        let mut stanza = ControlStanza::parse(data).unwrap();
        stanza.set("NewField", "NewValue");
        assert_eq!(stanza.field("NewField").unwrap(), "NewValue");
        stanza.set("Field1", "Value1".try_into().unwrap());
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
