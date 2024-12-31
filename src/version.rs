///
use {
    smallvec::{smallvec, SmallVec},
    std::{
        cmp::Ordering,
        fmt::{self, Debug, Display, Formatter},
        hash::{Hash, Hasher},
    },
};

/// Defines a method to check if a given value satisfies a specific requirement.
///
/// # Type Parameters
///
/// * `R`: The type of the requirement against which the value will be checked.
pub trait Satisfies<R> {
    fn satisfies(&self, requirement: &R) -> bool;
}
pub trait SatisfiedBy<C> {
    #[allow(dead_code)]
    fn is_satisfied_by(&self, candidate: &C) -> bool;
}
impl<C, S> SatisfiedBy<C> for S
where
    C: Satisfies<S>,
{
    fn is_satisfied_by(&self, candidate: &C) -> bool {
        candidate.satisfies(self)
    }
}

pub trait DisplayName {
    fn fmt_name<'a>(&'a self, name: impl Display + 'a) -> impl Display + 'a;
}

struct ArchNameDisplay<'a, A: Display, N: Display> {
    arch: &'a Option<A>,
    name: N,
}

impl<'a, A: Display, N: Display> Display for ArchNameDisplay<'a, A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.arch {
            None => self.name.fmt(f),
            Some(a) => write!(f, "{}:{}", self.name, a),
        }
    }
}

impl<A: Display> DisplayName for Option<A> {
    fn fmt_name<'a>(&'a self, name: impl Display + 'a) -> impl Display + 'a {
        ArchNameDisplay { arch: self, name }
    }
}

#[derive(Clone)]
pub enum ProvidedName<N, V> {
    Any(N),
    Exact(N, V),
}

impl<N, V> ProvidedName<N, V> {
    pub fn translate<OtherN, OtherV, FN, FV>(&self, tn: FN, tv: FV) -> ProvidedName<OtherN, OtherV>
    where
        FN: FnMut(&N) -> OtherN,
        FV: FnMut(&V) -> OtherV,
    {
        let mut tn = tn;
        let mut tv = tv;
        match self {
            Self::Exact(n, v) => ProvidedName::Exact(tn(n), tv(v)),
            Self::Any(n) => ProvidedName::Any(tn(n)),
        }
    }
}

impl<N: Display, V: Display> Display for ProvidedName<N, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Any(n) => n.fmt(f),
            Self::Exact(n, v) => {
                n.fmt(f)?;
                f.write_str("=")?;
                v.fmt(f)
            }
        }
    }
}

impl<N: Debug, V: Debug> Debug for ProvidedName<N, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("ProvidedName::")?;
        match self {
            Self::Any(n) => {
                f.write_str("Any(")?;
                n.fmt(f)?;
                f.write_str(")")
            }
            Self::Exact(n, v) => {
                f.write_str("Exact(")?;
                n.fmt(f)?;
                f.write_str("=")?;
                v.fmt(f)?;
                f.write_str(")")
            }
        }
    }
}

impl<N, V> ProvidedName<N, V> {
    pub fn name(&self) -> &N {
        match self {
            Self::Any(n) => n,
            Self::Exact(n, _) => n,
        }
    }
    pub fn version(&self) -> Option<&V> {
        match self {
            Self::Exact(_, v) => Some(v),
            _ => None,
        }
    }
}

impl<V: Clone> From<Option<&Version<V>>> for VersionSet<Version<V>> {
    fn from(pv: Option<&Version<V>>) -> Self {
        match pv {
            None => VersionSet::Any,
            Some(v) => VersionSet::Exactly(v.clone()),
        }
    }
}

#[derive(Clone)]
pub struct Constraint<A, N, V> {
    name: N,
    arch: A,
    range: VersionSet<V>,
}

impl<A, N, V> Constraint<A, N, V> {
    pub fn new(arch: A, name: N, version_set: VersionSet<V>) -> Self {
        Self {
            arch,
            name,
            range: version_set,
        }
    }
    pub fn arch(&self) -> &A {
        &self.arch
    }
    pub fn name(&self) -> &N {
        &self.name
    }
    pub fn range(&self) -> &VersionSet<V> {
        &self.range
    }
    pub fn into_range(self) -> VersionSet<V> {
        self.range
    }
}

impl<A: Hash + Eq, N: Hash + Eq, V: Hash + Eq> Hash for Constraint<A, N, V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.range.hash(state);
        self.arch.hash(state);
    }
}

impl<A: Eq, N: Eq, V: Eq> Eq for Constraint<A, N, V> {}
impl<A: Eq, N: Eq, V: Eq> PartialEq for Constraint<A, N, V> {
    fn eq(&self, other: &Self) -> bool {
        self.arch.eq(&other.arch) && self.name.eq(&other.name) && self.range.eq(&other.range)
    }
}

impl<A: DisplayName, N: Display, V: Display> Display for Constraint<A, N, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.range().fmt_name(self.arch.fmt_name(&self.name)).fmt(f)
    }
}

#[derive(Clone)]
pub enum Dependency<A, N, V> {
    Single(Constraint<A, N, V>),
    Union(SmallVec<[Constraint<A, N, V>; 2]>),
}

impl<A: DisplayName, N: Display, V: Display> fmt::Display for Dependency<A, N, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Single(dep) => dep.fmt(f),
            Self::Union(deps) => {
                for (i, dep) in deps.iter().enumerate() {
                    if i != 0 {
                        f.write_str(" | ")?;
                    }
                    dep.fmt(f)?;
                }
                Ok(())
            }
        }
    }
}

impl<A, N, V> Constraint<A, N, V> {
    pub fn translate<OtherA, OtherN, OtherV, FA, FN, FV>(
        &self,
        ta: FA,
        tn: FN,
        tv: FV,
    ) -> Constraint<OtherA, OtherN, OtherV>
    where
        FA: FnMut(&A) -> OtherA,
        FN: FnMut(&N) -> OtherN,
        FV: FnMut(&V) -> OtherV,
    {
        let mut ta = ta;
        let mut tn = tn;
        let mut tv = tv;
        Constraint {
            arch: ta(&self.arch),
            name: tn(&self.name),
            range: self.range.translate_internal(&mut tv),
        }
    }
}

impl<A, N, V> Dependency<A, N, V> {
    pub fn translate<OtherA, OtherN, OtherV, FA, FN, FV>(
        &self,
        ta: FA,
        tn: FN,
        tv: FV,
    ) -> Dependency<OtherA, OtherN, OtherV>
    where
        FA: FnMut(&A) -> OtherA,
        FN: FnMut(&N) -> OtherN,
        FV: FnMut(&V) -> OtherV,
    {
        let mut tn = tn;
        let mut tv = tv;
        let mut ta = ta;
        match self {
            Self::Single(v) => Dependency::Single(v.translate(&mut ta, &mut tn, &mut tv)),
            Self::Union(v) => Dependency::Union(
                v.iter()
                    .map(|v| v.translate(&mut ta, &mut tn, &mut tv))
                    .collect(),
            ),
        }
    }
    pub fn iter(&self) -> DependencyIterator<'_, A, N, V> {
        DependencyIterator { dep: self, item: 0 }
    }
}

pub struct DependencyIterator<'a, A, N, V> {
    dep: &'a Dependency<A, N, V>,
    item: usize,
}

impl<'a, A, N, V> Iterator for DependencyIterator<'a, A, N, V> {
    type Item = &'a Constraint<A, N, V>;
    fn next(&mut self) -> Option<&'a Constraint<A, N, V>> {
        match self.dep {
            Dependency::Single(dep) => {
                if self.item == 0 {
                    self.item += 1;
                    Some(dep)
                } else {
                    None
                }
            }
            Dependency::Union(deps) => {
                if self.item < deps.len() {
                    let ret = &deps[self.item];
                    self.item += 1;
                    Some(ret)
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone)]
pub enum VersionSet<V> {
    Any,
    StrictlyEarlierThan(V),
    EarlierOrEqualThan(V),
    Exactly(V),
    Except(V),
    LaterOrEqualThan(V),
    StrictlyLaterThan(V),
    None,
}

impl<V: Hash> Hash for VersionSet<V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Any | Self::None => {}
            Self::StrictlyEarlierThan(ver)
            | Self::EarlierOrEqualThan(ver)
            | Self::Exactly(ver)
            | Self::Except(ver)
            | Self::LaterOrEqualThan(ver)
            | Self::StrictlyLaterThan(ver) => {
                ver.hash(state);
            }
        }
    }
}

impl<V: Eq> Eq for VersionSet<V> {}
impl<V: Eq> PartialEq for VersionSet<V> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, Self::Any) | (Self::None, Self::None) => true,
            (Self::StrictlyEarlierThan(ver1), Self::StrictlyEarlierThan(ver2))
            | (Self::EarlierOrEqualThan(ver1), Self::EarlierOrEqualThan(ver2))
            | (Self::Exactly(ver1), Self::Exactly(ver2))
            | (Self::Except(ver1), Self::Except(ver2))
            | (Self::LaterOrEqualThan(ver1), Self::LaterOrEqualThan(ver2))
            | (Self::StrictlyLaterThan(ver1), Self::StrictlyLaterThan(ver2)) => ver1 == ver2,
            _ => false,
        }
    }
}

struct VersionSetDisplay<'a, V: Display, N: Display> {
    name: N,
    range: &'a VersionSet<V>,
}

impl<'a, V: Display, N: Display> Display for VersionSetDisplay<'a, V, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.range {
            VersionSet::Any => self.name.fmt(f),
            VersionSet::StrictlyEarlierThan(ver) => write!(f, "{} (<< {})", self.name, ver),
            VersionSet::EarlierOrEqualThan(ver) => write!(f, "{} (<= {})", self.name, ver),
            VersionSet::Exactly(ver) => write!(f, "{} (= {})", self.name, ver),
            VersionSet::Except(ver) => write!(f, "{} (!= {})", self.name, ver),
            VersionSet::LaterOrEqualThan(ver) => write!(f, "{} (>= {})", self.name, ver),
            VersionSet::StrictlyLaterThan(ver) => write!(f, "{} (>> {})", self.name, ver),
            VersionSet::None => write!(f, "!{}", self.name),
        }
    }
}

impl<V: Display> DisplayName for VersionSet<V> {
    fn fmt_name<'a>(&'a self, name: impl Display + 'a) -> impl Display + 'a {
        VersionSetDisplay { name, range: self }
    }
}

impl<V: Display> Display for VersionSet<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::StrictlyEarlierThan(ver) => write!(f, "<< {}", ver),
            Self::EarlierOrEqualThan(ver) => write!(f, "<= {}", ver),
            Self::Exactly(ver) => write!(f, "= {}", ver),
            Self::Except(ver) => write!(f, "!= {}", ver),
            Self::LaterOrEqualThan(ver) => write!(f, ">= {}", ver),
            Self::StrictlyLaterThan(ver) => write!(f, ">> {}", ver),
            Self::None => f.write_str("none"),
        }
    }
}
impl<V: Display> Debug for VersionSet<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("VersionSet(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl<V> VersionSet<V> {
    pub fn version(&self) -> Option<&V> {
        match self {
            Self::Any | Self::None => None,
            Self::StrictlyEarlierThan(version)
            | Self::EarlierOrEqualThan(version)
            | Self::Exactly(version)
            | Self::Except(version)
            | Self::LaterOrEqualThan(version)
            | Self::StrictlyLaterThan(version) => Some(version),
        }
    }
    pub fn translate<OtherV, TV>(&self, tv: TV) -> VersionSet<OtherV>
    where
        TV: FnMut(&V) -> OtherV,
    {
        let mut tv = tv;
        self.translate_internal(&mut tv)
    }
    fn translate_internal<OtherV, TV>(&self, tv: &mut TV) -> VersionSet<OtherV>
    where
        TV: FnMut(&V) -> OtherV,
    {
        match self {
            Self::Any => VersionSet::Any,
            Self::StrictlyEarlierThan(v) => VersionSet::StrictlyEarlierThan(tv(v)),
            Self::EarlierOrEqualThan(v) => VersionSet::EarlierOrEqualThan(tv(v)),
            Self::Exactly(v) => VersionSet::Exactly(tv(v)),
            Self::Except(v) => VersionSet::Except(tv(v)),
            Self::LaterOrEqualThan(v) => VersionSet::LaterOrEqualThan(tv(v)),
            Self::StrictlyLaterThan(v) => VersionSet::StrictlyLaterThan(tv(v)),
            Self::None => VersionSet::None,
        }
    }
}

/// Version represents a single version number
#[derive(Clone, Default)]
pub struct Version<V> {
    inner: V,
}

impl<V> Version<V> {
    pub(crate) fn translate<OtherV, TV>(&self, tv: TV) -> Version<OtherV>
    where
        TV: FnMut(&V) -> OtherV,
    {
        let mut tv = tv;
        Version {
            inner: tv(&self.inner),
        }
    }
}

impl<N, V> Satisfies<VersionSet<Version<V>>> for ProvidedName<N, Version<V>>
where
    Version<V>: Eq + Ord,
{
    fn satisfies(&self, set: &VersionSet<Version<V>>) -> bool {
        match self {
            Self::Any(_) => true,
            Self::Exact(_, v) => v.satisfies(set),
        }
    }
}

impl<V> Satisfies<VersionSet<Version<V>>> for Version<V>
where
    Version<V>: Eq + Ord,
{
    fn satisfies(&self, set: &VersionSet<Version<V>>) -> bool {
        match set {
            VersionSet::Any => true,
            VersionSet::StrictlyEarlierThan(set) => self < set,
            VersionSet::EarlierOrEqualThan(set) => self <= set,
            VersionSet::Exactly(set) => set == self,
            VersionSet::Except(set) => set != self,
            VersionSet::LaterOrEqualThan(set) => self >= set,
            VersionSet::StrictlyLaterThan(set) => self > set,
            VersionSet::None => false,
        }
    }
}

impl<V: Hash> Hash for Version<V> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<V> AsRef<V> for Version<V> {
    #[inline]
    fn as_ref(&self) -> &V {
        &self.inner
    }
}

impl<V: Eq + AsRef<str>> PartialOrd for Version<V> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(comparator::compare(
            self.inner.as_ref().as_bytes(),
            other.inner.as_ref().as_bytes(),
        ))
    }
}

impl<V: Eq + AsRef<str>> Ord for Version<V> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        comparator::compare(
            self.inner.as_ref().as_bytes(),
            other.inner.as_ref().as_bytes(),
        )
    }
}

impl<V: Eq> Eq for Version<V> {}
impl<V: Eq> PartialEq for Version<V> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl<V: AsRef<str>> PartialEq<str> for Version<V> {
    fn eq(&self, other: &str) -> bool {
        self.inner.as_ref() == other
    }
}

impl<V: AsRef<str>, T: AsRef<str>> PartialEq<T> for Version<V> {
    fn eq(&self, other: &T) -> bool {
        self.inner.as_ref() == other.as_ref()
    }
}

impl<V: AsRef<str>> From<&Version<V>> for String {
    fn from(value: &Version<V>) -> Self {
        value.inner.as_ref().to_string()
    }
}

impl<'a> From<&'a str> for Version<&'a str> {
    fn from(value: &'a str) -> Self {
        Version { inner: value }
    }
}

impl<V: Debug> Debug for Version<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<V: Display> Display for Version<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

enum Predicate {
    StrictlyEarlier,
    EarlierOrEqual,
    Equal,
    LaterOrEqual,
    StrictlyLater,
}
impl<'a> std::fmt::Display for Predicate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StrictlyEarlier => f.write_str("<<"),
            Self::EarlierOrEqual => f.write_str("<="),
            Self::Equal => f.write_str("="),
            Self::LaterOrEqual => f.write_str(">="),
            Self::StrictlyLater => f.write_str(">>"),
        }
    }
}

// Package names must consist only of lower case letters (a-z), digits (0-9), plus (+)
// and minus (-) signs, and periods (.). They must be at least two characters long and
// must start with an alphanumeric character.
pub fn package_char(c: &u8) -> bool {
    (*c >= b'0' && *c <= b'9')
        || (*c >= b'a' && *c <= b'z')
        || *c == b'.'
        || *c == b'-'
        || *c == b'+'
}
pub fn version_char(c: &u8) -> bool {
    (*c >= b'0' && *c <= b'9')
        || (*c >= b'a' && *c <= b'z')
        || (*c >= b'A' && *c <= b'Z')
        || *c == b'.'
        || *c == b'-'
        || *c == b'+'
        || *c == b'~'
        || *c == b':'
}

trait ByteMatcher {
    fn matches(&self, byte: &u8) -> bool;
}
impl ByteMatcher for u8 {
    #[inline]
    fn matches(&self, byte: &u8) -> bool {
        self == byte
    }
}
impl ByteMatcher for [u8] {
    #[inline]
    fn matches(&self, byte: &u8) -> bool {
        for b in self {
            if b == byte {
                return true;
            }
        }
        return false;
    }
}
impl<F: Fn(&u8) -> bool> ByteMatcher for F {
    #[inline]
    fn matches(&self, byte: &u8) -> bool {
        self(byte)
    }
}

#[derive(Debug, Clone)]
pub struct ParseError {
    msg: &'static str,
}

impl std::error::Error for ParseError {}

impl From<&'static str> for ParseError {
    fn from(msg: &'static str) -> Self {
        Self { msg }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error parsing {}", self.msg)
    }
}

struct Parser<'a> {
    inp: &'a [u8],
}

impl<'a> fmt::Debug for Parser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", unsafe {
            std::str::from_utf8_unchecked(self.inp)
        })
    }
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let [b, rest @ ..] = self.inp {
            if b.is_ascii_whitespace() {
                self.inp = rest
            } else {
                break;
            }
        }
    }
    fn is_empty(&mut self) -> bool {
        self.skip_ws();
        self.inp.is_empty()
    }
    fn next_matches(&mut self, m: impl ByteMatcher) -> Option<u8> {
        if let [b, rest @ ..] = self.inp {
            if m.matches(b) {
                self.inp = rest;
                return Some(*b);
            }
        }
        None
    }
    fn matches(&mut self, m: impl ByteMatcher) -> Option<u8> {
        self.skip_ws();
        if let [b, rest @ ..] = self.inp {
            if m.matches(b) {
                self.inp = rest;
                return Some(*b);
            }
        }
        None
    }
    fn parse(&mut self, m: impl ByteMatcher, err: &'static str) -> Result<u8, ParseError> {
        self.skip_ws();
        if let [b, rest @ ..] = self.inp {
            if m.matches(b) {
                self.inp = rest;
                return Ok(*b);
            }
        }
        Err(err.into())
    }
    fn parse_string_of(
        &mut self,
        at_least: usize,
        m: impl ByteMatcher,
        err: &'static str,
    ) -> Result<&'a str, ParseError> {
        self.skip_ws();
        let mut inp = self.inp;
        let mut cnt = 0;
        while let [b, rest @ ..] = inp {
            if m.matches(b) {
                inp = rest;
                cnt += 1;
            } else {
                break;
            }
        }
        if cnt < at_least {
            Err(err.into())
        } else {
            let ret = unsafe { std::str::from_utf8_unchecked(&self.inp[..cnt]) };
            self.inp = inp;
            Ok(ret)
        }
    }
    fn parse_predicate(&mut self) -> Result<Predicate, ParseError> {
        self.skip_ws();
        match self.inp {
            [b'=', rest @ ..] => {
                self.inp = rest;
                Ok(Predicate::Equal)
            }
            [b'<', rest @ ..] => match rest {
                [b'<', rest @ ..] => {
                    self.inp = rest;
                    Ok(Predicate::StrictlyEarlier)
                }
                [b'=', rest @ ..] => {
                    self.inp = rest;
                    Ok(Predicate::EarlierOrEqual)
                }
                _ => Err("predicate".into()),
            },
            [b'>', rest @ ..] => match rest {
                [b'>', rest @ ..] => {
                    self.inp = rest;
                    Ok(Predicate::StrictlyLater)
                }
                [b'=', rest @ ..] => {
                    self.inp = rest;
                    Ok(Predicate::LaterOrEqual)
                }
                _ => Err("predicate".into()),
            },
            _ => Err("predicate".into()),
        }
    }
}

pub struct ParsedConstraintIterator<'a> {
    straight: bool,
    parser: Parser<'a>,
}

impl<'a> ParsedConstraintIterator<'a> {
    pub(crate) fn new(src: &'a str, straight: bool) -> Self {
        Self {
            straight,
            parser: Parser {
                inp: src.as_bytes(),
            },
        }
    }
}

impl<'a> Iterator for ParsedConstraintIterator<'a> {
    type Item = Result<Constraint<Option<&'a str>, &'a str, Version<&'a str>>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            None
        } else {
            match Constraint::parse_internal(&mut self.parser, self.straight) {
                Ok(vs) => {
                    self.parser.matches(b',');
                    Some(Ok(vs))
                }
                err => Some(err),
            }
        }
    }
}

pub(crate) struct ParsedDependencyIterator<'a> {
    parser: Parser<'a>,
}

impl<'a> ParsedDependencyIterator<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        Self {
            parser: Parser {
                inp: src.as_bytes(),
            },
        }
    }
}

impl<'a> Iterator for ParsedDependencyIterator<'a> {
    type Item = Result<Dependency<Option<&'a str>, &'a str, Version<&'a str>>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            None
        } else {
            match Dependency::parse(&mut self.parser) {
                Ok(dep) => {
                    self.parser.matches(b',');
                    Some(Ok(dep))
                }
                err => Some(err),
            }
        }
    }
}

impl<'a> TryFrom<&'a str> for Dependency<Option<&'a str>, &'a str, Version<&'a str>> {
    type Error = ParseError;
    fn try_from(src: &'a str) -> Result<Self, Self::Error> {
        let mut parser = Parser {
            inp: src.as_bytes(),
        };
        let dep = Dependency::parse(&mut parser)?;
        if parser.is_empty() {
            Ok(dep)
        } else {
            Err("unexpected remaining input".into())
        }
    }
}

pub struct ParsedProvidedNameIterator<'a> {
    parser: Parser<'a>,
}

impl<'a> ParsedProvidedNameIterator<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        Self {
            parser: Parser {
                inp: src.as_bytes(),
            },
        }
    }
}

impl<'a> Iterator for ParsedProvidedNameIterator<'a> {
    type Item = Result<ProvidedName<&'a str, Version<&'a str>>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            None
        } else {
            match ProvidedName::parse(&mut self.parser) {
                Ok(pv) => {
                    self.parser.matches(b',');
                    Some(Ok(pv))
                }
                err => Some(err),
            }
        }
    }
}

impl<'a> ProvidedName<&'a str, Version<&'a str>> {
    fn parse(inp: &mut Parser<'a>) -> Result<ProvidedName<&'a str, Version<&'a str>>, ParseError> {
        if inp.is_empty() {
            return Err("provided version".into());
        }
        let package_name = inp.parse_string_of(2, package_char, "package name")?;
        if inp.matches(b'(').is_none() {
            return Ok(ProvidedName::Any(package_name));
        }
        inp.parse(b'=', "'=' in provided version")?;
        let version = inp.parse_string_of(1, version_char, "version number")?;
        inp.parse(b')', "closing ')'")?;
        Ok(ProvidedName::Exact(package_name, Version::from(version)))
    }
}

impl<'a> Constraint<Option<&'a str>, &'a str, Version<&'a str>> {
    pub fn parse(src: &'a str) -> Result<Self, ParseError> {
        let mut parser = Parser {
            inp: src.as_bytes(),
        };
        let dep = Constraint::parse_internal(&mut parser, true)?;
        if parser.is_empty() {
            Ok(dep)
        } else {
            Err("unexpected remaining input".into())
        }
    }
    fn parse_internal(inp: &mut Parser<'a>, straight: bool) -> Result<Self, ParseError> {
        if inp.is_empty() {
            return Err("dependency".into());
        }
        let name = inp.parse_string_of(2, package_char, "package name")?;
        let arch = if inp.next_matches(b':').is_some() {
            Some(inp.parse_string_of(
                2,
                |&b: &u8| (b >= b'a' && b <= b'z') || (b >= b'0' && b <= b'9') || b == b'-',
                "invalid arch qualifier",
            )?)
        } else {
            None
        };
        let range = VersionSet::<Version<&'a str>>::parse(inp, straight)?;
        Ok(Constraint { arch, name, range })
    }
}

impl<'a> VersionSet<Version<&'a str>> {
    fn parse(
        inp: &mut Parser<'a>,
        straight: bool,
    ) -> Result<VersionSet<Version<&'a str>>, ParseError> {
        if inp.matches(b'(').is_none() {
            return Ok(if straight {
                VersionSet::Any
            } else {
                VersionSet::None
            });
        }
        let predicate = inp.parse_predicate()?;
        let version = Version {
            inner: inp.parse_string_of(1, version_char, "version number")?,
        };
        inp.parse(b')', "closing ')'")?;
        Ok(match predicate {
            Predicate::StrictlyEarlier => {
                if straight {
                    VersionSet::StrictlyEarlierThan(version)
                } else {
                    VersionSet::LaterOrEqualThan(version)
                }
            }
            Predicate::EarlierOrEqual => {
                if straight {
                    VersionSet::EarlierOrEqualThan(version)
                } else {
                    VersionSet::StrictlyLaterThan(version)
                }
            }
            Predicate::Equal => {
                if straight {
                    VersionSet::Exactly(version)
                } else {
                    VersionSet::Except(version)
                }
            }
            Predicate::LaterOrEqual => {
                if straight {
                    VersionSet::LaterOrEqualThan(version)
                } else {
                    VersionSet::StrictlyEarlierThan(version)
                }
            }
            Predicate::StrictlyLater => {
                if straight {
                    VersionSet::StrictlyLaterThan(version)
                } else {
                    VersionSet::EarlierOrEqualThan(version)
                }
            }
        })
    }
}

impl<'a> Dependency<Option<&'a str>, &'a str, Version<&'a str>> {
    fn parse(inp: &mut Parser<'a>) -> Result<Self, ParseError> {
        let mut union: SmallVec<[Constraint<Option<&'a str>, &'a str, Version<&'a str>>; 2]> =
            smallvec![];
        loop {
            let dep = Constraint::parse_internal(inp, true)?;
            match inp.matches(b'|') {
                None => {
                    if union.is_empty() {
                        return Ok(Dependency::Single(dep));
                    } else {
                        union.push(dep);
                        return Ok(Dependency::Union(union));
                    }
                }
                Some(_) => {
                    union.push(dep);
                }
            }
        }
    }
}

// The version format is [epoch:]upstream_version[-debian_revision]
//
// The epoch is a number followed by ':'
//
// The version is a string that must contain only alphanumerics
// and the characters . + - ~ (full stop, plus, hyphen, tilde).
// The strings are compared from left to right.
//
// The upstream version must start with a digit. The debian version
// may start with a letter.
//
// First the initial part of each string consisting entirely of
// non-digit characters is determined. These two parts (one of
// which may be empty) are compared lexically. If a difference
// is found it is returned. The lexical comparison is a comparison
// of ASCII values modified so that all the letters sort earlier
// than all the non-letters and so that a tilde sorts before
// anything, even the end of a part. For example, the following
// parts are in sorted order from earliest to latest: `~~`, `~~a`, `~`,
// the empty part, `a`.
//
// Then the initial part of the remainder of each string which
// consists entirely of digit characters is determined. The
// numerical values of these two parts are compared, and any
// difference found is returned as the result of the comparison.
// For these purposes an empty string (which can only occur at
// the end of one or both version strings being compared) counts
// as zero.
//
// These two steps (comparing and removing initial non-digit
// strings and initial digit strings) are repeated until a difference
// is found or both strings are exhausted.

mod comparator {
    use std::cmp::Ordering;

    type Result<T> = std::result::Result<T, Ordering>;

    fn cmp<T: std::cmp::Ord + ?Sized>(this: &T, that: &T) -> Result<()> {
        match std::cmp::Ord::cmp(this, that) {
            Ordering::Equal => Ok(()),
            other => Err(other),
        }
    }

    fn cmp_alpha(this: u8, that: u8) -> Result<()> {
        if this == that {
            Ok(())
        } else if this == b'-' {
            Err(Ordering::Less)
        } else if that == b'-' {
            Err(Ordering::Greater)
        } else if (this >= b'a' && this <= b'z') || (this >= b'A' && this <= b'Z') {
            if (that >= b'a' && that <= b'z') || (that >= b'A' && that <= b'Z') {
                cmp(&this, &that)
            } else {
                Err(Ordering::Less)
            }
        } else {
            if (that >= b'a' && that <= b'z') || (that >= b'A' && that <= b'Z') {
                Err(Ordering::Greater)
            } else {
                cmp(&this, &that)
            }
        }
    }

    struct VersionComparator<'a> {
        data: &'a [u8],
    }

    impl<'a> std::fmt::Debug for VersionComparator<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("<")?;
            f.write_str(unsafe { std::str::from_utf8_unchecked(self.data) })?;
            f.write_str(">")
        }
    }

    impl<'a> VersionComparator<'a> {
        #[inline]
        fn advance(&mut self) {
            self.data = &self.data[1..];
        }
        #[inline]
        fn peek(&self) -> Option<u8> {
            if self.data.len() == 0 {
                None
            } else {
                Some(self.data[0])
            }
        }
        #[inline]
        fn peek_at(&self, pos: usize) -> Option<u8> {
            if pos < self.data.len() {
                Some(self.data[pos])
            } else {
                None
            }
        }
        #[inline]
        fn peek_char(&self) -> Option<u8> {
            match self.peek() {
                Some(c)
                    if (c >= b'a' && c <= b'z')
                        || (c >= b'A' && c <= b'Z')
                        || c == b'.'
                        || c == b'-'
                        || c == b'+'
                        || c == b'~' =>
                {
                    Some(c)
                }
                _ => None,
            }
        }
        #[inline]
        fn peek_number(&self, start: u32) -> (u32, usize) {
            let mut result = start;
            let mut pos = 0;
            while pos < self.data.len() && self.data[pos] >= b'0' && self.data[pos] <= b'9' {
                result = result * 10 + (self.data[pos] - b'0') as u32;
                pos += 1;
            }
            (result, pos)
        }
        fn compare_initial(&mut self, other: &mut Self) -> Result<()> {
            let (this_maybe_epoch, this_pos) = self.peek_number(0);
            let (that_maybe_epoch, that_pos) = other.peek_number(0);
            if self.peek_at(this_pos) == Some(b':') {
                // this version contains epoch
                if other.peek_at(that_pos) == Some(b':') {
                    // that version contains epoch, too
                    self.data = &self.data[this_pos + 1..];
                    other.data = &other.data[that_pos + 1..];
                    cmp(&this_maybe_epoch, &that_maybe_epoch)
                } else if this_maybe_epoch > 0 {
                    // that version has no epoch (i.e. epoch 0)
                    Err(Ordering::Greater)
                } else {
                    // a very unlikely epoch 0:
                    self.data = &self.data[this_pos + 1..];
                    Ok(())
                }
            } else if other.peek_at(that_pos) == Some(b':') {
                // only that version has epoch
                if that_maybe_epoch > 0 {
                    Err(Ordering::Less)
                } else {
                    // a very unlikely epoch 0:
                    other.data = &other.data[that_pos + 1..];
                    Ok(())
                }
            } else {
                self.data = &self.data[this_pos..];
                other.data = &other.data[that_pos..];
                cmp(&this_maybe_epoch, &that_maybe_epoch)
            }
        }
        fn compare_alpha(&mut self, other: &mut Self) -> Result<()> {
            loop {
                let this = self.peek_char();
                let that = other.peek_char();
                match this {
                    None => match that {
                        None => break Ok(()),
                        Some(b'~') => break Err(Ordering::Greater),
                        Some(_) => break Err(Ordering::Less),
                    },
                    Some(b'~') => match that {
                        None => break Err(Ordering::Less),
                        Some(b'~') => {
                            self.advance();
                            other.advance();
                            continue;
                        }
                        Some(_) => break Err(Ordering::Greater),
                    },
                    Some(left) => match that {
                        None => break Err(Ordering::Greater),
                        Some(b'~') => break Err(Ordering::Greater),
                        Some(right) => {
                            cmp_alpha(left, right)?;
                            self.advance();
                            other.advance();
                            continue;
                        }
                    },
                }
            }
        }
        fn compare_num(&mut self, other: &mut Self) -> Result<()> {
            let (this_num, this_pos) = self.peek_number(0);
            let (that_num, that_pos) = other.peek_number(0);
            self.data = &self.data[this_pos..];
            other.data = &other.data[that_pos..];
            cmp(&this_num, &that_num)
        }
        fn compare(&mut self, other: &mut Self) -> Result<()> {
            self.compare_initial(other)?;
            while self.data.len() > 0 || other.data.len() > 0 {
                self.compare_alpha(other)?;
                self.compare_num(other)?;
            }
            Ok(())
        }
    }

    pub(super) fn compare(this: &[u8], that: &[u8]) -> Ordering {
        // Check for equality first, as it is significantly faster.
        if this == that {
            Ordering::Equal
        } else {
            let mut this = VersionComparator { data: this };
            let mut that = VersionComparator { data: that };
            match this.compare(&mut that) {
                Ok(()) => Ordering::Equal,
                Err(ord) => ord,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert {
        ($left:tt $op:tt $right:tt) => {
            std::assert!( Version::from($left) $op Version::from($right) )
        }
    }

    macro_rules! satisfies {
        ($left:tt $right:tt) => {
            std::assert!(Version::from($left).satisfies(
                &VersionSet::parse(
                    &mut Parser {
                        inp: $right.as_bytes()
                    },
                    true
                )
                .unwrap()
            ))
        };
    }

    #[test]
    fn test_parse() {
        Dependency::try_from("ac").expect("should be parsed as package name");
        ParsedProvidedNameIterator::new("ac (<< 1.0)")
            .next()
            .unwrap()
            .expect_err("invalid predicate, should fail");
    }

    #[test]
    fn test_requirements() {
        satisfies!("1.0.1" "p (>= 1.0.0)");
        satisfies!("1:1.0" "p (= 1:1.0)");
        satisfies!("2.0.0~rc1" "p (<< 2.0.0)");
    }

    #[test]
    fn test_alpha_compare() {
        assert!("~~" < "~~a");
        assert!("~~a" > "~~");
        assert!("~~a" < "~");
        assert!("~" > "~~a");
        assert!("~" < "");
        assert!("" > "~");
        assert!("" < "a");
        assert!("a" > "");
        assert!("a" < "b");
        assert!("b" > "a");
        assert!("c" < "db");
        assert!("b" < "+a");
    }

    #[test]
    fn test_versions() {
        assert!("2.38.1-5+deb12u2" > "2.38~");
        assert!("2.35.1-1" >= "2.35.1~");
        assert!("2.35.1-1" < "2.35.1A");
        assert!("2" > "1");
        assert!("1:2" > "1:1");
        assert!("1:2.5" > "2.5");
        assert!("1.0.1" > "1.0.0");
        assert!("2.0.1" > "1.0.1");
        assert!("2.0.0" > "2.0.0~rc1");
        assert!("2.0.0~rc2" > "2.0.0~rc1");
        assert!("2.0.0~rc2+u1" > "2.0.0~rc2");
        assert!("1.0.3~rc2+b2" > "1.0.3~rc2+b1");
        assert!("2.0.0" > "2.0.0~b1");
        assert!("2.0.0+u10" > "2.0.0+u9");
        assert!("2.21-9" > "2.19-18+deb8u3");
        assert!("2.21-9" > "2.19-18+deb8u3");
        assert!("2:1.2498-1" > "2:1.2492-4");
        assert!("0.0.0+2016.01.15.git.29cc9e1b05-2+b8" < "0.0.0+2016.02.15.git.29cc9e1b05");
        assert!("6.2.2006+really6.2.1905+dfsg-5.1+b1" == "6.2.2006+really6.2.1905+dfsg-5.1+b1");
    }
}
