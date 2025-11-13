use serde::{Deserialize, Serialize};

pub struct KVList<R>(Vec<(String, R)>);

#[allow(dead_code)]
pub trait KVListSet<K, R> {
    fn set(&mut self, k: K, v: R);
    fn push(&mut self, k: K, v: R);
}

impl<R> Clone for KVList<R>
where
    R: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<K, V, R> FromIterator<(K, V)> for KVList<R>
where
    K: Into<String>,
    V: Into<R>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        KVList(
            iter.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl<R> std::fmt::Debug for KVList<R>
where
    R: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<R> Default for KVList<R> {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl<R> KVList<R> {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&'_ str, &'_ R)> {
        self.0.iter().map(|i| (i.0.as_str(), &i.1))
    }
    pub fn iter_keys(&self) -> impl Iterator<Item = &'_ str> {
        self.0.iter().map(|i| i.0.as_str())
    }
    pub fn iter_values(&self) -> impl Iterator<Item = &'_ R> {
        self.0.iter().map(|i| &i.1)
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&'_ str, &'_ mut R)> {
        self.0.iter_mut().map(|i| (i.0.as_str(), &mut i.1))
    }
    pub fn iter_values_mut(&mut self) -> impl Iterator<Item = &'_ mut R> {
        self.0.iter_mut().map(|i| &mut i.1)
    }
    pub fn get(&self, k: &str) -> Option<&'_ R> {
        self.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
    }
    pub fn entry_at(&self, pos: usize) -> (&'_ str, &'_ R) {
        let kv = &self.0[pos];
        (kv.0.as_str(), &kv.1)
    }
    pub fn entry_mut_at(&mut self, pos: usize) -> (&'_ str, &'_ mut R) {
        let kv = &mut (self.0[pos]);
        (kv.0.as_str(), &mut kv.1)
    }
    pub fn key_at(&self, pos: usize) -> &'_ str {
        self.0[pos].0.as_str()
    }
    pub fn value_at(&self, pos: usize) -> &'_ R {
        &self.0[pos].1
    }
    pub fn value_mut_at(&mut self, pos: usize) -> &'_ mut R {
        &mut self.0[pos].1
    }
    pub fn set_at(&mut self, pos: usize, k: String, v: R) {
        self.0[pos] = (k, v);
    }
    pub fn contains_key(&self, k: &str) -> bool {
        self.iter().any(|(n, _)| n == k)
    }
    pub fn remove_at(&mut self, idx: usize) -> (String, R) {
        self.0.remove(idx)
    }
    pub fn drain(&mut self) -> std::vec::Drain<'_, (String, R)> {
        self.0.drain(..)
    }
}

impl<R> From<Vec<(String, R)>> for KVList<R> {
    fn from(v: Vec<(String, R)>) -> Self {
        Self(v)
    }
}

impl<R> IntoIterator for KVList<R> {
    type Item = (String, R);
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<R> KVListSet<&str, R> for KVList<R> {
    fn set(&mut self, k: &str, v: R) {
        if let Some((_, p)) = self.iter_mut().find(|(n, _)| *n == k) {
            *p = v;
            return;
        }
        self.0.push((k.to_string(), v));
    }
    fn push(&mut self, k: &str, v: R) {
        self.0.push((k.to_string(), v));
    }
}

impl<R> KVListSet<String, R> for KVList<R> {
    fn set(&mut self, k: String, v: R) {
        if let Some((_, p)) = self.iter_mut().find(|(n, _)| *n == k.as_str()) {
            *p = v;
            return;
        }
        self.0.push((k, v));
    }
    fn push(&mut self, k: String, v: R) {
        self.0.push((k, v));
    }
}

impl<R> std::ops::Index<usize> for KVList<R> {
    type Output = R;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index].1
    }
}

impl<R> std::ops::IndexMut<usize> for KVList<R> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index].1
    }
}
impl<T: Serialize> Serialize for KVList<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for KVList<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct Visitor<T>(std::marker::PhantomData<T>);

        impl<T> Visitor<T> {
            fn has_name(v: &[(String, T)], n: &str) -> bool {
                v.iter().any(|(k, _)| k == n)
            }
        }

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = KVList<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of items")
            }

            fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                let mut out: Vec<(String, T)> = Vec::with_capacity(access.size_hint().unwrap_or(0));

                while let Some(key) = access.next_key::<String>()? {
                    if Self::has_name(&out, &key) {
                        return Err(A::Error::custom(format!("duplicate item name: {key}")));
                    }
                    let spec = access.next_value::<T>()?;
                    out.push((key, spec));
                }

                Ok(KVList(out))
            }
        }

        deserializer.deserialize_map(Visitor::<T>(std::marker::PhantomData))
    }
}
