use std::{
    borrow::Borrow,
    cell::UnsafeCell,
    collections::HashMap,
    hash::{Hash, Hasher},
    ops::Index,
};

pub(crate) trait IntoId<Id> {
    fn into_id(self) -> Id;
}
pub(crate) trait ToIndex {
    fn to_index(&self) -> usize;
}

impl IntoId<u32> for usize {
    fn into_id(self) -> u32 {
        self as u32
    }
}
impl ToIndex for u32 {
    fn to_index(&self) -> usize {
        *self as usize
    }
}

impl IntoId<usize> for usize {
    fn into_id(self) -> usize {
        self
    }
}
impl ToIndex for usize {
    fn to_index(&self) -> usize {
        *self
    }
}

#[derive(Debug)]
pub(crate) enum UpdateResult<T> {
    Inserted(T),
    Updated(T),
}

impl<T> UpdateResult<T> {
    pub(crate) fn unwrap(self) -> T {
        match self {
            UpdateResult::Updated(value) => value,
            UpdateResult::Inserted(value) => value,
        }
    }
}
impl Into<u32> for UpdateResult<u32> {
    fn into(self) -> u32 {
        self.unwrap()
    }
}
impl<T: ToIndex> Into<usize> for UpdateResult<T> {
    fn into(self) -> usize {
        self.unwrap().to_index()
    }
}

macro_rules! id_type {
    ($name:ident) => {
        impl IntoId<$name> for usize {
            fn into_id(self) -> $name {
                $name(self as u32)
            }
        }
        impl ToIndex for $name {
            fn to_index(&self) -> usize {
                self.0 as usize
            }
        }
        impl Into<$name> for UpdateResult<$name> {
            fn into(self: UpdateResult<$name>) -> $name {
                self.unwrap()
            }
        }
    };
}
pub(crate) use id_type;

const BLOCK_SIZE: usize = 4096;

pub(crate) struct HashRef<T: Hash + Eq + ?Sized> {
    ptr: *const T,
}
impl<T: Hash + Eq + ?Sized> Borrow<T> for HashRef<T> {
    fn borrow(&self) -> &T {
        unsafe { &*self.ptr }
    }
}
impl<T: Hash + Eq + ?Sized> Borrow<T> for HashRef<Box<T>> {
    fn borrow(&self) -> &T {
        unsafe { (&*self.ptr).as_ref() }
    }
}
impl<T: Hash + Eq + ?Sized> std::ops::Deref for HashRef<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}
impl<T: Hash + Eq + ?Sized> Hash for HashRef<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unsafe { (&*self.ptr).hash(state) }
    }
}
impl<T: Hash + Eq + ?Sized> PartialEq<T> for HashRef<Box<T>> {
    fn eq(&self, other: &T) -> bool {
        PartialEq::eq(unsafe { (&*self.ptr).as_ref() }, other)
    }
}
impl<T: Hash + Eq + ?Sized> PartialEq for HashRef<T> {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(unsafe { &*self.ptr }, unsafe { &*other.ptr })
    }
}
impl<T: Hash + Eq + ?Sized> Eq for HashRef<T> {}
impl<T: Hash + Eq + ?Sized> From<&T> for HashRef<T> {
    fn from(value: &T) -> Self {
        Self { ptr: value }
    }
}

pub(crate) struct IdMap<IdMap, Value: Hash + Eq> {
    arena: UnsafeCell<Vec<Box<Vec<Value>>>>,
    index: UnsafeCell<HashMap<HashRef<Value>, IdMap>>,
}

impl<IdType, Value: std::fmt::Debug + Hash + Eq> std::fmt::Debug for IdMap<IdType, Value> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        unsafe {
            let arena = &mut *self.arena.get();
            let size = if arena.len() == 0 {
                return Ok(());
            } else {
                let al = arena.len() - 1;
                (al * BLOCK_SIZE) + arena[al].len()
            };
            f.write_str("[")?;
            for i in 0..size {
                let bi = i / BLOCK_SIZE;
                let ii = i % BLOCK_SIZE;
                if i != 0 {
                    f.write_str("\n ")?;
                }
                write!(f, "{:?}={:?}", i, &arena[bi][ii])?;
            }
            f.write_str("\n]")
        }
    }
}

impl<IdType, Value> Default for IdMap<IdType, Value>
where
    Value: Hash + Eq,
    IdType: Copy + ToIndex,
    usize: IntoId<IdType>,
{
    fn default() -> Self {
        Self::new()
    }
}

//impl<IdType, Value, Src> From<Src> for IdMap<IdType, Value>
//where
//    Src: IntoIterator<Item = Value>,
//    Value: Hash + Eq,
//    IdType: Copy + ToIndex,
//    usize: IntoId<IdType>,
//{
//    fn from(source: Src) -> Self {
//        let ret = Self::new();
//        for item in source.into_iter() {
//            ret.insert(item);
//        }
//        ret
//    }
//}
//
impl<IdType, Value> IdMap<IdType, Value>
where
    Value: Hash + Eq,
    IdType: Copy + ToIndex,
    usize: IntoId<IdType>,
{
    pub(crate) fn new() -> Self {
        Self {
            arena: UnsafeCell::new(vec![]),
            index: UnsafeCell::new(HashMap::new()),
        }
    }
    pub(crate) fn get<K: Hash + Eq + ?Sized>(&self, item: &K) -> Option<IdType>
    where
        HashRef<Value>: Borrow<K>,
    {
        unsafe { (&*self.index.get()).get(item).map(|id| *id) }
    }
    fn insert(&self, item: Value) -> IdType {
        unsafe {
            let map = &mut *self.index.get();
            let arena = &mut *self.arena.get();
            let size = if arena.len() == 0 {
                0
            } else {
                let al = arena.len() - 1;
                (al * BLOCK_SIZE) + arena[al].len()
            };
            let bi = size / BLOCK_SIZE;
            let ii = size % BLOCK_SIZE;
            if ii == 0 {
                arena.push(Box::new(Vec::with_capacity(BLOCK_SIZE)))
            }
            arena[bi].push(item);
            let item_ref = &arena[bi][ii];
            let id: IdType = size.into_id();
            map.insert(HashRef::from(item_ref), id);
            id
        }
    }
    pub(crate) fn get_or_insert(&self, item: Value) -> IdType {
        self.get(&HashRef::from(&item))
            .unwrap_or_else(|| self.insert(item))
    }
    pub(crate) unsafe fn insert_or_update<K, Fi, Fu>(
        &self,
        key: &K,
        insert: Fi,
        update: Fu,
    ) -> UpdateResult<IdType>
    where
        K: Hash + Eq + ?Sized,
        HashRef<Value>: Borrow<K>,
        Fi: FnOnce() -> Value,
        Fu: FnOnce(&mut Value) -> (),
    {
        match self.get(key) {
            None => UpdateResult::Inserted(self.insert(insert())),
            Some(id) => {
                let bi = id.to_index() / BLOCK_SIZE;
                let ii = id.to_index() % BLOCK_SIZE;
                unsafe {
                    let arena = &mut *self.arena.get();
                    update(&mut arena[bi][ii])
                }
                UpdateResult::Updated(id)
            }
        }
    }
}

//impl<IdType, Value> IdMap<IdType, Value>
//where
//    Value: Hash + Eq + Sized,
//    IdType: Copy + ToIndex,
//    usize: IntoId<IdType>,
//{
//    pub(crate) fn intern<V>(&self, value: V) -> InternResult<IdType, &Value>
//    where
//        V: IntoBoxed<Value> + AsRef<Value>,
//    {
//        let id = self
//            .get(&value)
//            .unwrap_or_else(|| self.insert(value));
//        InternResult { id, val: self[id].as_ref() }
//    }
//}

impl<IdType, Value> IdMap<IdType, Box<Value>>
where
    Value: Hash + Eq + ?Sized,
    IdType: Copy + ToIndex,
    usize: IntoId<IdType>,
{
    pub(crate) fn intern<V>(&self, value: V) -> InternResult<IdType, &Value>
    where
        V: IntoBoxed<Value> + AsRef<Value>,
    {
        let id = self
            .get(value.as_ref())
            .unwrap_or_else(|| self.insert(value.into_boxed()));
        InternResult { id, val: self[id].as_ref() }
    }
}

impl<IdType, Value, Src, I> From<Src> for IdMap<IdType, Box<Value>>
where
    I: IntoBoxed<Value>,
    Src: IntoIterator<Item = I>,
    Value: Hash + Eq + ?Sized,
    IdType: Copy + ToIndex,
    usize: IntoId<IdType>,
{
    fn from(source: Src) -> Self {
        let ret = Self::new();
        for item in source.into_iter() {
            ret.insert(item.into_boxed());
        }
        ret
    }
}

pub(crate) struct InternResult<IdType, Value> {
    id: IdType,
    val: Value,
}
impl<IdType, Value> InternResult<IdType, Value> {
    pub(crate) fn as_ref(self) -> Value {
        self.val
    }
    pub(crate) fn as_id(self) -> IdType {
        self.id
    }
}

pub(crate) trait IntoBoxed<Value> 
where
    Value: Hash + Eq + ?Sized,
{
    fn into_boxed(self) -> Box<Value>;
}

impl<I: Hash + Eq + Clone> IntoBoxed<[I]> for &[I] {
    fn into_boxed(self) -> Box<[I]> {
        Vec::from(self).into_boxed_slice()
    }
}

impl<S: AsRef<str>> IntoBoxed<str> for &S {
    fn into_boxed(self) -> Box<str> {
        self.as_ref().to_string().into_boxed_str()
    }
}

impl IntoBoxed<str> for &str {
    fn into_boxed(self) -> Box<str> {
        self.to_string().into_boxed_str()
    }
}

impl IntoBoxed<str> for String {
    fn into_boxed(self) -> Box<str> {
        self.into_boxed_str()
    }
}

impl<IdType, Value> Index<IdType> for IdMap<IdType, Value>
where
    Value: Hash + Eq,
    IdType: Copy + ToIndex,
{
    type Output = Value;
    fn index(&self, index: IdType) -> &Self::Output {
        let bi = index.to_index() / BLOCK_SIZE;
        let ii = index.to_index() % BLOCK_SIZE;
        unsafe {
            let arena = &*self.arena.get();
            &arena[bi][ii]
        }
    }
}
