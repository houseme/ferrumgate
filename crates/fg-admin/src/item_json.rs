use std::{borrow::Cow, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{
        DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, Visitor,
        value::{BorrowedStrDeserializer, MapAccessDeserializer, StringDeserializer},
    },
};

pub(super) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    view_only: &[&str],
) -> serde_json::Result<T> {
    if view_only.is_empty() {
        return serde_json::from_slice(bytes);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let item = deserializer.deserialize_map(Item {
        view_only,
        output: PhantomData,
    })?;
    deserializer.end()?;
    Ok(item)
}

struct Item<'a, T> {
    view_only: &'a [&'a str],
    output: PhantomData<T>,
}

impl<'de, T: DeserializeOwned> Visitor<'de> for Item<'_, T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON item object")
    }

    fn visit_map<A: MapAccess<'de>>(self, source: A) -> Result<T, A::Error> {
        T::deserialize(MapAccessDeserializer::new(Writable {
            source,
            view_only: self.view_only,
        }))
    }
}

struct Writable<'a, A> {
    source: A,
    view_only: &'a [&'a str],
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Field<'a>(#[serde(borrow)] Cow<'a, str>);

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Writable<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        while let Some(Field(name)) = self.source.next_key::<Field<'de>>()? {
            if self.view_only.contains(&name.as_ref()) {
                self.source.next_value::<IgnoredAny>()?;
                continue;
            }
            return match name {
                Cow::Borrowed(name) => seed.deserialize(BorrowedStrDeserializer::new(name)),
                Cow::Owned(name) => seed.deserialize(StringDeserializer::new(name)),
            }
            .map(Some);
        }
        Ok(None)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.source.next_value_seed(seed)
    }
}
