use serde::ser::SerializeSeq;
use serde::{self, Deserializer, Serializer};

pub fn serialize<S>(types: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match types.len() {
        1 => serializer.serialize_str(&types[0]),
        _ => {
            let mut seq = serializer.serialize_seq(Some(types.len()))?;
            for t in types {
                seq.serialize_element(t)?;
            }
            seq.end()
        }
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut types = Vec::new();
            while let Some(t) = seq.next_element()? {
                types.push(t);
            }
            Ok(types)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}
