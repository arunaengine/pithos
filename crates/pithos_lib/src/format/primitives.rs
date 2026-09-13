use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use integer_encoding::{VarIntReader, VarIntWriter};
use std::io::{Read, Write};

pub(crate) fn write_len_prefix<W: Write>(
    writer: &mut W,
    len: usize,
) -> Result<(), SerializationError> {
    writer.write_varint(
        u64::try_from(len)
            .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?,
    )?;
    Ok(())
}

pub(crate) fn encode_string<W: Write>(
    writer: &mut W,
    value: &str,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, value.len())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

pub(crate) fn bounded_len(
    value: u64,
    limit: u64,
    field: &'static str,
) -> Result<usize, DeserializationError> {
    if value > limit {
        return Err(DeserializationError::LimitExceeded {
            field,
            limit,
            actual: value,
        });
    }
    usize::try_from(value).map_err(|_| DeserializationError::InvalidLength)
}

pub(crate) fn reserve<T>(
    output: &mut Vec<T>,
    count: usize,
    field: &'static str,
) -> Result<(), DeserializationError> {
    output
        .try_reserve(count)
        .map_err(|_| DeserializationError::AllocationFailed {
            field,
            size: count as u64,
        })
}

pub(crate) fn decode_string<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<String, DeserializationError> {
    let len = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_string_bytes,
        "string",
    )?;
    let mut bytes = Vec::new();
    reserve(&mut bytes, len, "string")?;
    bytes.resize(len, 0);
    reader.read_exact(&mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_uleb128_accepts_bounded_non_minimal_values() {
        for (mut encoded, expected) in [
            (&[0x00][..], 0_u64),
            (&[0x7f][..], 127),
            (&[0x80, 0x01][..], 128),
            (&[0x80, 0x00][..], 0),
            (&[0x81, 0x00][..], 1),
        ] {
            assert_eq!(encoded.read_varint::<u64>().unwrap(), expected);
        }
    }

    #[test]
    fn typed_uleb128_rejects_truncated_and_width_overflowing_values() {
        assert!((&[0x80][..]).read_varint::<u64>().is_err());
        assert!(
            (&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02][..])
                .read_varint::<u64>()
                .is_err()
        );
        assert!(
            (&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
            ][..])
                .read_varint::<u64>()
                .is_err()
        );
    }

    #[test]
    fn bounded_string_decode_rejects_truncation_and_limits() {
        let limits = DeserializationLimits {
            max_string_bytes: 2,
            ..DeserializationLimits::default()
        };
        assert_eq!(
            decode_string(&mut &[2, b'o', b'k'][..], &limits).unwrap(),
            "ok"
        );
        assert!(decode_string(&mut &[3, b'o', b'k'][..], &limits).is_err());
        assert!(decode_string(&mut &[2, b'o'][..], &limits).is_err());
    }
}
