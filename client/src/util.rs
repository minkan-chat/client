//! Helper methods

use sequoia_openpgp::{parse::Parse, serialize::SerializeInto, Cert};
use serde::{Deserialize, Deserializer, Serializer};

/// A helper method to serialize a [`Cert`] with serde.
///
/// **This method will always include secret key material if there is some**
pub fn serialize_cert<S>(cert: &Cert, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_bytes(
        &cert
            .as_tsk()
            .export_to_vec()
            .map_err(<S::Error as serde::ser::Error>::custom)?,
    )
}

/// A helper method to deserialize a [`Cert`] with serde
pub fn deserialize_cert<'de, D>(de: D) -> Result<Cert, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    // this represents the `certificate` field in an [`crate::actor::Actor`]
    #[serde(rename = "certificate")]
    struct Repr {
        body: bytes::Bytes,
    }
    let repr = Repr::deserialize(de)?;

    Cert::from_bytes(&repr.body).map_err(<D::Error as serde::de::Error>::custom)
}

/// A helper method to deserialize a [`Cert`] with serde which returns a [`Box`]
pub fn deserialize_cert_box<'de, D>(de: D) -> Result<Box<Cert>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_cert::<'de>(de).map(Box::new)
}
