use bytes::Bytes;

use graphql_client::GraphQLQuery;
use hkdf::Hkdf;
use hmac::Hmac;
use log::debug;
use sequoia_openpgp::{
    cert,
    crypto::{KeyPair, Password},
    packet::prelude::SignatureBuilder,
    parse::Parse,
    policy::StandardPolicy,
    serialize::MarshalInto,
    types::{KeyFlags, SignatureType},
    Packet,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::graphql::{
    mutations::{Authenticate, AuthenticationCredentialsUserInput, Signup, SignupUserInput},
    perform_query,
    queries::GetChallenge,
};

use super::{error, TokenPair};

const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

#[cfg(test)]
mod tests {

    use super::*;

    const USERNAME: &str = "erik";
    const PASSWORD: &str = "qwerty";

    #[test]
    fn test_master_key_derviation() {
        let expected = base64::decode("66Nn+bGSnk0QkWtd3vEiLLzrhiCm3SFkurcpcm+L8GA=").unwrap();
        let got = derive_master_key("erik", &PASSWORD);
        assert_eq!(expected, got);
    }

    #[test]
    fn test_master_password_hash_derviation() {
        let expected = base64::decode("FJ05kkc74dniHi2kzbBMFMD6gfkoIR7PdcLCYc7iUK0=").unwrap();
        let got = derive_master_password_hash(
            &USERNAME,
            &PASSWORD,
            &derive_master_key(&USERNAME, &PASSWORD),
        );
        assert_eq!(expected, got);
    }

    #[test]
    fn test_stretched_master_key_derviation() {
        let expected = base64::decode("fwNcXC46Kssud1nN3ManWAeN5L0990ZVPZZ/BHdun+sTJvwf7bZF6eb37hwk1bYS3gLGPqUkzFQK63o5soQ9sw==").unwrap();
        let got = derive_stretched_master_key(&derive_master_key(&USERNAME, &PASSWORD));
        assert_eq!(expected, got);
    }
}
/// Represents an authenticated [`User`]
#[derive(Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct User {
    /// The (login) name of the user
    #[serde(rename = "name")]
    pub username: String,
    /// the unique id of the user
    #[serde(rename = "id")]
    // FIXME: use uuid crate on the server side so this can be deserialized with cbor without pain.
    // Currently, it expects a bytearray but since the scalar ID of async_graphql is ID(String) instead of ID(uuid)
    // it always gets a string. This works with serde_json but not with serde_cbor
    pub uuid: String,
    /// The pgp key of the user
    #[serde(
        rename = "certificate",
        serialize_with = "serialize_cert",
        deserialize_with = "deserialize_cert"
    )]
    pub cert: cert::Cert,
    /// The token pair used for authentication
    pub token: TokenPair,
}

/// Serializes the public parts of a [``sequoia_openpgp::cert::Cert``]
fn serialize_cert<S>(cert: &cert::Cert, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    ser.serialize_bytes(
        &cert
            .to_vec()
            .map_err(<S::Error as serde::ser::Error>::custom)?,
    )
}

/// Serializes the public AND private parts of a [``sequoia_openpgp::cert::Cert``]
fn serialize_cert_secret<S>(cert: &cert::Cert, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    ser.serialize_bytes(
        &cert
            .as_tsk()
            .to_vec()
            .map_err(<S::Error as serde::ser::Error>::custom)?,
    )
}

/// Deserializes a [``sequoia_openpgp::cert::Cert``] and includes secret parts if present
fn deserialize_cert<'de, D>(de: D) -> Result<cert::Cert, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    #[derive(Debug, Deserialize)]
    #[serde(rename = "certificate")]
    struct Repr {
        content: Bytes,
    }
    let repr = Repr::deserialize(de)?;

    cert::Cert::from_bytes(&repr.content).map_err(<D::Error as serde::de::Error>::custom)
}

/// This struct is used to represent an unauthenticated [`User`]
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct UnauthenticatedUser {
    #[serde(rename = "name")]
    pub username: String,
    #[serde(rename = "hash")]
    master_password_hash: [u8; 32],
    #[serde(skip)]
    stretched_master_key: [u8; 64],
}

/// This struct is used during registration of a new [`User`].
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct UnregisteredUser {
    #[serde(rename = "name")]
    pub username: String,
    #[serde(rename = "hash")]
    master_password_hash: [u8; 32],
    #[serde(serialize_with = "serialize_cert_secret", rename = "certificate")]
    pub cert: cert::Cert,
    challenge: String,
    signature: Bytes,
}

/// Uses hkdf to construct the stretched master key. Derivation is done by generating two hkdfs with different info paramters.
/// Our refernce implementation [bitwarden](https://bitwarden.com/help/article/bitwarden-security-white-paper/#overview-of-the-master-password-hashing-key-derivation-and-encryption-process) does this (we don't know exactly why) and so do we.
/// It should definitively not decrease security.
pub fn derive_stretched_master_key(master_key: &[u8; 32]) -> [u8; 64] {
    let mut okm = [0u8; 64];

    // divide `okm` into two parts so we can use two different info values.
    let (mut first_half, mut second_half) = okm.split_at_mut(32);

    let h =
        Hkdf::<Sha256>::from_prk(master_key).expect("Master key to derive prk from is invalid.");
    debug!("Generating stretched master key");
    h.expand("enc".as_bytes(), &mut first_half)
        .expect("Failed to derive first 32 bytes of stretched master key");
    h.expand("mac".as_bytes(), &mut second_half)
        .expect("Failed to derive last 32 bytes of stretched master key");
    debug!("Done generating stretched master key");

    okm
}

/// Uses pbkdf2_sha256(password: password, salt: username, rounds: 100_000)
pub fn derive_master_key(username: &str, password: &str) -> [u8; 32] {
    let rounds = 100_000;
    let mut result = [0u8; 32];
    debug!("Generating master key for {}...", username);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        username.as_bytes(),
        rounds,
        &mut result,
    );
    debug!("Done generating master key for {}", username);
    result
}

/// Uses the generated master key to further derive a hash using pbkdf2_sha256(password: master_key, salt: password, rounds: 1)
/// The resulting hash is sent to the server for authentication
pub fn derive_master_password_hash(
    username: &str,
    password: &str,
    master_key: &[u8; 32],
) -> [u8; 32] {
    let rounds = 1;
    let mut result = [0u8; 32];
    debug!("Generating master password hash for {}...", &username);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(master_key, password.as_bytes(), rounds, &mut result);
    debug!("Done generating master password hash for {}", &username);
    result
}

impl UnauthenticatedUser {
    /// Returns the acutal [`User`] if successful or an [`Error`][`super::error::AuthenticationError`]
    pub async fn authenticate(self) -> Result<User, Vec<error::AuthenticationError>> {
        perform_query::<Authenticate>(Authenticate::build_query(
            AuthenticationCredentialsUserInput { credentials: self },
        ))
        .await
        .map_err(|_| vec![super::error::AuthenticationError::NoConnection])?
        .data
        .expect("The provided query is invalid")
        .result
    }
}

impl UnregisteredUser {
    /// Returns the registered [`User`] or a [`Vec<super::error::SignupError>`]
    pub async fn register(self) -> Result<User, Vec<error::SignupError>> {
        perform_query::<Signup>(Signup::build_query(SignupUserInput { user: self }))
            .await
            .map_err(|_| vec![super::error::SignupError::NoConnection])?
            .data
            .expect("The provided query is invalid")
            .result
    }
}
impl User {
    /// Returns an [`UnauthenticatedUser`].
    pub fn login(username: &str, password: &str) -> UnauthenticatedUser {
        let master_key = derive_master_key(username, password);
        let master_password_hash = derive_master_password_hash(username, password, &master_key);
        let stretched_master_key = derive_stretched_master_key(&master_key);

        UnauthenticatedUser {
            username: username.to_string(),
            master_password_hash,
            stretched_master_key,
        }
    }

    /// Returns an [`UnregisteredUser`].
    /// This function is used to abstract key generation.
    /// To complete the registration and send the keys to the server, call [`UnregisteredUser::register`].
    pub async fn create(username: &str, password: &str) -> anyhow::Result<UnregisteredUser> {
        // TODO: spawn extra thread so the non-async crypto stuff won't block everything
        let master_key = derive_master_key(username, password);
        let stretched_master_key = derive_stretched_master_key(&master_key);
        let master_password_hash = derive_master_password_hash(username, password, &master_key);

        // Discare the revocation certificate because as we won't lose the key as long as the user does not forget their password.
        // In this case, it would make sense to store a revocation certificate, but because we would need to store it encrypted with the user's password, it doesn't make sense.
        // If we won't store it unprotected, because such a revocation certificate could be used in an attack too, e.g. by destroying the trust other users have to the user.
        let (cert, _) = cert::CertBuilder::new()
            // For now, the userid in the key is just the username
            .add_userid(username)
            // We are using cv 25519 as the key algorithm because we want to be compliant to the Signal and MLS standard for the identity key.
            // Curve 25519 is supported by many pgp implementations (e.g. gnupg) and will be in the next pgp standard.
            // The idea is to use this as the long term identity key as per https://signal.org/docs/specifications/x3dh/#keys (IK_A and IK_B).
            .set_cipher_suite(cert::CipherSuite::Cv25519)
            // The primary key is only used for certification (C)
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            // validity and cipher suite are all equal to the one of the primary key (CV2519)
            // The first subkey is used for signing (S)
            .add_subkey(KeyFlags::empty().set_signing(), None, None)
            // The second key is used for encryption (E)
            .add_subkey(
                KeyFlags::empty()
                    .set_storage_encryption()
                    .set_transport_encryption(),
                None,
                None,
            )
            // The third key is used for authentication (A)
            .add_subkey(KeyFlags::empty().set_authentication(), None, None)
            // we provide the stretched master key as the password for the pgp key.
            .set_password(Some(Password::from(&stretched_master_key[..])))
            .generate()?;
        //.expect("Failed to generate pgp key.");
        debug!(
            "PGP public key for {}:\n{}",
            cert.fingerprint(),
            String::from_utf8_lossy(&cert.armored().to_vec().unwrap())
        );

        if let Some(data) = perform_query::<GetChallenge>(GetChallenge::build_query(()))
            .await?
            .data
        {
            debug!("Challenge from server: {}", data.challenge);

            let mut signer = cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()?
                .decrypt_secret(&Password::from(&stretched_master_key[..]))?
                .into_keypair()?;
            let sig = SignatureBuilder::new(SignatureType::Text)
                .sign_message(&mut signer, &data.challenge)?
                .to_vec()?;

            Ok(UnregisteredUser {
                username: username.into(),
                master_password_hash,
                cert,
                challenge: data.challenge,
                signature: sig.into(),
            })
        } else {
            Err(anyhow::anyhow!("Failed to get challenge from server."))
        }
    }

    /// A private helper function to prevent code duplication.
    ///
    /// The function filters a Certificate by the provided ``KeyFlags`` and returns the keypair (secret and public key)
    /// or an error.
    fn get_subkey_by_keyflag(
        &self,
        stretched_master_key: &[u8; 64],
        flags: KeyFlags,
    ) -> Result<KeyPair, error::KeyError> {
        // filter by the key flags
        let s = self
            .cert
            .keys()
            .with_policy(STANDARD_POLICY, None)
            .alive()
            .revoked(false)
            .secret() // we only want a key which has a secret part
            .key_flags(flags) // and that matches the specified ``flags``
            .next(); // and we get the first one (should be only one anyway)
        match s
            .ok_or(error::KeyError::NoSuchKey)?
            .component()
            .clone()
            .decrypt_secret(&Password::from(&stretched_master_key[..]))
        {
            Ok(k) => Ok(k
                .into_keypair()
                .expect("A user's cert should have both keys.")),
            _ => Err(error::KeyError::InvalidKeyPassword), // we ain't able to decrypt the key
        }
    }

    /* TODO: write tests for this
    /// Helper function to return the raw key bytes of a [`sequoia_openpgp::crypto::KeyPair`]
    pub fn get_keypair_bytes(key: &KeyPair) -> Result<Vec<u8>, error::KeyError> {
        // the only way to access the inner scalar is to map over the enum
        key.secret().map(|s| match s {
            // operations which involve encryption/decryption
            sequoia_openpgp::crypto::mpi::SecretKeyMaterial::EdDSA { scalar } => {
                Ok(scalar.value().to_vec())
            }
            // used for operations which involve signing (authentication, signing and certification)
            sequoia_openpgp::crypto::mpi::SecretKeyMaterial::ECDH { scalar } => {
                Ok(scalar.value().to_vec())
            }
            _ => Err(error::KeyError::InvalidKeyAlgo),
        })
    }
    */

    /// A helper function to get the unencrypted signing subkey of a [`User`].
    /// Since the key is protected by the stretched master key of a user,
    /// we need the password (and the username, but that is stored in the [`User`] struct itself)
    pub fn get_signing_subkey(&self, password: &str) -> Result<KeyPair, error::KeyError> {
        let stretched_master_key =
            &derive_stretched_master_key(&derive_master_key(&self.username, password));
        self.get_subkey_by_keyflag(stretched_master_key, KeyFlags::empty().set_signing())
    }

    /// A helper function to get the unencrypted encryption subkey of a [`User`]
    /// Since the key is protected by the stretched master key of a user,
    /// we need the password (and the username, but that is stored in the [`User`] struct itself)
    pub fn get_encryption_subkey(&self, password: &str) -> Result<KeyPair, error::KeyError> {
        let stretched_master_key =
            &derive_stretched_master_key(&derive_master_key(&self.username, password));
        self.get_subkey_by_keyflag(
            stretched_master_key,
            KeyFlags::empty()
                .set_storage_encryption()
                .set_transport_encryption(),
        )
    }

    /// A helper function to get the unencrypted authentication subkey of a [`User`].
    /// Since the key is protected by the stretched master key of a user,
    /// we need the password (and the username, but that is stored in the [`User`] struct itself)
    pub fn get_authentication_subkey(&self, password: &str) -> Result<KeyPair, error::KeyError> {
        let stretched_master_key =
            &derive_stretched_master_key(&derive_master_key(&self.username, password)); // derive stretched master key from master key which is derived from the password
        self.get_subkey_by_keyflag(stretched_master_key, KeyFlags::empty().set_authentication())
    }
}

/// Takes the user's password to derive the stretched master secret from and then re-encrypts the certificate with ``export_password``.
/// The ``export_password`` can be typed in any other pgp program (e.g. gnupg).
pub fn export_cert(
    cert: &cert::Cert,
    username: &str,
    password: &str,
    export_password: &str,
) -> Result<cert::Cert, error::KeyError> {
    let password =
        &Password::from(&derive_stretched_master_key(&derive_master_key(username, password))[..]);
    // this will be the password the user can use to decrypt the key in any other pgp application (e.g. gnupg)
    let export_password = &Password::from(export_password);

    // a Vec of all key packets which will then be inserted into the certificate. The other keys will be replaced automatically.
    let keys = std::iter::once(cert.primary_key().key().clone())
        // map over the primary key (C)
        .map(|key| {
            let key = key.parts_into_secret()?;
            // decrypt the key
            let key = key.decrypt_secret(password)?;
            // encrypt it again
            Ok(Packet::from(key.encrypt_secret(export_password)?))
        })
        // chain the single interator of the primary togehter with all subkeys
        .chain(cert.keys().subkeys().map(|key| {
            let key = key.key().clone().parts_into_secret()?;
            let key = key.decrypt_secret(password)?;
            Ok(Packet::from(key.encrypt_secret(export_password)?))
        }))
        .collect::<sequoia_openpgp::Result<Vec<_>>>();
    match keys {
        Ok(keys) => Ok(cert.clone().insert_packets(keys).unwrap()),
        Err(_) => Err(error::KeyError::InvalidKeyPassword),
    }
}
