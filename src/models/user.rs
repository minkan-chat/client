use hkdf::Hkdf;
use hmac::Hmac;
use log::debug;
use sequoia_openpgp::{cert, crypto, types::KeyFlags};
use sha2::Sha256;

use super::errors;

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
#[derive(Debug)]
pub struct User {
    _priv: (),
    /// The name of the user
    pub username: String,
    /// The pgp key of the user
    pub cert: cert::Cert,
}

/// This struct is used to represent an unauthenticated [`User`]
#[derive(Debug)]
pub struct UnauthenticatedUser {
    _priv: (),
    pub username: String,
}

/// This struct is used during registration of a new [`User`].
#[derive(Debug)]
pub struct UnregisteredUser {
    _priv: (),
    pub username: String,
    pub password: String,
    pub cert: cert::Cert,
}

/// Uses hkdf to construct the stretched master key. Derivation is done by generating two hkdfs with different info paramters.
/// Our refernce implementation [bitwarden](https://bitwarden.com/help/article/bitwarden-security-white-paper/#overview-of-the-master-password-hashing-key-derivation-and-encryption-process) does this (we don't know exactly why) and so do we.
/// It should definitively not decrease security.
fn derive_stretched_master_key(master_key: &[u8; 32]) -> [u8; 64] {
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
fn derive_master_key(username: &str, password: &str) -> [u8; 32] {
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
fn derive_master_password_hash(username: &str, password: &str, master_key: &[u8; 32]) -> [u8; 32] {
    let rounds = 1;
    let mut result = [0u8; 32];
    debug!("Generating master password hash for {}...", &username);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(master_key, &password.as_bytes(), rounds, &mut result);
    debug!("Done generating master password hash for {}", &username);
    result
}

impl UnauthenticatedUser {
    /// Returns the acutal [`User`] if successful or an [`Error`][`super::errors::AuthenticationError`]
    pub fn authenticate(&self, password: String) -> Result<User, errors::AuthenticationError> {
        let master_key = derive_master_key(&self.username, &password);
        let _master_password_hash =
            derive_master_password_hash(&self.username, &password, &master_key);
        let _stretched_master_key = derive_stretched_master_key(&master_key);
        Err(errors::AuthenticationError::NoConnection)
    }
}

impl UnregisteredUser {
    /// Returns the registered [`User`] or an [`Error`][`super::errors::RegistrationError`]
    pub fn register(&self) -> Result<User, errors::RegistrationError> {
        // TODO: talk to the server
        Ok(User {
            _priv: (),
            cert: self.cert.clone(),
            username: self.username.clone(),
        })
    }
}
impl User {
    /// Returns an [`UnauthenticatedUser`].
    pub fn new(username: &str) -> UnauthenticatedUser {
        UnauthenticatedUser {
            _priv: (),
            username: username.to_string(),
        }
    }

    /// Returns an [`UnregisteredUser`].
    /// This function is used to abstract key generation. 
    /// To complete the registration and send the keys to the server, call [`UnregisteredUser::register`].
    pub fn create(username: &str, password: &str) -> UnregisteredUser {
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
            .add_subkey(KeyFlags::empty().set_storage_encryption().set_transport_encryption(), None, None)
            // The third key is used for authentication (A)
            .add_subkey(KeyFlags::empty().set_authentication(), None, None)
            // we provide the stretched master key as the password for the pgp key.
            .set_password(Some(crypto::Password::from(
                &derive_stretched_master_key(&derive_master_key(&username, &password))[..],
            )))
            .generate()
            .expect("Failed to generate pgp key.");
        debug!("PGP key fingerprint: {}", cert.fingerprint());
        UnregisteredUser {
            _priv: (),
            username: username.to_string(),
            password: password.to_string(),
            cert,
        }
    }
}
