use hkdf::Hkdf;
use hmac::Hmac;
use log::debug;
use sequoia_openpgp::{
    cert,
    crypto::{KeyPair, Password},
    policy::StandardPolicy,
    serialize::MarshalInto,
    types::KeyFlags,
    Packet,
};
use sha2::Sha256;

use super::error;
use uuid;

const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

#[cfg(test)]
mod tests {

    use super::*;

    const USERNAME: &str = "erik";
    const PASSWORD: &str = "qwerty";
    /* NOTE: not needed yet
        const UUID: &str = "f76d463c-c4f5-43b5-a26e-f28549e52519";
        const CERT_ARMOR: &str = "\
    -----BEGIN PGP PRIVATE KEY BLOCK-----

    lFgEYPG7rBYJKwYBBAHaRw8BAQdA5o2m68brKVAIRDk8t3ZP6wqzOsxsIifuBrKE
    aFlAo9EAAQCh7deEwMDTz62dQCq+MQ5dnSmV97oBFYiLpJRwNsjaCBDXiMsEHxYK
    AH0FgmDxu6wDCwkHCRDprp7KaSUdP0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5z
    ZXF1b2lhLXBncC5vcmckalvvhB4zXsMZPhhkx9ShucvzAtb/E44GEddpjT2tCQMV
    CggCmwECHgEWIQTlYUzT6rmmCx258iHprp7KaSUdPwAAXWkA/iv8eiWTfp8Zk4Zn
    RBYnumfPDPYD2qyRmYLJzmJiBta6AQC3wSKLRk5/L7jN7OGcCWPEOhdLsQWCugS5
    NjchAGMFDbQEZXJpa4jOBBMWCgCABYJg8busAwsJBwkQ6a6eymklHT9HFAAAAAAA
    HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnAc8wZ0vQH8rp44FLIoqu
    nYo1CQtq+70jtlhcKmypdoQDFQoIApkBApsBAh4BFiEE5WFM0+q5pgsdufIh6a6e
    ymklHT8AAMu+AP4wdplkpHvNc5BHwSrKGNFfWqsRie3myn5ssigJsqKSPwD9Ei/P
    4gYjts9yVii49ElZaYBQA6Kaglzwfas4NtmNGw2cWARg8busFgkrBgEEAdpHDwEB
    B0CXyVuVdSRizHmAAzBeb4PyoQ2oO65BWaWSNVsdSNbDJAAA/1O53tcez/uBtoiu
    Yr3bJMd1ElHSeY9Pwf0Wn67Q6utmFCeJAX8EGBYKATEFgmDxu6wJEOmunsppJR0/
    RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/1i2Q+rbclN
    yrcNJW+1IPzVFmeFp0cgq3ZsPyanWaZIApsCvqAEGRYKAG8FgmDxu6wJEG16kJt4
    v/9ORxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzXa/B6O
    EjfRoK7KK+W0s74xXhjUaebJxv5Bsk5r1viFFiEEiVDeil6oK+3Y4oJwbXqQm3i/
    /04AAAKwAP44hDPVSFbNQ1qGoGn/N2C2rARaGpruPqg6XLNf+/UN5wEA2ZmtD070
    GeKjCvP44lWfMgR+RmGb5wmmiy0soq1GnwwWIQTlYUzT6rmmCx258iHprp7KaSUd
    PwAAR4YA/jcHKz3LYQioM99yp7cJ+TqF0SP5hxC/KZM6kDQspEugAQC69+X2wJKu
    +EGMWS6csMN9T8uXhAvGMu6M1R82A1fEC5xYBGDxu6wWCSsGAQQB2kcPAQEHQMmF
    uXs3NRLsyhyIFn40d3HHOSTwDVTonw28mG5I/iyaAAEA/S9e/FGZ9H5iUksJlhaH
    H83WcAaaD65pGmD3wHUOX30OpojABBgWCgByBYJg8busCRDprp7KaSUdP0cUAAAA
    AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmf1pu4krkTC1AkJT2EI
    5sE/VBY6TWWsGvTdrAxs6dbazQKbIBYhBOVhTNPquaYLHbnyIemunsppJR0/AABX
    1wEA3HLYga8PIHmWbiNKOtUS0aS7k0gx3fpNsf9KOKtD5yoBAL+MdqCh43M8p2bv
    kwbBINVQdND1p3+2hZza9LztNkgNnF0EYPG7rBIKKwYBBAGXVQEFAQEHQFuL5863
    TiVuSLriyo69eqT5/wA/mi9OeyIOlv864sh+AwEICQAA/1BI5ybhHcAU4yBIaog0
    0uph5q9UVIxorRSiPojNU944EJSIwAQYFgoAcgWCYPG7rAkQ6a6eymklHT9HFAAA
    AAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnrxWcFJ7iD8JTe9U+
    /e2TZvd/geFu5AgYQtUB51VDMlYCmwwWIQTlYUzT6rmmCx258iHprp7KaSUdPwAA
    nZwA/jptUcNuWqKMAyDg3XS1K/J2iO6ahqTV2lX4szbtRfO3AQCzA/1VJaFH7hR1
    1pEo/1jN0d6U56iU+YRjiBVtnnHfDw==
    =YKSy
    -----END PGP PRIVATE KEY BLOCK-----
    ";
        const ENCRYPTED_CERT_ARMOR: &str = "\
    -----BEGIN PGP PRIVATE KEY BLOCK-----
    xYYEYPG7rBYJKwYBBAHaRw8BAQdA5o2m68brKVAIRDk8t3ZP6wqzOsxsIifuBrKE
    aFlAo9H+CQMIXSONEFrEUbv/+G/1YosmWZqkY9wuwMcmEelIcjBUf/rY2YMymKF4
    znc21yMO5ZCahjubz/HGSQWKrvtZe4vUna7DEC9bwrKlCOba5hXRcsLACwQfFgoA
    fQWCYPG7rAMLCQcJEOmunsppJR0/RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNl
    cXVvaWEtcGdwLm9yZyRqW++EHjNewxk+GGTH1KG5y/MC1v8TjgYR12mNPa0JAxUK
    CAKbAQIeARYhBOVhTNPquaYLHbnyIemunsppJR0/AABdaQD+K/x6JZN+nxmThmdE
    Fie6Z88M9gParJGZgsnOYmIG1roBALfBIotGTn8vuM3s4ZwJY8Q6F0uxBYK6BLk2
    NyEAYwUNzQRlcmlrwsAOBBMWCgCABYJg8busAwsJBwkQ6a6eymklHT9HFAAAAAAA
    HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnAc8wZ0vQH8rp44FLIoqu
    nYo1CQtq+70jtlhcKmypdoQDFQoIApkBApsBAh4BFiEE5WFM0+q5pgsdufIh6a6e
    ymklHT8AAMu+AP4wdplkpHvNc5BHwSrKGNFfWqsRie3myn5ssigJsqKSPwD9Ei/P
    4gYjts9yVii49ElZaYBQA6Kaglzwfas4NtmNGw3HhgRg8busFgkrBgEEAdpHDwEB
    B0CXyVuVdSRizHmAAzBeb4PyoQ2oO65BWaWSNVsdSNbDJP4JAwjRvr6Zmpv6mf9a
    iGlbnWUDPPFYgEWRX27iKmF5i2M3v8AiL71fodQGO20sz4SNZWqxH8676YwH1eS0
    /figOMJCG3KKWd1TLviVRGFuSo2JwsC/BBgWCgExBYJg8busCRDprp7KaSUdP0cU
    AAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmf9YtkPq23JTcq3
    DSVvtSD81RZnhadHIKt2bD8mp1mmSAKbAr6gBBkWCgBvBYJg8busCRBtepCbeL//
    TkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc12vwejhI3
    0aCuyivltLO+MV4Y1Gnmycb+QbJOa9b4hRYhBIlQ3opeqCvt2OKCcG16kJt4v/9O
    AAACsAD+OIQz1UhWzUNahqBp/zdgtqwEWhqa7j6oOlyzX/v1DecBANmZrQ9O9Bni
    owrz+OJVnzIEfkZhm+cJpostLKKtRp8MFiEE5WFM0+q5pgsdufIh6a6eymklHT8A
    AEeGAP43Bys9y2EIqDPfcqe3Cfk6hdEj+YcQvymTOpA0LKRLoAEAuvfl9sCSrvhB
    jFkunLDDfU/Ll4QLxjLujNUfNgNXxAvHhgRg8busFgkrBgEEAdpHDwEBB0DJhbl7
    NzUS7MociBZ+NHdxxzkk8A1U6J8NvJhuSP4smv4JAwj9Y+h6VejaSP8K5Xq2XSZa
    hGg+kjs4sc2H3/cnOkTS3yxsw06yMUCsAOZw22+Ri1nhn3z+tlHxPeLpUgcjQOZZ
    a89myd7uGe44q7AYTZdUwsAABBgWCgByBYJg8busCRDprp7KaSUdP0cUAAAAAAAe
    ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmf1pu4krkTC1AkJT2EI5sE/
    VBY6TWWsGvTdrAxs6dbazQKbIBYhBOVhTNPquaYLHbnyIemunsppJR0/AABX1wEA
    3HLYga8PIHmWbiNKOtUS0aS7k0gx3fpNsf9KOKtD5yoBAL+MdqCh43M8p2bvkwbB
    INVQdND1p3+2hZza9LztNkgNx4sEYPG7rBIKKwYBBAGXVQEFAQEHQFuL5863TiVu
    SLriyo69eqT5/wA/mi9OeyIOlv864sh+AwEICf4JAwhxugeBHT9uI/9rrYNDLlBt
    xcDZ1FTQhiEEU6bqRYzWdkfqnDSpdjp91wclQBxUE+4PMBQ+0k68g0dnDDZ1rgZn
    kZwVZj6qwXbnlOeWTa0gwsAABBgWCgByBYJg8busCRDprp7KaSUdP0cUAAAAAAAe
    ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmevFZwUnuIPwlN71T797ZNm
    93+B4W7kCBhC1QHnVUMyVgKbDBYhBOVhTNPquaYLHbnyIemunsppJR0/AACdnAD+
    Om1Rw25aoowDIODddLUr8naI7pqGpNXaVfizNu1F87cBALMD/VUloUfuFHXWkSj/
    WM3R3pTnqJT5hGOIFW2ecd8P
    =78LK
    -----END PGP PRIVATE KEY BLOCK-----";
    */

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
    /// The name of the
    pub username: String,
    /// the unique id of the user
    pub uuid: uuid::Uuid,
    /// The pgp key of the user
    cert: cert::Cert,
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
    /// Returns the acutal [`User`] if successful or an [`Error`][`super::error::AuthenticationError`]
    pub fn authenticate(&self, password: String) -> Result<User, error::AuthenticationError> {
        let master_key = derive_master_key(&self.username, &password);
        let _master_password_hash =
            derive_master_password_hash(&self.username, &password, &master_key);
        let _stretched_master_key = derive_stretched_master_key(&master_key);
        // TODO: talk to the server
        Err(error::AuthenticationError::NoConnection)
    }
}

impl UnregisteredUser {
    /// Returns the registered [`User`] or an [`Error`][`super::error::RegistrationError`]
    pub fn register(&self) -> Result<User, error::RegistrationError> {
        // TODO: talk to the server
        Err(super::error::RegistrationError::NoConnection)
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
            .set_password(Some(Password::from(
                &derive_stretched_master_key(&derive_master_key(&username, &password))[..],
            )))
            .generate()
            .unwrap();
        //.expect("Failed to generate pgp key.");
        debug!(
            "PGP public key for {}:\n{}",
            cert.fingerprint(),
            String::from_utf8_lossy(&cert.armored().to_vec().unwrap())
        );
        UnregisteredUser {
            _priv: (),
            username: username.to_string(),
            password: password.to_string(),
            cert,
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
            &derive_stretched_master_key(&derive_master_key(&self.username, &password));
        self.get_subkey_by_keyflag(&stretched_master_key, KeyFlags::empty().set_signing())
    }

    /// A helper function to get the unencrypted encryption subkey of a [`User`]
    /// Since the key is protected by the stretched master key of a user,
    /// we need the password (and the username, but that is stored in the [`User`] struct itself)
    pub fn get_encryption_subkey(&self, password: &str) -> Result<KeyPair, error::KeyError> {
        let stretched_master_key =
            &derive_stretched_master_key(&derive_master_key(&self.username, &password));
        self.get_subkey_by_keyflag(
            &stretched_master_key,
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
            &derive_stretched_master_key(&derive_master_key(&self.username, &password)); // derive stretched master key from master key which is derived from the password
        self.get_subkey_by_keyflag(
            &stretched_master_key,
            KeyFlags::empty().set_authentication(),
        )
    }

    /// Takes the user's password to derive the stretched master secret from and then re-encrypts the certificate with ``export_password``.
    /// The ``export_password`` can be typed in any other pgp program (e.g. gnupg).
    pub fn export_cert(
        &self,
        password: &str,
        export_password: &str,
    ) -> Result<cert::Cert, error::KeyError> {
        let password = &Password::from(
            &derive_stretched_master_key(&derive_master_key(&self.username, password))[..],
        );
        // this will be the password the user can use to decrypt the key in any other pgp application (e.g. gnupg)
        let export_password = &Password::from(export_password);

        // a Vec of all key packets which will then be inserted into the certificate. The other keys will be replaced automatically.
        let keys = std::iter::once(self.cert.primary_key().key().clone())
            // map over the primary key (C)
            .map(|key| {
                let key = key.parts_into_secret()?;
                // decrypt the key
                let key = key.decrypt_secret(password)?;
                // encrypt it again
                Ok(Packet::from(key.encrypt_secret(export_password)?))
            })
            // chain the single interator of the primary togehter with all subkeys
            .chain(self.cert.keys().subkeys().map(|key| {
                let key = key.key().clone().parts_into_secret()?;
                let key = key.decrypt_secret(password)?;
                Ok(Packet::from(key.encrypt_secret(export_password)?))
            }))
            .collect::<sequoia_openpgp::Result<Vec<_>>>();
        match keys {
            Ok(keys) => Ok(self.cert.clone().insert_packets(keys).unwrap()),
            Err(_) => Err(error::KeyError::InvalidKeyPassword),
        }
    }
}
