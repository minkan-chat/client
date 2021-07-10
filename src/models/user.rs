use hkdf::Hkdf;
use hmac::Hmac;
use log::debug;
use sequoia_openpgp::cert;
use sha2::Sha256;


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_master_key_derviation() {
        let password = "qwerty";
        let expected = base64::decode("66Nn+bGSnk0QkWtd3vEiLLzrhiCm3SFkurcpcm+L8GA=").unwrap();
        let got = derive_master_key("erik", &password);
        assert_eq!(expected, got);
    }

    #[test]
    fn test_master_password_hash_derviation() {
        let username = "erik";
        let password = "qwerty";
        let expected = base64::decode("FJ05kkc74dniHi2kzbBMFMD6gfkoIR7PdcLCYc7iUK0=").unwrap();
        let got = derive_master_password_hash(
            &username,
            &password,
            &derive_master_key(&username, &password),
        );
        assert_eq!(expected, got);
    }

    #[test]
    fn test_stretched_master_key_derviation() {
        let username = "erik";
        let password = "qwerty";
        let expected = base64::decode("fwNcXC46Kssud1nN3ManWAeN5L0990ZVPZZ/BHdun+sTJvwf7bZF6eb37hwk1bYS3gLGPqUkzFQK63o5soQ9sw==").unwrap();
        let got = derive_stretched_master_key(&derive_master_key(&username, &password));
        assert_eq!(expected, got);
    }
}
/// Represents an authenticated [`User`]
pub struct User {
    /// The name of the user
    pub username: String,
    /// The pgp key of the user
    pub cert: cert::Cert,
}

/// This struct is used to represent an unauthenticated [`User`]
pub struct UnauthenticatedUser {
    pub username: String,
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
    /// Returns the acutal [`User`]
    pub fn authenticate(&self, password: String)  {
        let master_key = derive_master_key(&self.username, &password);
        let _master_password_hash =
            derive_master_password_hash(&self.username, &password, &master_key);
        let _stretched_master_key = derive_stretched_master_key(&master_key);
    }
}

impl User {
    /// returns an [`UnauthenticatedUser`]
    pub fn new(username: String) -> UnauthenticatedUser {
        UnauthenticatedUser { username }
    }
}
