#![allow(dead_code)]

use argon2::password_hash::SaltString;
use argon2::{password_hash, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use blake2::{Blake2b512, Digest};
use tokio::task;

use crate::secret_box::{self, SecretBox};
use crate::Result;

pub struct Hasher {
    pepper: String,
}

impl Hasher {
    pub fn new(pepper: String) -> Hasher {
        Hasher { pepper }
    }

    pub async fn hash(&self, user_id: String, password: String) -> Result<Vec<u8>> {
        let key = self.kdf(user_id).await?;
        let secret_box = SecretBox::new(&key).unwrap();

        let hash = task::spawn_blocking(move || {
            let salt = SaltString::generate(rand::thread_rng());
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string().into_bytes())
        })
        .await??;

        Ok(secret_box.seal(&hash))
    }

    pub async fn verify(&self, user_id: String, password: String, hash: Vec<u8>) -> Result<bool> {
        let key = self.kdf(user_id).await?;
        let secret_box = SecretBox::new(&key).unwrap();

        let Ok(decrypted_hash) = secret_box.open(&hash) else {
            return Ok(false);
        };

        let Ok(hash_string) = String::from_utf8(decrypted_hash) else {
            return Ok(false);
        };

        task::spawn_blocking(move || {
            let hash = PasswordHash::new(&hash_string)?;

            match Argon2::default().verify_password(password.as_bytes(), &hash) {
                Ok(()) => Ok(true),
                Err(password_hash::Error::Password) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await?
    }
}

impl Hasher {
    async fn kdf(&self, user_id: String) -> Result<[u8; secret_box::KEY_BYTES]> {
        let mut key = [0; secret_box::KEY_BYTES];

        let mut salt_hasher = Blake2b512::new();
        salt_hasher.update(user_id.as_bytes());
        let salt = salt_hasher.finalize();

        let pepper = self.pepper.clone();

        task::spawn_blocking(move || {
            Argon2::default().hash_password_into(pepper.as_bytes(), &salt, &mut key)?;

            Ok(key)
        })
        .await?
    }
}

#[tokio::test]
async fn test_hash() {
    let hasher = Hasher::new("secret".to_string());

    let hash = hasher
        .hash("AzureDiamond".to_string(), "hunter2".to_string())
        .await
        .unwrap();

    // Same password, same username, same pepper => true
    assert!(hasher
        .verify(
            "AzureDiamond".to_string(),
            "hunter2".to_string(),
            hash.clone()
        )
        .await
        .unwrap());
}

#[tokio::test]
async fn test_verify_wrong_password() {
    let hasher = Hasher::new("secret".to_string());

    let hash = hasher
        .hash("AzureDiamond".to_string(), "hunter2".to_string())
        .await
        .unwrap();

    // Different password => false
    assert_eq!(
        hasher
            .verify(
                "AzureDiamond".to_string(),
                "hunter1".to_string(),
                hash.clone()
            )
            .await
            .unwrap(),
        false
    );
}

#[tokio::test]
async fn test_verify_wrong_username() {
    let hasher = Hasher::new("secret".to_string());

    let hash = hasher
        .hash("AzureDiamond".to_string(), "hunter2".to_string())
        .await
        .unwrap();

    // Different username => false
    assert_eq!(
        hasher
            .verify("Cthon98".to_string(), "hunter2".to_string(), hash.clone())
            .await
            .unwrap(),
        false
    );
}

#[tokio::test]
async fn test_verify_invalid_pepper() {
    let hasher = Hasher::new("secret".to_string());

    let hash = hasher
        .hash("AzureDiamond".to_string(), "hunter2".to_string())
        .await
        .unwrap();

    // Same password, invalid pepper => false
    let bad_hasher = Hasher::new("sekrit".to_string());
    assert_eq!(
        bad_hasher
            .verify(
                "AzureDiamond".to_string(),
                "hunter2".to_string(),
                hash.clone()
            )
            .await
            .unwrap(),
        false
    );
}
