use crate::{Error, Result};

pub const KEY_BYTES: usize = libsodium_sys::crypto_secretbox_KEYBYTES as usize;

const MAC_BYTES: usize = libsodium_sys::crypto_secretbox_MACBYTES as usize;
const NONCE_BYTES: usize = libsodium_sys::crypto_secretbox_NONCEBYTES as usize;

pub struct SecretBox<'a> {
    key: &'a [u8],
}

pub fn init() -> Result<()> {
    unsafe {
        if libsodium_sys::sodium_init() < 0 {
            return Err(Error::SodiumError);
        }
    }

    Ok(())
}

impl SecretBox<'_> {
    pub fn new(key: &[u8]) -> SecretBox<'_> {
        #[cfg(test)]
        init().unwrap();

        SecretBox { key }
    }

    pub fn seal(&self, message: &[u8]) -> Vec<u8> {
        let ciphertext_size = NONCE_BYTES + message.len() + MAC_BYTES;

        let mut ciphertext = Vec::with_capacity(ciphertext_size);
        let nonce = generate_nonce();

        // Prepend the nonce to the ciphertext.
        // This follows the implementation in PyNaCl and swift-sodium.
        for byte in nonce {
            ciphertext.push(byte);
        }

        unsafe {
            libsodium_sys::crypto_secretbox_easy(
                ciphertext.as_mut_ptr().add(NONCE_BYTES),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                self.key.as_ptr(),
            );

            ciphertext.set_len(ciphertext_size)
        }

        ciphertext
    }

    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < (MAC_BYTES + NONCE_BYTES) {
            return Err(Error::CiphertextTooShort);
        }

        let message_size = ciphertext.len() - MAC_BYTES - NONCE_BYTES;

        let mut message = Vec::<u8>::with_capacity(message_size);

        unsafe {
            let retval = libsodium_sys::crypto_secretbox_open_easy(
                message.as_mut_ptr(),
                ciphertext.as_ptr().add(NONCE_BYTES),
                (ciphertext.len() - NONCE_BYTES) as u64,
                ciphertext.as_ptr(),
                self.key.as_ptr(),
            );

            if retval != 0 {
                return Err(Error::ForgedMessage);
            }

            message.set_len(message_size)
        }

        Ok(message)
    }
}

fn generate_nonce() -> [u8; NONCE_BYTES] {
    let mut nonce: [u8; NONCE_BYTES] = [0; NONCE_BYTES];

    unsafe {
        libsodium_sys::randombytes_buf(nonce.as_mut_ptr() as *mut _, NONCE_BYTES);
    }

    nonce
}

#[test]
fn test_secretbox() {
    let message = "Hello, world!".as_bytes();

    let key: [u8; KEY_BYTES] = [2; KEY_BYTES];
    let secret_box = SecretBox::new(&key);
    let ciphertext = secret_box.seal(message);

    let decrypted = secret_box.open(&ciphertext).unwrap();
    assert_eq!(message, decrypted);
}

#[test]
fn test_nonce_ne() {
    // Sanity check.
    assert_ne!(generate_nonce(), generate_nonce());
}

#[test]
fn test_bad_length() {
    let key: [u8; KEY_BYTES] = [2; KEY_BYTES];

    let secret_box = SecretBox::new(&key);

    let ciphertext = [1u8; (MAC_BYTES + NONCE_BYTES - 1)];
    assert_eq!(secret_box.open(&ciphertext), Err(Error::CiphertextTooShort));
}

#[test]
fn test_empty_message() {
    let message: Vec<u8> = vec![];
    let key: [u8; KEY_BYTES] = [2; KEY_BYTES];

    let secret_box = SecretBox::new(&key);
    let ciphertext = secret_box.seal(&message);

    assert_eq!(ciphertext.len(), MAC_BYTES + NONCE_BYTES);
    assert_eq!(secret_box.open(&ciphertext), Ok(vec![]));
}

#[test]
fn generate_key() {
    init().unwrap();
    let mut key: [u8; KEY_BYTES] = [0; KEY_BYTES];

    unsafe {
        libsodium_sys::randombytes_buf(key.as_mut_ptr() as *mut _, KEY_BYTES);
    }

    println!("{:?}", key);
}
