use std::io;

use secret_box::SecretBox;
use serde::{Deserialize, Serialize};

use base64::prelude::*;

pub use self::error::{Error, Result};

mod error;
mod password;
mod secret_box;

const COOKIE_KEY: [u8; 32] = [
    168, 77, 225, 162, 97, 28, 202, 13, 237, 97, 35, 55, 111, 241, 56, 188, 212, 35, 33, 146, 228,
    215, 154, 113, 95, 253, 226, 20, 230, 207, 193, 43,
];

#[derive(Serialize, Deserialize, Debug)]
struct SessionToken {
    sub: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    secret_box::init().unwrap();

    let cookie_box: SecretBox<'static> = SecretBox::new(&COOKIE_KEY);

    let session = SessionToken {
        sub: "lachy".into(),
    };

    let token_bytes = serde_json::to_vec(&session).unwrap();
    let cookie_bytes = cookie_box.seal(&token_bytes);

    let cookie_text = BASE64_URL_SAFE.encode(&cookie_bytes);

    println!("{:?}", cookie_text);

    let input_bytes = BASE64_URL_SAFE
        .decode("9qhixC9N-nMt24gq3-WqByWW-TKp3Xi3DKjAeB_0EXoz2m_OYXrFHoaMsKXgDXcWprUjGqzhSQ==")
        .unwrap();
    println!(
        "{:?}",
        std::str::from_utf8(&cookie_box.open(input_bytes.as_slice()).unwrap())
    );

    Ok(())
}
