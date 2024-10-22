use std::{io, str::FromStr, sync::Arc};

use password::Hasher;
use secret_box::SecretBox;
use serde::{Deserialize, Serialize};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode},
    SqlitePool,
};

pub use self::error::{Error, Result};

mod error;
mod password;
mod secret_box;
mod web;

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

    let token_box = SecretBox::new(&COOKIE_KEY).unwrap();
    let hasher = Hasher::new("pepper".to_string());
    let db = SqlitePool::connect_with(
        SqliteConnectOptions::from_str(&dotenvy::var("DATABASE_URL").unwrap())
            .unwrap()
            .journal_mode(SqliteJournalMode::Wal),
    )
    .await
    .unwrap();

    let state = web::AppState {
        token_box: Arc::new(token_box),
        hasher: Arc::new(hasher),
        db,
    };

    web::serve(state).await;

    Ok(())
}
