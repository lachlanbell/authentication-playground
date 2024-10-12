use std::sync::Arc;

use sqlx::SqlitePool;

use crate::{password::Hasher, secret_box::SecretBox};

#[derive(Clone)]
pub struct AppState<'a> {
    pub token_box: Arc<SecretBox<'a>>,
    pub hasher: Arc<Hasher>,
    pub db: SqlitePool,
}
