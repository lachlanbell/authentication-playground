CREATE TABLE user (
    user_id     TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL
);

CREATE INDEX user_username_idx ON user(username);
