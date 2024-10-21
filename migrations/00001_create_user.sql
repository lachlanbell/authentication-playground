CREATE TABLE user (
    user_id     BLOB PRIMARY KEY NOT NULL,
    username    TEXT UNIQUE NOT NULL
);

CREATE INDEX user_username_idx ON user(username);
