CREATE TABLE password (
    user_id     BLOB PRIMARY KEY,
    hash        BLOB NOT NULL
);
