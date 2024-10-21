CREATE TABLE session (
    session     BLOB PRIMARY KEY,
    user_id     BLOB NOT NULL
);

CREATE INDEX session_user_id_idx ON session(user_id);
