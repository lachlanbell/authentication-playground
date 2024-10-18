CREATE TABLE session (
    session     TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL
);

CREATE INDEX session_user_id_idx ON session(user_id);
