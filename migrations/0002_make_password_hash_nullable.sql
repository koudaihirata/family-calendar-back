-- Migration: 0002_make_password_hash_nullable
-- Google OAuth users have no password, so password_hash must be nullable

PRAGMA foreign_keys = OFF;

CREATE TABLE users_new (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  avatar_url    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO users_new SELECT id, name, email, password_hash, avatar_url, created_at FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_keys = ON;
