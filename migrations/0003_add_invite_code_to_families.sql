-- Migration: 0003_add_invite_code_to_families
-- Add invite_code column for family joining feature

ALTER TABLE families ADD COLUMN invite_code TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_families_invite_code ON families(invite_code);
