-- Trusted adapter outcomes are separate from untrusted raw scanner text.
-- Run explicitly with schema privileges; old rows remain readable as legacy.
ALTER TABLE summary ADD COLUMN IF NOT EXISTS scan_metadata LONGTEXT NULL;
