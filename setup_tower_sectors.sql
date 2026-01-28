-- ============================================
-- Add Sector/Beam Columns to Towers Table
-- ============================================
-- Run this SQL in your Supabase SQL Editor
-- ============================================

ALTER TABLE IF EXISTS towers
    ADD COLUMN IF NOT EXISTS azimuth NUMERIC,
    ADD COLUMN IF NOT EXISTS beamwidth NUMERIC,
    ADD COLUMN IF NOT EXISTS radius NUMERIC,
    ADD COLUMN IF NOT EXISTS sector TEXT;

-- Optional: quick check
-- SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'towers';
