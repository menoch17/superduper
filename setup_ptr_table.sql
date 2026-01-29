-- ============================================
-- PTR (Reverse DNS) Cache Table Setup for Supabase
-- ============================================
-- Run this SQL in your Supabase SQL Editor
-- (https://app.supabase.com/project/_/sql)
-- ============================================

-- Create the ip_ptr table
CREATE TABLE IF NOT EXISTS ip_ptr (
    id BIGSERIAL PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    ptr_name TEXT,
    lookup_date TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index on ip_address for fast lookups
CREATE INDEX IF NOT EXISTS idx_ip_ptr_address ON ip_ptr(ip_address);

-- Create index on lookup_date for sorting recent lookups
CREATE INDEX IF NOT EXISTS idx_ip_ptr_lookup_date ON ip_ptr(lookup_date DESC);

-- Enable Row Level Security (RLS)
ALTER TABLE ip_ptr ENABLE ROW LEVEL SECURITY;

-- Create policy to allow all operations (adjust based on your security needs)
CREATE POLICY "Enable all access for authenticated users" ON ip_ptr
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- Optional: Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_ip_ptr_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Optional: Create trigger to auto-update updated_at
CREATE TRIGGER update_ip_ptr_updated_at
    BEFORE UPDATE ON ip_ptr
    FOR EACH ROW
    EXECUTE FUNCTION update_ip_ptr_updated_at();

-- Grant permissions (adjust based on your needs)
GRANT ALL ON ip_ptr TO authenticated;
GRANT ALL ON ip_ptr TO anon;

-- Display setup completion message
DO $$
BEGIN
    RAISE NOTICE 'PTR cache table setup complete!';
    RAISE NOTICE 'Table: ip_ptr';
    RAISE NOTICE 'Indexes: idx_ip_ptr_address, idx_ip_ptr_lookup_date';
    RAISE NOTICE 'RLS: Enabled with open policy';
END $$;
