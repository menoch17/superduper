-- ============================================
-- WHOIS Cache Table Setup for Supabase
-- ============================================
-- Run this SQL in your Supabase SQL Editor
-- (https://app.supabase.com/project/_/sql)
-- ============================================

-- Create the ip_whois table
CREATE TABLE IF NOT EXISTS ip_whois (
    id BIGSERIAL PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    organization TEXT,
    country TEXT,
    city TEXT,
    region TEXT,
    asn TEXT,
    isp TEXT,
    lookup_date TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index on ip_address for fast lookups
CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_whois(ip_address);

-- Create index on lookup_date for sorting recent lookups
CREATE INDEX IF NOT EXISTS idx_lookup_date ON ip_whois(lookup_date DESC);

-- Enable Row Level Security (RLS)
ALTER TABLE ip_whois ENABLE ROW LEVEL SECURITY;

-- Create policy to allow all operations (adjust based on your security needs)
-- For law enforcement use, you may want to restrict this further
CREATE POLICY "Enable all access for authenticated users" ON ip_whois
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- Optional: Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Optional: Create trigger to auto-update updated_at
CREATE TRIGGER update_ip_whois_updated_at
    BEFORE UPDATE ON ip_whois
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (adjust based on your needs)
-- If using service role key, these may not be necessary
GRANT ALL ON ip_whois TO authenticated;
GRANT ALL ON ip_whois TO anon;

-- Display setup completion message
DO $$
BEGIN
    RAISE NOTICE 'WHOIS cache table setup complete!';
    RAISE NOTICE 'Table: ip_whois';
    RAISE NOTICE 'Indexes: idx_ip_address, idx_lookup_date';
    RAISE NOTICE 'RLS: Enabled with open policy';
END $$;
