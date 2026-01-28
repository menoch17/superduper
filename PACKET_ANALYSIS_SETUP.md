# Packet Analysis Tab - Setup Guide

## Overview

The Packet Analysis tab allows you to upload pen register CSV data and automatically:
- Identify messaging apps (WhatsApp, Telegram, Signal, etc.)
- Detect social media usage (Facebook, Instagram, Twitter, etc.)
- Identify banking and financial services
- Perform WHOIS lookups on IP addresses with database caching
- Analyze port usage and protocols

## Features

### 1. Application Detection
Automatically identifies apps and services based on IP address ranges:
- **Messaging:** WhatsApp, Telegram, Signal, Facebook Messenger
- **Social Media:** Facebook, Instagram, Twitter/X, Snapchat, TikTok
- **System Services:** Apple Push Notifications, Google Cloud Messaging
- **VoIP:** SIP calling services
- **Streaming:** Netflix, YouTube
- **Cloud Services:** Amazon AWS, Microsoft Azure, Cloudflare

### 2. IP WHOIS Lookups with Database Caching
- Query database first before making API calls
- Automatically stores new lookups for future use
- Bulk lookup functionality with progress tracking
- View cached IPs in a modal window
- Shows organization, country, and city for each IP

### 3. Port and Protocol Analysis
- Identifies common services by port number
- Shows connection statistics
- Protocol distribution analysis

## Database Setup

### Step 1: Configure Supabase

1. Go to [Supabase](https://supabase.com) and create a project (if you don't have one)
2. In your app, click **Tower Management** tab → **Cloud Config**
3. Enter your Supabase URL and Anon Key
4. Click **Save & Connect**

### Step 2: Create the WHOIS Cache Table

1. Open the Supabase dashboard for your project
2. Go to **SQL Editor** (left sidebar)
3. Click **New Query**
4. Copy and paste the contents of `setup_whois_table.sql`
5. Click **Run**

The table structure:
```sql
ip_whois (
    id BIGSERIAL PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    organization TEXT,
    country TEXT,
    city TEXT,
    region TEXT,
    asn TEXT,
    isp TEXT,
    lookup_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
)
```

### Step 3: Verify Setup

1. Go back to your app
2. Click **Packet Analysis** tab
3. Upload a CSV file
4. The database stats should show "X IPs cached" in purple banner
5. If it shows "Database not connected", verify your Supabase credentials

## Usage

### Upload and Analyze

1. Click **Packet Analysis** tab
2. Click **Upload Packet CSV**
3. Select your pen register CSV file (must have these columns):
   - Target
   - Source Address
   - Destination Address
   - Source Port
   - Destination Port
   - Transport Protocol / Session Protocol
   - Bytes
   - Start Time / End Time

4. Results will automatically display:
   - Detected apps with connection counts and data transferred
   - Top IP addresses sorted by traffic volume
   - Port usage statistics
   - Protocol distribution

### WHOIS Lookups

#### Individual Lookup
- Click the **Lookup** button next to any IP address
- If the IP exists in the database, it will show immediately with "(cached)"
- If not, it will perform an API call and store the result

#### Bulk Lookup
- Click **Run WHOIS on All IPs** to lookup all visible IPs
- The system will:
  1. Check database for all IPs at once (instant)
  2. Perform API lookups only for IPs not in cache
  3. Display progress: "X from cache, Y new lookups"
  4. Rate-limited to 1.5 seconds between API calls

#### View Cache
- Click **View Cache** button in the purple banner
- Shows last 100 cached IP lookups
- Displays IP, organization, location, and lookup date

## CSV Format Requirements

Your CSV should have headers (first row) and include these columns:

**Required:**
- `Source Address` - Source IP address (IPv4 or IPv6)
- `Destination Address` - Destination IP address
- `Source Port` - Source port number
- `Destination Port` - Destination port number

**Optional but recommended:**
- `Transport Protocol` or `Session Protocol` - tcp, udp, https, sip, etc.
- `Bytes` - Data transferred
- `Start Time` - Connection start timestamp
- `Target` - Target identifier
- `Direction` - incoming/outgoing
- `Duration` - Session duration

## API Rate Limits

### WHOIS API (ipapi.co)
- **Free Tier:** 1,000 requests per day
- **Rate Limit:** ~1 request per second
- **Built-in Protection:** 1.5 second delay between requests
- **Recommended:** Use database caching to minimize API calls

### Why Database Caching Matters
- Lookups for the same IP are instant (no API call)
- Saves your daily API quota
- Works offline if IP was previously looked up
- Shared across all your cases/investigations

## Troubleshooting

### "Database not connected" Warning
**Solution:** Configure Supabase credentials in Tower Management → Cloud Config

### WHOIS Lookups Show "Failed"
**Possible causes:**
1. API rate limit exceeded (wait a few minutes)
2. Invalid IP address format
3. IP is private/local (fd00::, 127.0.0.1, etc.)
4. Network connectivity issue

### No Apps Detected
**Possible causes:**
1. CSV doesn't have IP address columns
2. IPs are all private/internal
3. Services not in known IP range database
4. Check port analysis instead - may show service by port number

### Table Already Exists Error
If you see "table already exists" when running setup SQL:
- The table is already set up
- No action needed
- Or run: `DROP TABLE ip_whois;` first (WARNING: deletes all cached data)

## Security Considerations

### Row Level Security (RLS)
The setup script enables RLS with an open policy for convenience. For production:

**Restrict to authenticated users only:**
```sql
DROP POLICY "Enable all access for authenticated users" ON ip_whois;

CREATE POLICY "Enable read for authenticated users" ON ip_whois
    FOR SELECT
    USING (auth.role() = 'authenticated');

CREATE POLICY "Enable insert for authenticated users" ON ip_whois
    FOR INSERT
    WITH CHECK (auth.role() = 'authenticated');
```

### API Key Security
- Never commit Supabase credentials to version control
- Use environment variables in production
- Rotate keys periodically
- Use service role key only on backend, not in browser

### Data Retention
- Consider purging old WHOIS data periodically
- Add TTL (time to live) for cached records
- Example: Delete records older than 90 days

```sql
DELETE FROM ip_whois
WHERE lookup_date < NOW() - INTERVAL '90 days';
```

## Performance Tips

1. **Bulk Lookup First:** Run bulk WHOIS on all IPs once, then individual lookups are instant
2. **Database Caching:** Always configure Supabase before starting investigation
3. **Limit Results:** The app shows top 50 IPs by default to keep UI responsive
4. **Clear Cache:** Use browser dev tools to clear old data if needed

## Known IP Ranges

The app includes known IP ranges for:
- Meta/Facebook services (2a03:2880:, 157.240., etc.)
- Apple services (2620:149:, 17., etc.)
- Google services (2607:f8b0:, 142.250., etc.)
- Telegram (2001:67c:4e8:, 91.108., etc.)
- And many more...

See `analyzer.js` → `IP_RANGES` object for the full list.

## Common Ports Reference

Built-in port identification:
- 443 - HTTPS (encrypted web traffic)
- 5060/5061 - SIP (VoIP calling)
- 5223 - Apple Push Notifications / iMessage
- 5228 - Google Cloud Messaging / Android notifications
- 53 - DNS lookups
- 80 - HTTP (unencrypted web)
- 25, 587, 465 - Email (SMTP)
- 993, 995 - Secure email (IMAP/POP3)

See `analyzer.js` → `PORT_SERVICES` object for the full list.
