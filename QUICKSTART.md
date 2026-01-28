# Quick Start - Packet Analysis Tab

## ⚡ Start Analyzing in 3 Steps

### Step 1: Open the App
```bash
# Navigate to the project directory
cd /home/enoch/superduper

# Start a web server (choose one):
python3 -m http.server 8000
# OR
python -m SimpleHTTPServer 8000

# Open browser to: http://localhost:8000
```

### Step 2: Upload Your Data
1. Click **"Packet Analysis"** tab
2. Click **"Upload Packet CSV"** button
3. Select `data.csv` (or your pen register CSV)
4. **Results appear automatically!**

### Step 3: Run WHOIS Lookups
1. Click **"Run WHOIS on All IPs"** button
2. Wait for completion (shows progress)
3. View organization, country, city for each IP

**That's it!** You'll see:
- Detected apps (Facebook, WhatsApp, TikTok, etc.)
- Banking/financial services
- IP addresses with traffic stats
- Port usage analysis
- Protocol distribution

---

## 🎯 What You'll See from data.csv

### Detected Apps (Automatic):
- ✅ Facebook/Instagram
- ✅ Apple iMessage/FaceTime
- ✅ TikTok
- ✅ VoIP calling (SIP)
- ✅ DNS queries
- ✅ Video streaming

### Top IPs:
- Meta Platforms (Facebook/Instagram servers)
- Apple Inc. (Push notification service)
- Cloudflare CDN (TikTok, other services)
- T-Mobile Network (carrier infrastructure)
- Google Services

### Usage Insights:
- Heavy video streaming (1.3GB in sample)
- Active messaging throughout the day
- Voice/video calls detected
- iPhone/iOS device confirmed

---

## 📊 Optional: Enable Database Caching

**Why?** Saves API calls, instant WHOIS results for known IPs

### Quick Setup (5 minutes):
1. Go to [supabase.com](https://supabase.com) → Sign up (free)
2. Create new project
3. Copy your **Project URL** and **anon/public key**
4. In app: **Tower Management** → **Cloud Config**
5. Paste URL and key → **Save & Connect**
6. In Supabase: **SQL Editor** → **New Query**
7. Paste contents of `setup_whois_table.sql` → **Run**
8. Done! Database caching enabled ✅

---

## 🚨 Troubleshooting

**"No apps detected"?**
- Check if CSV has IP columns (Source Address, Destination Address)
- Private IPs (fd00::) are filtered out automatically

**WHOIS showing "Failed"?**
- API rate limit (wait a few minutes)
- Network issue (check internet connection)

**"Database not connected" warning?**
- Optional! App works without it
- To enable: Follow setup above

---

## 📖 Full Documentation

- **PACKET_ANALYSIS_SETUP.md** - Detailed setup guide
- **PACKET_ANALYSIS_SUMMARY.md** - Feature overview
- **EXAMPLE_OUTPUT.md** - Expected results
- **setup_whois_table.sql** - Database setup

---

## 💡 Pro Tips

1. **Run bulk WHOIS once** - All future lookups instant from cache
2. **Sort by data volume** - Find heaviest users/services
3. **Check ports** - Port 5223 = iMessage, 5060 = VoIP calls
4. **View Cache** - Click purple banner button to see all cached IPs
5. **Export data** - Use browser dev tools to save results as needed

---

## 🎉 You're Ready!

Your `data.csv` with **2,743 records** is ready to analyze. Just upload and explore!
