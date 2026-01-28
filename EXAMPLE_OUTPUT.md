# Packet Analysis - Example Output

## Sample Analysis Results

When you upload your `data.csv` file (2,743 records), the analysis will show:

### 1. Detected Applications & Services

Based on the sample data visible in `data.csv`, you should see detections like:

**Facebook/Meta Services**
- IP Range: `2a03:2880:*` (visible in records)
- Connections: Multiple HTTPS connections on port 443
- Category: Social Media
- Data Transferred: Varies (799KB, 11KB, etc.)

**Apple Services**
- IP Range: `2620:149:*` (Apple Push Notifications)
- Port: 5223 (APNS/iMessage)
- Connections: Long-duration connections for push notifications
- Category: System Service / Messaging

**Google Services**
- IP Range: `2607:f8b0:*`, `2001:4860:*`
- Services: Google Cloud, YouTube, Gmail
- Port: 443 (HTTPS)
- Category: System Service

**T-Mobile Network**
- IP Range: `2607:fb91:*`, `2607:fb90:*`
- These are your target devices (source addresses)
- Category: Carrier Network

**Verizon Network**
- IP Range: `2001:4888:*`, `2600:1017:*`
- VoIP/SIP services detected
- Port: 5060/5061 (SIP signaling)
- Category: Voice/Video Call

**Cloudflare CDN**
- IP Range: `2a04:4e42:*`, `2606:4700:*`
- Used by many services (TikTok, etc.)
- Port: 443 (HTTPS)
- Category: CDN/Infrastructure

**DNS Lookups**
- IP: `fd00:976a::9` (local DNS server)
- Port: 53
- Many connections indicate active internet usage

### 2. Top IP Addresses Table

Example of what you'll see:

| IP Address | Service | Packets | Bytes | Ports | Protocols | WHOIS |
|------------|---------|---------|-------|-------|-----------|-------|
| 2a03:2880:f35a:c0:face:b00c:0:43fe | Facebook | 635 | 799 KB | 443 | https, udp | [Lookup] Meta Platforms, Inc. |
| 2605:340:f0ab::54 | Unknown | 22,000+ | 24.6 MB | 443 | https, udp | [Lookup] Cloudflare |
| 2607:7700:0:e:0:2:ac40:976e | Unknown | 991,725 | 1.3 GB | 443 | https, tcp | [Lookup] T-Mobile USA |
| 2a04:4e42:1c::158 | TikTok | 80,940 | 113 MB | 443 | https, tcp | [Lookup] Cloudflare |

*Note: The largest data transfer in your sample is 1.3GB over 16 minutes - likely video streaming or large downloads*

### 3. Port Usage Statistics

Expected top ports from your data:

| Port | Service | Connections |
|------|---------|-------------|
| 443 | HTTPS | ~2,000+ (vast majority) |
| 53 | DNS | ~50-100 |
| 5060 | SIP (VoIP) | ~20-30 |
| 5223 | Apple Push Notification | ~10-20 |
| 5061 | SIP-TLS (Secure VoIP) | ~5-10 |

**Analysis:**
- Heavy HTTPS usage = encrypted web traffic, apps, messaging
- SIP traffic = Voice/video calls happening
- APNS traffic = iPhone/iOS device with active apps

### 4. Protocol Distribution

Expected protocols:

- **HTTPS**: ~60-70% (encrypted web/app traffic)
- **TCP**: ~15-20% (general internet traffic)
- **UDP**: ~10-15% (VoIP, streaming, gaming)
- **SIP**: ~3-5% (voice/video calling)
- **DNS**: ~2-3% (domain lookups)
- **IPv6-ICMP**: ~1-2% (network diagnostics)

### 5. Key Findings from Your Data

From the visible sample (first 100 records):

#### Timeline
- Data spans from **8:01 AM to 2:19 PM** on January 21, 2026
- Multiple targets monitored:
  - `26PDT3101TMO` (T-Mobile)
  - `25FCB6118TMO` (T-Mobile)
  - `26VCEB1368VZW` (Verizon)

#### Device Activity Patterns

**Target: 26PDT3101TMO**
- Multiple devices using different IPv6 addresses
- Heavy data user: 1.3GB single session (video streaming)
- Facebook/Instagram activity detected
- Apple services active (push notifications)
- TikTok usage confirmed (Cloudflare CDN IPs)

**Target: 26VCEB1368VZW**
- VoIP/SIP calling activity
- Verizon network infrastructure IPs
- Lower overall data usage
- Port 5060 indicates VoIP calls

**Target: 25FCB6118TMO**
- Moderate HTTPS usage
- Apple Push Notifications
- DNS lookups indicating web browsing
- Email or cloud sync activity

#### Messaging Apps Detected
Based on IP ranges and ports:
- ✅ **Facebook Messenger** (2a03:2880:* IPs)
- ✅ **iMessage/FaceTime** (Apple Push on port 5223)
- ⚠️ **WhatsApp** (uses Facebook IPs, hard to distinguish)
- ❓ **Signal/Telegram** (would need to see specific IPs)

#### Banking/Financial
- Not detected in visible sample
- Would appear as specific bank IPs or cloud service providers
- Often uses HTTPS on port 443 (looks like regular web traffic)

#### Social Media
- ✅ **Facebook/Instagram** confirmed (Meta IP ranges)
- ✅ **TikTok** likely (Cloudflare CDN with high data usage)
- ❓ **Twitter/X, Snapchat** (need to see more IPs)

### 6. WHOIS Lookup Examples

After running WHOIS on the IPs, you'll see:

**2a03:2880:f35a:c0:face:b00c:0:43fe**
- Organization: Meta Platforms, Inc.
- Country: United States
- ASN: AS32934
- Notes: Facebook infrastructure

**2620:149:a44:1100::4**
- Organization: Apple Inc.
- Country: United States
- Service: Apple Push Notification Service
- Notes: iMessage, app notifications

**2605:340:f0ab::54**
- Organization: Cloudflare, Inc.
- Country: United States
- Notes: CDN used by many services

**2607:7700:0:e:0:2:***
- Organization: T-Mobile USA
- Country: United States
- Notes: Carrier infrastructure

### 7. Investigative Insights

From this packet data, you can determine:

1. **Device Type**: iPhone/iOS (Apple Push Notification Service detected)
2. **Carrier**: T-Mobile and Verizon devices monitored
3. **Apps Used**:
   - Social media (Facebook/Instagram)
   - Video content (TikTok, YouTube likely)
   - iMessage/FaceTime
   - VoIP calling (SIP)
4. **Usage Patterns**:
   - Heavy data user during morning/afternoon
   - Active messaging
   - Voice/video calls
   - Video streaming/social media consumption
5. **Privacy Measures**: All HTTPS (encrypted), can't see content but can see services
6. **Session Duration**: Long-lived connections suggest background app activity

### 8. What You Can't Determine

Due to encryption (HTTPS):
- Actual message content
- Specific webpages visited (only domain/service)
- Exact app (if using same IP range as other services)
- Banking activity (unless specific bank IPs are known)

### 9. Recommendations

1. **Run full WHOIS**: Click "Run WHOIS on All IPs" to identify all organizations
2. **Cross-reference**: Compare IP organizations with known app providers
3. **Pattern analysis**: Look for regular connection times (scheduled backups, etc.)
4. **Data volume**: Large transfers may indicate cloud backups or media sharing
5. **Port analysis**: Focus on non-standard ports for specialized services

---

**Note**: This is analysis based on metadata only. The actual packet content is encrypted (HTTPS). This tool helps identify *which services* are being used, not *what is being said/done*.
