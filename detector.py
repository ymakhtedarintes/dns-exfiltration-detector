from scapy.all import sniff, DNS, DNSQR, IP
import math
import collections
import datetime

# Shannon entropy measures how random a string looks.
# Normal subdomains like "mail" score low (~1.5).
# Base64 encoded payloads score high (~3.8+).
def entropy(s):
    if not s:
        return 0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# Tracks how many times each base domain gets queried within a 60s window
query_tracker = {}

ENTROPY_THRESHOLD = 3.8
LENGTH_THRESHOLD = 52
FREQUENCY_THRESHOLD = 20

# Known CDN, ad, and browser domains that legitimately produce high-entropy subdomains
WHITELISTED_DOMAINS = [
    "google.com", "googleapis.com", "googlevideo.com", "gstatic.com",
    "youtube.com", "ytimg.com", "doubleclick.net",
    "mozilla.com", "mozilla.net", "firefox.com",
    "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
    "amazon.com", "amazonaws.com",
    "cloudfront.net", "akamaized.net", "fastly.net", "cloudflare.com",
    "microsoft.com", "windows.com", "live.com",
    "spotify.com", "scdn.co",
    "apple.com", "icloud.com",
    "twitter.com", "twimg.com",
    "instagram.com", "fbcdn.net", "facebook.com",
    "discord.com", "discordapp.com"
]

def check_frequency(domain):
    now = datetime.datetime.now()
    if domain not in query_tracker:
        query_tracker[domain] = []
    query_tracker[domain].append(now)
    query_tracker[domain] = [t for t in query_tracker[domain] if (now - t).seconds < 60]
    return len(query_tracker[domain]) >= FREQUENCY_THRESHOLD

def alert(rule, domain, subdomain, score, src_ip, severity):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n[ALERT] {timestamp} | Severity: {severity}")
    print(f"  Rule      : {rule}")
    print(f"  Source IP : {src_ip}")
    print(f"  Domain    : {domain}")
    print(f"  Subdomain : {subdomain}")
    print(f"  Entropy   : {score:.2f}")
    with open("alerts.log", "a") as f:
        f.write(f"{timestamp} | {rule} | {src_ip} | {domain} | {subdomain} | entropy={score:.2f} | severity={severity}\n")

def process_packet(packet):
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return

    full_domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

    parts = full_domain.split(".")
    if len(parts) < 2:
        return

    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    base_domain = ".".join(parts[-2:])

    print(f"[DNS] {src_ip} queried {full_domain}")

    if any(base_domain.endswith(w) for w in WHITELISTED_DOMAINS):
        return

    if not subdomain:
        return

    score = entropy(subdomain)
    severity_score = 0
    triggered_rules = []

    if score >= ENTROPY_THRESHOLD:
        severity_score += 1
        triggered_rules.append("HIGH ENTROPY SUBDOMAIN")

    if len(subdomain) >= LENGTH_THRESHOLD:
        severity_score += 1
        triggered_rules.append("LONG SUBDOMAIN")

    if check_frequency(base_domain):
        severity_score += 1
        triggered_rules.append("HIGH FREQUENCY")

    # Require at least 2 rules to fire, or a very high entropy score.
    # Single rule hits produce too many false positives on real traffic.
    if severity_score >= 2 or score >= 4.0:
        severity = "CRITICAL" if severity_score == 3 or score >= 4.0 else "MEDIUM"
        alert(" + ".join(triggered_rules), full_domain, subdomain, score, src_ip, severity)

print("DNS Exfiltration Detector running... press Ctrl+C to stop\n")
sniff(filter="udp port 53", prn=process_packet, store=False)
