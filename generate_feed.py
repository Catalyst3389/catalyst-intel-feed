import feedparser
from xml.etree.ElementTree import Element, SubElement, ElementTree
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

FEEDS = [
    # --- existing sources ---
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/news.xml",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://securelist.com/feed/",
    "https://risky.biz/feeds/newsletters",
    # --- Australian government (highest relevance for an AU operation) ---
    "https://www.cyber.gov.au/rss/alerts",
    "https://www.cyber.gov.au/rss/advisories",
    # --- OT / ICS (production-line & critical-infrastructure relevance) ---
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
]

# Sources we trust enough to let every item through, regardless of title.
# These are already-curated, low-noise feeds (newsletters or government
# advisories) whose titles are often descriptive rather than keyword-heavy,
# so applying the keyword filter would wrongly drop important items.
TRUSTED_SOURCES = [
    "risky.biz",
    "cyber.gov.au",       # ASD's ACSC alerts & advisories
    "ics-advisories",     # CISA ICS advisories
]

KEYWORDS = [
    "zero-day",
    "critical vulnerability",
    "ransomware",
    "exploit",
    "breach",
    "initial access",
    "credential theft",
    "actively exploited",
    "cve-",
    "malware",
    "phishing",
    # --- OT / manufacturing / critical-infrastructure terms ---
    "ics",
    "scada",
    "plc",
    "operational technology",
    "ot security",
    "supply chain",
    "manufacturing",
    "critical infrastructure",
    "kev",                # CISA Known Exploited Vulnerabilities
    "data breach",
]

MAX_ITEMS = 50


def is_relevant(title: str, source_url: str) -> bool:
    t = (title or "").lower()
    src = (source_url or "").lower()
    # Always allow trusted, pre-curated sources through.
    if any(trusted in src for trusted in TRUSTED_SOURCES):
        return True
    return any(keyword in t for keyword in KEYWORDS)


def get_severity(title: str) -> str:
    t = (title or "").lower()
    high_terms = [
        "zero-day",
        "critical",
        "actively exploited",
        "ransomware",
        "credential theft",
    ]
    medium_terms = [
        "exploit",
        "breach",
        "phishing",
        "malware",
        "cve-",
    ]
    if any(term in t for term in high_terms):
        return "HIGH"
    if any(term in t for term in medium_terms):
        return "MEDIUM"
    return "INFO"


def normalise_date(entry) -> tuple[str, datetime]:
    # Prefer published_parsed where available
    if getattr(entry, "published_parsed", None):
        dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        return dt.strftime("%a, %d %b %Y %H:%M:%S GMT"), dt
    published = entry.get("published") or entry.get("updated")
    if published:
        try:
            dt = parsedate_to_datetime(published)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%a, %d %b %Y %H:%M:%S GMT"), dt.astimezone(timezone.utc)
        except Exception:
            pass
    dt = datetime.now(timezone.utc)
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT"), dt


def fetch_entries() -> list[dict]:
    entries = []
    seen_links = set()
    for url in FEEDS:
        print(f"Fetching: {url}")
        feed = feedparser.parse(url)
        if getattr(feed, "bozo", 0):
            print(f"Warning: feed parse issue for {url}")
        for item in feed.entries:
            title = item.get("title", "").strip()
            link = item.get("link", "").strip()
            if not title or not link:
                continue
            if link in seen_links:
                continue
            if not is_relevant(title, url):
                continue
            pub_date_str, pub_dt = normalise_date(item)
            entries.append({
                "title": title,
                "link": link,
                "pub_date": pub_date_str,
                "pub_dt": pub_dt,
                "severity": get_severity(title),
                "source": url,
                "description": item.get("summary", "")[:500],
            })
            seen_links.add(link)
    entries.sort(key=lambda x: x["pub_dt"], reverse=True)
    return entries[:MAX_ITEMS]


def build_rss(entries: list[dict]) -> None:
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")
    SubElement(channel, "title").text = "Catalyst Threat Intelligence Feed"
    SubElement(channel, "description").text = (
        "Curated cyber threat intelligence feed aggregating incidents, "
        "vulnerabilities, exploits, and active threats."
    )
    SubElement(channel, "link").text = "https://catalyst3389.github.io/catalyst-intel-feed/"
    SubElement(channel, "language").text = "en-au"
    SubElement(channel, "lastBuildDate").text = datetime.now(timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )

    for entry in entries:
        item = SubElement(channel, "item")
        SubElement(item, "title").text = f"[{entry['severity']}] {entry['title']}"
        SubElement(item, "link").text = entry["link"]
        SubElement(item, "guid").text = entry["link"]
        SubElement(item, "pubDate").text = entry["pub_date"]
        SubElement(item, "category").text = entry["severity"]
        SubElement(item, "description").text = (
            f"Source: {entry['source']}\n\n{entry['description']}"
        )

    tree = ElementTree(rss)
    tree.write("feed.xml", encoding="utf-8", xml_declaration=True)


def main() -> None:
    entries = fetch_entries()
    build_rss(entries)
    print(f"Done. Generated feed.xml with {len(entries)} items.")


if __name__ == "__main__":
    main()
