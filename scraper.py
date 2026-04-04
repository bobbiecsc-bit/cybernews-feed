"""
Cybersecurity News Feed Scraper
================================
Scrapes RSS feeds from major cybersecurity sources and outputs a
lightweight feed.json file. No database required — designed to run
as a GitHub Actions cron job and serve via Vercel static hosting.

Output: feed.json (top 100 articles, deduplicated by URL hash)
"""

import feedparser
import json
import hashlib
import re
import os
import logging
from datetime import datetime, timezone

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# NEWS SOURCES
# ============================================================================

# Only these four categories are kept in the output feed.
# Articles that don't match any are dropped entirely (no 'general' fallback).
HIGH_SIGNAL_CATEGORIES = {'breach', 'vulnerability', 'malware', 'threat'}

NEWS_SOURCES = {
    'thehackernews': {
        'name': 'The Hacker News',
        'rss_url': 'https://feeds.feedburner.com/TheHackersNews',
        'category_keywords': {
            'breach':        ['breach', 'hacked', 'compromised', 'leaked', 'data leak', 'stolen', 'exposed'],
            'vulnerability': ['vulnerability', 'CVE', 'patch', 'exploit', 'zero-day', 'flaw', 'bug'],
            'malware':       ['malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'spyware', 'wiper'],
            'threat':        ['threat', 'attack', 'campaign', 'APT', 'threat actor', 'cybercrime'],
        }
    },
    'krebs': {
        'name': 'Krebs on Security',
        'rss_url': 'https://krebsonsecurity.com/feed/',
        'category_keywords': {
            'breach':        ['breach', 'hacked', 'compromised', 'stolen', 'leaked'],
            'vulnerability': ['vulnerability', 'flaw', 'bug', 'weakness'],
            'malware':       ['malware', 'ransomware', 'rat', 'trojan'],
            'threat':        ['threat', 'scam', 'fraud', 'phishing', 'crime'],
        }
    },
    'bleepingcomputer': {
        'name': 'Bleeping Computer',
        'rss_url': 'https://www.bleepingcomputer.com/feed/',
        'category_keywords': {
            'breach':        ['breach', 'data leak', 'hacked', 'stolen'],
            'vulnerability': ['vulnerability', 'CVE', 'security flaw', 'exploit'],
            'malware':       ['malware', 'ransomware', 'infostealer'],
            'threat':        ['attack', 'threat', 'campaign'],
        }
    },
    'darkreading': {
        'name': 'Dark Reading',
        'rss_url': 'https://www.darkreading.com/rss/all.xml',
        'category_keywords': {
            'breach':        ['breach', 'incident', 'compromised'],
            'vulnerability': ['vulnerability', 'exploit', 'flaw'],
            'threat':        ['threat', 'attack', 'risk', 'APT'],
        }
    },
    'cisa': {
        'name': 'CISA Alerts',
        'rss_url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'category_keywords': {
            'vulnerability': ['vulnerability', 'CVE', 'KEV', 'flaw', 'advisory'],
            'threat':        ['alert', 'warning', 'bulletin', 'malicious activity'],
        }
    },
    'sans': {
        'name': 'SANS ISC',
        'rss_url': 'https://isc.sans.edu/rssfeed.xml',
        'category_keywords': {
            'vulnerability': ['vulnerability', 'exploit', 'CVE'],
            'threat':        ['threat', 'malicious', 'attack', 'scanning'],
        }
    },
    'schneier': {
        'name': 'Schneier on Security',
        'rss_url': 'https://www.schneier.com/blog/atom.xml',
        'category_keywords': {
            'breach':        ['breach', 'hack', 'compromised'],
            'vulnerability': ['vulnerability', 'flaw', 'bug'],
            'threat':        ['threat', 'attack', 'surveillance', 'espionage'],
        }
    },
    'securityweek': {
        'name': 'Security Week',
        'rss_url': 'https://www.securityweek.com/feed/',
        'category_keywords': {
            'breach':        ['breach', 'hack', 'compromised', 'leaked'],
            'vulnerability': ['vulnerability', 'flaw', 'bug', 'CVE', 'exploit'],
            'malware':       ['malware', 'ransomware', 'trojan', 'spyware'],
            'threat':        ['threat', 'attack', 'campaign', 'APT'],
        }
    },
    'therecord': {
        'name': 'The Record',
        'rss_url': 'https://therecord.media/feed/',
        'category_keywords': {
            'breach':        ['breach', 'hack', 'compromised', 'leaked'],
            'vulnerability': ['vulnerability', 'flaw', 'bug', 'CVE'],
            'malware':       ['malware', 'ransomware', 'trojan'],
            'threat':        ['threat', 'attack', 'campaign', 'espionage'],
        }
    },
}

# ============================================================================
# PAGINATION SETTINGS
# ============================================================================

ARCHIVE_SIZE = 250          # total articles kept in the rolling archive
PAGE_SIZE    = 50           # articles shown per page
TOTAL_PAGES  = ARCHIVE_SIZE // PAGE_SIZE   # 5 pages

ARCHIVE_PATH = 'archive.json'   # full rolling archive (not served publicly)

# Page files served by Vercel:
#   feed.json       → page 1  (newest 50)
#   feed-2.json     → page 2
#   ...
#   feed-5.json     → page 5  (oldest 50 in the archive)

def page_filename(page_number):
    """Return the output filename for a given 1-based page number."""
    return 'feed.json' if page_number == 1 else f'feed-{page_number}.json'


# ============================================================================
# HELPERS
# ============================================================================

def clean_text(text):
    """Strip HTML tags and normalize whitespace."""
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def make_hash(url):
    """SHA-256 of URL — used for deduplication."""
    return hashlib.sha256(url.encode()).hexdigest()


def categorize(title, summary, keywords):
    """Return the first matching high-signal category, or None."""
    combined = (title + " " + summary).lower()
    for category, terms in keywords.items():
        for term in terms:
            if term.lower() in combined:
                return category
    return None  # caller will drop this article


def parse_date(entry):
    """Extract a UTC ISO-8601 date string from a feedparser entry."""
    for attr in ('published_parsed', 'updated_parsed'):
        parsed = getattr(entry, attr, None)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                pass
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# SCRAPING
# ============================================================================

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (compatible; CyberNewsFeed/1.0; '
        '+https://github.com/your-org/cybernews-feed)'
    )
}


def fetch_source(source_id, config):
    """Fetch and parse a single RSS source. Returns list of article dicts."""
    articles = []
    logging.info(f"Fetching: {config['name']}")

    try:
        feed = feedparser.parse(config['rss_url'], request_headers=HEADERS)

        if feed.bozo:
            logging.warning(f"  Feed warning ({config['name']}): {feed.bozo_exception}")

        for entry in feed.entries:
            try:
                title = clean_text(entry.get('title', ''))
                url   = entry.get('link', '').strip()

                if not title or not url:
                    continue

                summary_raw = (
                    entry.get('summary', '') or
                    entry.get('description', '') or
                    (entry.get('content') or [{}])[0].get('value', '')
                )
                summary  = clean_text(summary_raw)[:300]
                category = categorize(title, summary, config['category_keywords'])

                # Drop articles that don't match a high-signal category
                if category is None:
                    continue

                articles.append({
                    'id':       make_hash(url),
                    'title':    title,
                    'url':      url,
                    'summary':  summary,
                    'source':   config['name'],
                    'category': category,
                    'date':     parse_date(entry),
                })

            except Exception as e:
                logging.warning(f"  Skipped entry from {config['name']}: {e}")

        logging.info(f"  Got {len(articles)} articles from {config['name']}")

    except Exception as e:
        logging.error(f"  Failed to fetch {config['name']}: {e}")

    return articles


def scrape_all():
    """Scrape every source, deduplicate, sort newest first."""
    seen   = set()
    result = []

    for source_id, config in NEWS_SOURCES.items():
        for article in fetch_source(source_id, config):
            if article['id'] not in seen:
                seen.add(article['id'])
                result.append(article)

    result.sort(key=lambda a: a['date'], reverse=True)
    return result


# ============================================================================
# ARCHIVE — rolling 250-article store between runs
# ============================================================================

def load_archive():
    """Load the existing archive, or return an empty list."""
    if os.path.exists(ARCHIVE_PATH):
        try:
            with open(ARCHIVE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f).get('articles', [])
        except Exception as e:
            logging.warning(f"Could not read archive: {e}")
    return []


def merge_into_archive(new_articles, existing):
    """
    Merge new articles into the existing archive.
    New articles take priority on duplicates.
    Result is sorted newest-first and trimmed to ARCHIVE_SIZE.
    """
    merged_map = {a['id']: a for a in existing}
    for article in new_articles:
        merged_map[article['id']] = article

    merged = list(merged_map.values())
    merged.sort(key=lambda a: a['date'], reverse=True)
    return merged[:ARCHIVE_SIZE]


def save_archive(articles, updated_ts):
    """Persist the full archive to disk (not served publicly)."""
    with open(ARCHIVE_PATH, 'w', encoding='utf-8') as f:
        json.dump({
            'updated':  updated_ts,
            'total':    len(articles),
            'articles': articles,
        }, f, ensure_ascii=False, indent=2)
    logging.info(f"Wrote {ARCHIVE_PATH}  ({len(articles)} articles)")


# ============================================================================
# PAGE FILES — split archive into PAGE_SIZE chunks
# ============================================================================

def write_page_files(archive, updated_ts):
    """
    Split the archive into paginated JSON files:
      feed.json      page 1  (articles 0-49)
      feed-2.json    page 2  (articles 50-99)
      ...
      feed-5.json    page 5  (articles 200-249)

    Each file includes pagination metadata so the embed knows
    how many pages exist and which one it's on.
    """
    total_articles = len(archive)
    # Actual number of pages needed (may be less than TOTAL_PAGES early on)
    actual_pages = max(1, (total_articles + PAGE_SIZE - 1) // PAGE_SIZE)

    for page_num in range(1, actual_pages + 1):
        start = (page_num - 1) * PAGE_SIZE
        end   = start + PAGE_SIZE
        slice_ = archive[start:end]

        output = {
            'updated':       updated_ts,
            'page':          page_num,
            'total_pages':   actual_pages,
            'total_articles': total_articles,
            'page_size':     PAGE_SIZE,
            'articles':      slice_,
        }

        path = page_filename(page_num)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        logging.info(f"Wrote {path}  ({len(slice_)} articles, page {page_num}/{actual_pages})")


# ============================================================================
# MAIN
# ============================================================================

def main():
    logging.info("=" * 60)
    logging.info("Cybersecurity News Feed Scraper")
    logging.info("=" * 60)

    updated_ts = datetime.now(timezone.utc).isoformat()

    # 1. Scrape fresh articles from all sources
    new_articles = scrape_all()
    logging.info(f"Scraped {len(new_articles)} unique high-signal articles")

    # 2. Merge with existing archive
    existing = load_archive()
    archive  = merge_into_archive(new_articles, existing)
    logging.info(f"Archive size after merge: {len(archive)} articles")

    # 3. Save archive (private, not served)
    save_archive(archive, updated_ts)

    # 4. Write paginated page files (served by Vercel)
    write_page_files(archive, updated_ts)

    logging.info("Done.")


if __name__ == '__main__':
    main()
