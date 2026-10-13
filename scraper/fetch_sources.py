"""
抓取層 (Collector)
依 config/sources.yaml 設定的來源清單抓取最新情資，正規化成統一格式，
並用 data/seen.json 做去重，避免同一則情資重複進入後續流程。

新增來源只需改 config/sources.yaml，不需要動這支程式（可擴展性設計）。
"""
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import feedparser
import requests
import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "sources.yaml")
SEEN_PATH = os.path.join(BASE_DIR, "data", "seen.json")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_seen():
    if not os.path.exists(SEEN_PATH):
        return set()
    with open(SEEN_PATH, "r", encoding="utf-8") as f:
        return set(json.load(f))


def save_seen(seen_ids):
    os.makedirs(os.path.dirname(SEEN_PATH), exist_ok=True)
    # 只保留最近 5000 筆，避免檔案無限長大
    trimmed = list(seen_ids)[-5000:]
    with open(SEEN_PATH, "w", encoding="utf-8") as f:
        json.dump(trimmed, f, ensure_ascii=False, indent=2)


def make_id(url, title):
    raw = f"{url}|{title}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def parse_rss(source, cutoff):
    items = []
    try:
        feed = feedparser.parse(source["url"])
    except Exception as e:
        print(f"[WARN] 抓取 RSS 失敗: {source['id']} - {e}", file=sys.stderr)
        return items

    for entry in feed.entries:
        published = None
        for key in ("published_parsed", "updated_parsed"):
            if getattr(entry, key, None):
                published = datetime(*getattr(entry, key)[:6], tzinfo=timezone.utc)
                break
        if published is None:
            published = datetime.now(timezone.utc)
        if published < cutoff:
            continue

        items.append({
            "source_id": source["id"],
            "source_name": source["name"],
            "org": source["org"],
            "category_hint": source.get("category", "news"),
            "title": entry.get("title", "").strip(),
            "url": entry.get("link", "").strip(),
            "published": published.strftime("%Y-%m-%d"),
            "raw_summary": (entry.get("summary", "") or "")[:3000],
        })
    return items


def parse_cisa_kev(source, cutoff):
    items = []
    try:
        resp = requests.get(source["url"], timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[WARN] 抓取 CISA KEV 失敗: {e}", file=sys.stderr)
        return items

    for vuln in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if added < cutoff:
            continue

        title = f"{vuln.get('cveID')} — {vuln.get('vulnerabilityName', '')}"
        items.append({
            "source_id": source["id"],
            "source_name": source["name"],
            "org": source["org"],
            "category_hint": source.get("category", "vuln"),
            "title": title,
            "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID')}",
            "published": vuln["dateAdded"],
            "raw_summary": (
                f"廠商/產品: {vuln.get('vendorProject')} {vuln.get('product')}\n"
                f"說明: {vuln.get('shortDescription')}\n"
                f"要求行動: {vuln.get('requiredAction')}\n"
                f"截止日: {vuln.get('dueDate')}"
            ),
            "cve_id": vuln.get("cveID"),
        })
    return items


FETCHERS = {
    "rss": parse_rss,
    "cisa_kev": parse_cisa_kev,
}


def fetch_all():
    config = load_config()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=config.get("lookback_hours", 30))
    max_per_source = config.get("max_items_per_source", 5)
    seen = load_seen()

    new_items = []
    for source in config["sources"]:
        fetcher = FETCHERS.get(source["type"])
        if not fetcher:
            print(f"[WARN] 未知的來源類型: {source['type']} ({source['id']})", file=sys.stderr)
            continue

        items = fetcher(source, cutoff)[:max_per_source]
        for item in items:
            item_id = make_id(item["url"], item["title"])
            if item_id in seen:
                continue
            item["id"] = item_id
            new_items.append(item)
            seen.add(item_id)

    save_seen(seen)
    return new_items


if __name__ == "__main__":
    results = fetch_all()
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"\n共抓到 {len(results)} 則新情資", file=sys.stderr)
