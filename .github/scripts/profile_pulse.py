#!/usr/bin/env python3
"""
profile_pulse.py
================
GitHub Action bot that injects fresh data into README.md between
<!-- DYNAMIC:START --> ... <!-- DYNAMIC:END --> markers.

Sections generated:
  1. operations / recent focus  — last 3 repos with recent commits
  2. live_pulse                 — stars / followers / public_repos delta
                                  + last 24h CVE count from NVD
  3. feed                       — Sploitus CVEs, LinuxDo, Reddit netsec/cybersecurity

Designed to be:
  - idempotent (re-running on a stale README produces same output)
  - rate-limit aware (1 GitHub call per 30s ceiling, 1 NVD call)
  - fail-soft (writes fallback "unavailable" text instead of crashing)

Requires env: GH_TOKEN, GH_USER
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import sys
import time
import datetime as dt
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests

# ---------- config --------------------------------------------------------

GH_USER = os.environ.get("GH_USER", "anonymous99-Rise")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
README_PATH = Path(os.environ.get("README_PATH", "README.md"))
GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# wakatime: optional. If WAKATIME_API_KEY is set, fetch & render real stats.
# If absent, section renders a friendly "not configured" hint instead of failing.
WAKATIME_API_KEY = os.environ.get("WAKATIME_API_KEY", "")
WAKATIME_USER = os.environ.get("WAKATIME_USER", "anonymous99-Rise")

# Feed config: each entry is a dict with keys:
#   type  — "sploitus" or "rss"
#   label — display name for the subsection header
#   url   — RSS URL
#   max   — max items to show
FEEDS = [
    {"type": "sploitus", "label": "sploitus",     "url": "https://sploitus.com/rss",                       "max": 5},
    {"type": "rss",      "label": "steipete",     "url": "https://steipete.me/rss.xml",                     "max": 3},
    {"type": "rss",      "label": "cryptoeng",    "url": "https://blog.cryptographyengineering.com/feed/",  "max": 3},
    {"type": "rss",      "label": "trailofbits",  "url": "https://blog.trailofbits.com/feed/",             "max": 3},
]

# ---------- helpers -------------------------------------------------------

def gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GH_TOKEN:
        h["Authorization"] = f"Bearer {GH_TOKEN}"
    return h


def gh_get(path: str, params: dict | None = None) -> requests.Response | None:
    """GET a GitHub endpoint, return None on any failure (fail-soft)."""
    try:
        r = requests.get(
            f"{GITHUB_API}{path}",
            headers=gh_headers(),
            params=params or {},
            timeout=15,
        )
        if r.status_code == 403 and "rate limit" in r.text.lower():
            print(f"  ! rate-limited on {path}", file=sys.stderr)
            return None
        r.raise_for_status()
        return r
    except Exception as e:
        print(f"  ! gh_get({path}) failed: {e}", file=sys.stderr)
        return None


def nvd_get_recent_24h() -> int | None:
    """Count CVEs published in the last 24h. Public endpoint, no key needed."""
    try:
        end = dt.datetime.utcnow()
        start = end - dt.timedelta(hours=24)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 1,  # we only need totalResults
        }
        r = requests.get(NVD_API, params=params, timeout=20)
        r.raise_for_status()
        return int(r.json().get("totalResults", 0))
    except Exception as e:
        print(f"  ! nvd_get_recent_24h failed: {e}", file=sys.stderr)
        return None


def gh_paginate_total_stars() -> int | None:
    """
    Sum stargazers_count across ALL non-fork, non-archived repos owned by user.
    Walks pagination so we don't undercount (a user with 200+ repos needs > 1 page).
    Returns None on any failure (fail-soft).
    """
    total = 0
    page = 1
    while page <= 10:  # safety cap: 10 * 100 = 1000 repos max
        r = gh_get(f"/users/{GH_USER}/repos", {
            "type": "owner",
            "per_page": 100,
            "page": page,
            "sort": "full_name",  # deterministic order
        })
        if r is None:
            return None
        batch = r.json()
        if not batch:
            break
        for repo in batch:
            if repo.get("fork") or repo.get("archived"):
                continue
            total += repo.get("stargazers_count", 0)
        if len(batch) < 100:
            break
        page += 1
        time.sleep(0.3)  # be polite
    return total


def _parse_pub_date(pub: str) -> str:
    """Normalize an RSS pubDate string to YYYY-MM-DD."""
    if not pub:
        return ""
    try:
        return parsedate_to_datetime(pub).strftime("%Y-%m-%d")
    except Exception:
        return pub[:10]


def _curl_fetch(url: str, headers: list[str]) -> str:
    """Download a URL using curl and return response body as string."""
    curl_cmd = ["curl", "-s", "-L", "--max-time", "15", *headers, url]
    return subprocess.check_output(curl_cmd, stderr=subprocess.DEVNULL).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Sploitus RSS — aggregates CVEs/exploits from multiple sources
# ---------------------------------------------------------------------------
def fetch_sploitus(url: str, max_items: int) -> list[dict]:
    """Parse Sploitus RSS (https://sploitus.com/rss)."""
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "profile-pulse/1.0"})
        r.raise_for_status()
        root = ET.fromstring(r.text)
        items: list[dict] = []
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "#").strip()
            pub = item.findtext("pubDate") or ""
            if title:
                items.append({"title": title, "link": link, "updated": _parse_pub_date(pub)})
            if len(items) >= max_items:
                break
        return items
    except Exception as e:
        print(f"  ! sploitus fetch failed: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# RSS fetcher — handles any generic RSS/Atom feed
# ---------------------------------------------------------------------------
def fetch_rss(url: str, max_items: int) -> list[dict]:
    """Fetch and parse any RSS/Atom feed. Returns list of {title, link, updated}."""
    try:
        r = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        r.raise_for_status()
        root = ET.fromstring(r.text)
        results: list[dict] = []
        for item in root.findall(".//item") + root.findall(".//entry"):
            title = (item.findtext("title") or "").strip()
            # link: RSS uses <link>, Atom uses <link href="...">
            link_elem = item.find("link")
            if link_elem is not None:
                link = link_elem.text or link_elem.get("href") or "#"
            else:
                link = item.findtext("link") or "#"
            link = link.strip()
            pub = item.findtext("pubDate") or item.findtext("published") or item.findtext("updated") or ""
            if title:
                results.append({"title": title, "link": link, "updated": _parse_pub_date(pub)})
            if len(results) >= max_items:
                break
        return results
    except Exception as e:
        print(f"  ! rss fetch failed ({url}): {e}", file=sys.stderr)
        return []


def wakatime_get_summary() -> dict | None:
    """
    Fetch last-7-days coding time from wakatime API.
    Returns dict with 'total_seconds', 'languages' (top 5), 'editors' (top 3),
    or None if WAKATIME_API_KEY not set / call fails.

    Uses HTTP Basic auth (NOT Bearer — wakatime v1 rejects bearer tokens with 401).
    Also fetches user timezone first so the summary query is in the user's
    local tz (UTC fallback if that call fails).
    """
    if not WAKATIME_API_KEY:
        return None
    basic = base64.b64encode(f"{WAKATIME_API_KEY}:".encode()).decode()
    auth = {"Authorization": f"Basic {basic}"}

    try:
        # Step 1: read user info to get the actual timezone.
        # If the user account has no username / never had a heartbeat, this
        # still returns 200 with the registered email + tz.
        u = requests.get(
            "https://wakatime.com/api/v1/users/current",
            headers=auth, timeout=15,
        )
        if u.status_code != 200:
            print(f"  ! wakatime /users/current {u.status_code}: {u.text[:200]}", file=sys.stderr)
            return None
        user = u.json().get("data") or {}
        tz = user.get("timezone") or "UTC"
        last_hb = user.get("last_heartbeat_at")
        last_plugin = user.get("last_plugin")

        # Step 2: query last-7-days summaries in user's local tz.
        end = dt.datetime.utcnow().strftime("%Y-%m-%d")
        start = (dt.datetime.utcnow() - dt.timedelta(days=7)).strftime("%Y-%m-%d")
        r = requests.get(
            "https://wakatime.com/api/v1/users/current/summaries",
            params={"start": start, "end": end, "timezone": tz},
            headers=auth, timeout=15,
        )
        if r.status_code != 200:
            print(f"  ! wakatime /summaries {r.status_code}: {r.text[:200]}", file=sys.stderr)
            return None
        data = r.json()
        total_sec = 0
        lang_agg: dict[str, int] = {}
        editor_agg: dict[str, int] = {}
        for day in data.get("data", []):
            for summary in day.get("languages", []) or []:
                sec = summary.get("total_seconds", 0) or 0
                total_sec += sec
                name = summary.get("name") or "Other"
                lang_agg[name] = lang_agg.get(name, 0) + sec
            for ed in day.get("editors", []) or []:
                sec = ed.get("total_seconds", 0) or 0
                editor_agg[ed.get("name", "Unknown")] = editor_agg.get(ed.get("name", "Unknown"), 0) + sec
        return {
            "total_seconds": total_sec,
            "languages": sorted(lang_agg.items(), key=lambda x: -x[1])[:5],
            "editors": sorted(editor_agg.items(), key=lambda x: -x[1])[:3],
            "range": f"{start} → {end}",
            "tz": tz,
            "last_heartbeat_at": last_hb,
            "last_plugin": last_plugin,
        }
    except Exception as e:
        print(f"  ! wakatime failed: {e}", file=sys.stderr)
        return None


def fmt_duration(seconds: int) -> str:
    if seconds <= 0:
        return "0m"
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def now_utc() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")


# ---------- data builders -------------------------------------------------

def build_operations() -> str:
    """Fetch user's repos, pick 3 most recently pushed, format as tree."""
    print("→ fetching recent activity…")
    r = gh_get(f"/users/{GH_USER}/repos", {
        "sort": "pushed",
        "direction": "desc",
        "per_page": 8,
        "type": "owner",
    })
    if r is None:
        return _fallback_block("recent focus", "gh api unavailable")

    repos = [repo for repo in r.json() if not repo.get("archived") and not repo.get("fork")]
    top3 = repos[:3]

    if not top3:
        return _fallback_block("recent focus", "no active repos found")

    # static learning block stays the same — it's about you, not your repos
    learning = """[+] currently learning
    ├── langgraph deep dive — durable execution semantics
    ├── mitre d3fend mappings for blue-side tooling
    └── riscv assembly for embedded payload research"""

    lines = ["[+] recent focus"]
    for i, repo in enumerate(top3, 1):
        connector = "└──" if i == len(top3) else "├──"
        pushed = repo["pushed_at"][:10]  # YYYY-MM-DD
        name = repo["name"]
        desc = (repo.get("description") or "").strip().split("\n")[0]
        if len(desc) > 60:
            desc = desc[:57] + "…"
        lang = repo.get("language") or "—"
        lines.append(f"    {connector} {name} ({lang}, pushed {pushed}) — {desc or 'no description'}")
    lines.append("")
    return "```text\n" + "\n".join(lines) + "\n" + learning + "\n```"


def build_pulse() -> str:
    """Live stats: follower count, total stars (paginated), public repos, last 24h CVEs."""
    print("→ fetching profile + paginated stars + 24h CVE count…")
    r = gh_get(f"/users/{GH_USER}")
    cve_24h = nvd_get_recent_24h()

    if r is None:
        return _fallback_block("live_pulse", "gh api unavailable", wrap_in_sub=True)

    u = r.json()
    followers = u.get("followers", 0)
    following = u.get("following", 0)
    public_repos = u.get("public_repos", 0)

    # Paginated real total stars (walks pages, not just 100 most recent)
    total_stars = gh_paginate_total_stars() or 0

    cve_str = f"{cve_24h}" if cve_24h is not None else "n/a"

    md = (
        f'<div align="center">\n\n'
        f'![followers](https://img.shields.io/badge/followers-{followers}-8A2BE2?style=for-the-badge&logo=github&logoColor=white) '
        f'![following](https://img.shields.io/badge/following-{following}-FF6B35?style=for-the-badge&logo=github&logoColor=white) '
        f'![public_repos](https://img.shields.io/badge/repos-{public_repos}-3178C6?style=for-the-badge&logo=github&logoColor=white) '
        f'![total_stars](https://img.shields.io/badge/stars-{total_stars}-DC143C?style=for-the-badge&logo=github&logoColor=white) '
        f'![cve_24h](https://img.shields.io/badge/CVE_24h-{cve_str}-D93B3B?style=for-the-badge&logo=commonvulnerabilitiesandexposures&logoColor=white)\n\n'
        f'<sub>🤖 auto-refreshed by <code>profile-pulse.yml</code> · last pulse <code>{now_utc()}</code> · '
        f'<a href="commits/main/.github/workflows/profile-pulse.yml">history</a></sub>\n\n'
        f'</div>'
    )
    return md


def build_feed() -> str:
    """Render feed items from multiple source types: sploitus, rss."""
    print("→ fetching feeds…")
    sections: list[str] = []

    for feed in FEEDS:
        feed_type = feed["type"]
        label = feed["label"]
        url = feed["url"]
        max_items = feed["max"]

        if feed_type == "sploitus":
            items = fetch_sploitus(url, max_items)
        else:
            items = fetch_rss(url, max_items)

        if items:
            print(f"  ✓ {label}: {len(items)} items")
        else:
            print(f"  ! {label}: no items (source may be blocked)")

        if not items:
            continue

        rows = []
        for item in items:
            title = item["title"]
            if len(title) > 70:
                title = title[:67] + "…"
            rows.append(f"- <code>{item['updated']}</code> · [{title}]({item['link']})")

        if feed_type == "sploitus":
            sections.append(f"#### ▸ Sploitus (exploits & CVEs)\n\n" + "\n".join(rows))
        else:
            sections.append(f"#### ▸ [{label}]({url})\n\n" + "\n".join(rows))

    if not sections:
        # All feeds failed. Render a graceful fallback with direct links.
        return (
            "\n"
            "⏳ feeds blocked from GitHub Actions runner · "
            "[Sploitus](https://sploitus.com) · "
            "[steipete](https://steipete.me) · "
            "[cryptoeng](https://blog.cryptographyengineering.com) · "
            "[trailofbits](https://blog.trailofbits.com)\n"
        )

    return "\n\n".join(sections)


def build_wakatime() -> str:
    """Render last-7-days coding stats. Graceful when token absent or new account."""
    print("→ fetching wakatime summary…")
    summary = wakatime_get_summary()

    if summary is None:
        # Token not set OR API failed — both render the same helpful hint
        return (
            '<sub align="center">⏳ wakatime not configured · '
            'set <code>WAKATIME_API_KEY</code> secret to enable · '
            'see <a href="https://wakatime.com/settings/api-key">wakatime.com/settings/api-key</a></sub>'
        )

    total = fmt_duration(summary["total_seconds"])

    # New account with zero heartbeats — guide the user to install the plugin
    if not summary["languages"] and not summary["last_heartbeat_at"]:
        return (
            f'<sub align="center">⏳ wakatime account is empty ({summary["range"]}, tz={summary["tz"]}) · '
            f'install the <a href="https://wakatime.com/plugins">wakatime plugin</a> for your editor to start tracking</sub>'
        )

    if not summary["languages"]:
        return f'<sub align="center">⏳ no wakatime data in last 7 days ({summary["range"]}, tz={summary["tz"]})</sub>'

    # build inline language list with bar chars
    max_sec = max(sec for _, sec in summary["languages"]) or 1
    lang_lines = []
    for name, sec in summary["languages"]:
        bar_pct = int((sec / max_sec) * 10)
        bar = "█" * bar_pct + "░" * (10 - bar_pct)
        lang_lines.append(f"- `{name:<12}` {bar} {fmt_duration(sec)}")

    editor_str = ", ".join(f"`{n}` ({fmt_duration(s)})" for n, s in summary["editors"]) or "—"

    return (
        f"**`{total}`** coded in last 7 days · editors: {editor_str}\n\n"
        + "\n".join(lang_lines)
        + f"\n\n<sub>range: {summary['range']} · tz: {summary['tz']} · source: wakatime API</sub>"
    )


def _fallback_block(label: str, reason: str, wrap_in_sub: bool = False) -> str:
    """Return a safe placeholder when an API call fails — never blow up the workflow."""
    if wrap_in_sub:
        return f'<sub align="center">⏳ pulse unavailable ({reason}) · try again next run</sub>'
    return f"```text\n[+] {label}\n    └── data unavailable ({reason})\n```"


# ---------- README patcher -----------------------------------------------

MARKER_RE = re.compile(
    r"<!-- DYNAMIC:START -->(.*?)<!-- DYNAMIC:END -->",
    re.DOTALL,
)


def inject(readme_text: str, heading: str, new_content: str) -> str:
    """
    Find the section whose H2 heading == `heading` and replace the FIRST
    <!-- DYNAMIC:START --> ... <!-- DYNAMIC:END --> block inside it with
    `new_content`. If no marker pair found, no-op (returns text unchanged).
    """
    # locate heading line: ## anything (case-insensitive, handles emoji)
    h_re = re.compile(rf"^##.*{re.escape(heading)}.*$", re.MULTILINE | re.IGNORECASE)
    m_h = h_re.search(readme_text)
    if not m_h:
        print(f"  ! heading '{heading}' not found, skipping", file=sys.stderr)
        return readme_text

    # find next DYNAMIC block after heading
    after_heading = readme_text[m_h.end():]
    m_d = MARKER_RE.search(after_heading)
    if not m_d:
        print(f"  ! DYNAMIC markers missing under '{heading}'", file=sys.stderr)
        return readme_text

    absolute_start = m_h.end() + m_d.start()
    absolute_end = m_h.end() + m_d.end()
    replacement = f"<!-- DYNAMIC:START -->\n{new_content}\n<!-- DYNAMIC:END -->"
    return readme_text[:absolute_start] + replacement + readme_text[absolute_end:]


# ---------- main ---------------------------------------------------------

def main() -> int:
    if not README_PATH.exists():
        print(f"  ! {README_PATH} not found", file=sys.stderr)
        return 1

    text = README_PATH.read_text(encoding="utf-8")
    original = text

    text = inject(text, "operations", build_operations())
    time.sleep(0.5)  # be polite to GitHub API
    text = inject(text, "live_pulse", build_pulse())
    text = inject(text, "feed", build_feed())
    text = inject(text, "wakatime", build_wakatime())

    if text == original:
        print("✓ nothing to update")
        return 0

    README_PATH.write_text(text, encoding="utf-8")
    print("✓ README.md updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
