import asyncio
import json
import urllib.parse
import aiohttp
from bs4 import BeautifulSoup

PLATFORMS = {
    "GitHub (API)": {
        "url": "https://api.github.com/users/{}",
        "profile_url": "https://github.com/{}",
        "check_type": "status_only",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "profile_url": "https://www.reddit.com/user/{}",
        "error_msg": '"error": 404',
    },
    "Dev.to": {
        "url": "https://dev.to/{}",
        "profile_url": "https://dev.to/{}",
        "error_msg": "This page does not exist",
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "profile_url": "https://medium.com/@{}",
        "error_msg": "PAGE NOT FOUND",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{}/",
        "profile_url": "https://pypi.org/user/{}/",
        "error_msg": "We looked everywhere",
    },
    "Keybase": {
        "url": "https://keybase.io/{}",
        "profile_url": "https://keybase.io/{}",
        "error_msg": "Not a user",
    },
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

TIMEOUT = aiohttp.ClientTimeout(total=25)


async def check_platform(session, platform, config, username):
    url = config["url"].format(username)
    profile_url = config["profile_url"].format(username)
    try:
        async with session.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True) as response:
            if config.get("check_type") == "status_only":
                status = "FOUND" if response.status == 200 else "NOT FOUND"
                return {"platform": platform, "url": profile_url, "status": status}

            if response.status in (403, 429):
                return {"platform": platform, "url": profile_url, "status": f"BLOCKED ({response.status})"}
            if response.status == 404:
                return {"platform": platform, "url": profile_url, "status": "NOT FOUND"}

            text = await response.text(errors="replace")
            if response.status == 200 and config.get("error_msg", "") not in text:
                return {"platform": platform, "url": profile_url, "status": "FOUND"}
            return {"platform": platform, "url": profile_url, "status": "NOT FOUND"}
    except Exception as e:
        return {"platform": platform, "url": profile_url, "status": f"ERROR ({type(e).__name__})"}


async def fetch_github_details(session, username):
    api_url = f"https://api.github.com/users/{username}"
    api_headers = {
        **HEADERS,
        "Accept": "application/vnd.github+json",
    }
    try:
        async with session.get(api_url, headers=api_headers, timeout=TIMEOUT) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "name": data.get("name"),
                    "bio": data.get("bio"),
                    "location": data.get("location"),
                    "company": data.get("company"),
                    "public_repos": data.get("public_repos"),
                    "blog": data.get("blog"),
                }
    except Exception:
        pass
    return None


async def search_web_mentions(session, query):
    """Search DuckDuckGo HTML endpoint for open-web mentions of a name or username."""
    encoded = urllib.parse.quote_plus(f'"{query}"')
    search_url = f"https://html.duckduckgo.com/html/?q={encoded}"
    mentions = []
    try:
        async with session.get(search_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True) as response:
            if response.status == 200:
                html = await response.text(errors="replace")
                soup = BeautifulSoup(html, "html.parser")
                for result in soup.select(".result__body")[:5]:
                    title_tag = result.select_one(".result__a")
                    snippet_tag = result.select_one(".result__snippet")
                    if title_tag:
                        mentions.append({
                            "title": title_tag.get_text(strip=True),
                            "link": title_tag.get("href"),
                            "snippet": snippet_tag.get_text(strip=True) if snippet_tag else "",
                        })
            else:
                print(f"[!] Web search returned HTTP {response.status}")
    except Exception as e:
        print(f"[!] Web search error: {type(e).__name__}")
    return mentions


async def run_osint(target):
    clean_target = target.strip().lstrip("@")
    print(f"\n[*] Scanning public sources for: {clean_target}\n")
    connector = aiohttp.TCPConnector(limit=3)
    async with aiohttp.ClientSession(connector=connector) as session:
        found_profiles = []
        github_info = None

        if " " not in clean_target:
            tasks = [
                check_platform(session, name, cfg, clean_target)
                for name, cfg in PLATFORMS.items()
            ]
            results = await asyncio.gather(*tasks)
            found_profiles = [r for r in results if r["status"] == "FOUND"]

            for r in results:
                marker = "[+]" if r["status"] == "FOUND" else "[-]"
                print(f"{marker} {r['platform']}: {r['status']} -> {r['url']}")

            github_info = await fetch_github_details(session, clean_target)
            if github_info:
                print("\n[*] Enriched GitHub Metadata:")
                for key, value in github_info.items():
                    if value is not None and value != "":
                        print(f"    - {key.capitalize()}: {value}")
        else:
            print("[*] Full name detected — skipping username-only URLs and running open-web search...")

        print("\n[*] Searching Open Web Mentions:")
        mentions = await search_web_mentions(session, clean_target)
        if mentions:
            for m in mentions:
                print(f"    [+] {m['title']}")
                print(f"        URL: {m['link']}")
                if m["snippet"]:
                    print(f"        Info: {m['snippet'][:120]}...")
        else:
            print("    [-] No direct web mentions returned (or search rate-limited).")

        report = {
            "target": clean_target,
            "found_profiles": found_profiles,
            "github_metadata": github_info,
            "web_mentions": mentions,
        }
        safe_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in clean_target.lower())
        filename = f"{safe_name or 'target'}_report.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"\n[*] Full report saved to {filename}")


if __name__ == "__main__":
    target = input("Enter a username or full name to search: ").strip()
    if target:
        asyncio.run(run_osint(target))
