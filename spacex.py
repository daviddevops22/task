#!/usr/bin/env python3
"""
SpaceX Launches — Python CLI with argparse

- Fetches SpaceX launches data from https://api.spacexdata.com/v4/launches
- Caches raw JSON to a local file
- Filters launches for year 2022 based on date_utc
- Supports actions:
  - report: totals, success/fail, success ratio excluding success == None
  - payloads: average payload count per launch (missing payloads treated as 0)
  - launchpads: count launches per launchpad id (missing -> "unknown"), sorted desc
- Robustness: 15s timeout, retry once on timeout, non-200 => error + non-zero exit

Usage examples:
  python spacex.py --action report
  python spacex.py --action payloads -v
  python spacex.py --action launchpads --refresh --cache .cache/launches.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: Missing dependency 'requests'. Install it with: pip install requests", file=sys.stderr)
    sys.exit(2)

API_URL = "https://api.spacexdata.com/v4/launches"
DEFAULT_CACHE_PATH = "launches.json"
HTTP_TIMEOUT_SECONDS = 15


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        logging.debug("Creating cache directory: %s", parent)
        os.makedirs(parent, exist_ok=True)


def load_cache(path: str) -> Optional[List[Dict[str, Any]]]:
    if not os.path.exists(path):
        logging.debug("Cache does not exist at: %s", path)
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            logging.warning("Cache file is not a JSON list: %s", path)
            return None
        logging.debug("Loaded %d records from cache: %s", len(data), path)
        return data
    except (OSError, json.JSONDecodeError) as e:
        logging.warning("Failed to read/parse cache '%s': %s", path, e)
        return None


def save_cache(path: str, data: List[Dict[str, Any]]) -> None:
    ensure_parent_dir(path)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logging.debug("Saved %d records to cache: %s", len(data), path)
    except OSError as e:
        # Cache failure should not necessarily kill the program, but is useful to warn.
        logging.warning("Failed to write cache '%s': %s", path, e)


def fetch_launches_with_retry(url: str, timeout_s: int, retry_on_timeout: int = 1) -> List[Dict[str, Any]]:
    """
    Fetch JSON list from API.
    - Timeout: timeout_s seconds
    - Retry once on timeout (requests.exceptions.Timeout)
    - On non-200: print error and exit non-zero
    """
    attempts = 0
    timeouts = 0
    while True:
        attempts += 1
        try:
            logging.debug("HTTP GET %s (attempt %d)", url, attempts)
            resp = requests.get(url, timeout=timeout_s)
        except requests.exceptions.Timeout:
            timeouts += 1
            logging.warning("Request timed out after %ds (attempt %d)", timeout_s, attempts)
            if timeouts <= retry_on_timeout:
                logging.info("Retrying once due to timeout...")
                continue
            print(f"ERROR: Request timed out after {timeout_s}s (retried).", file=sys.stderr)
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network error while fetching data: {e}", file=sys.stderr)
            sys.exit(1)

        if resp.status_code != 200:
            # Clear error message + non-zero exit code required
            snippet = resp.text[:300].replace("\n", " ").strip() if resp.text else ""
            print(
                f"ERROR: API returned HTTP {resp.status_code}. Response: {snippet}",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            data = resp.json()
        except ValueError as e:
            print(f"ERROR: Failed to decode JSON response: {e}", file=sys.stderr)
            sys.exit(1)

        if not isinstance(data, list):
            print("ERROR: API returned JSON that is not a list.", file=sys.stderr)
            sys.exit(1)

        logging.debug("Fetched %d records from API", len(data))
        return data


def parse_date_utc(date_str: Any) -> Optional[datetime]:
    """
    Parse date_utc from SpaceX. Expected ISO string like "2022-01-13T15:25:00.000Z"
    Return aware datetime in UTC or None if invalid.
    """
    if not isinstance(date_str, str) or not date_str.strip():
        return None

    s = date_str.strip()
    # Handle trailing Z for UTC
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            # assume UTC if missing tz
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def filter_launches_2022(launches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep only launches whose date_utc falls within year 2022 (UTC).
    Skip entries with invalid or missing dates.
    """
    out: List[Dict[str, Any]] = []
    for item in launches:
        if not isinstance(item, dict):
            continue
        dt = parse_date_utc(item.get("date_utc"))
        if dt is None:
            logging.debug("Skipping launch with invalid/missing date_utc: %r", item.get("id", "<no id>"))
            continue
        if dt.year == 2022:
            out.append(item)
    logging.debug("Filtered to %d launches in year 2022", len(out))
    return out


def action_report(launches_2022: List[Dict[str, Any]]) -> None:
    total = len(launches_2022)

    success_true = 0
    success_false = 0
    success_known = 0  # counts only success is True/False (excludes None)

    for l in launches_2022:
        success = l.get("success", None)
        if success is True:
            success_true += 1
            success_known += 1
        elif success is False:
            success_false += 1
            success_known += 1
        else:
            # success == None or missing: excluded from ratio denominator
            pass

    ratio = 0
    if success_known > 0:
        ratio = round((success_true / success_known) * 100)

    print("Year 2022 summary:")
    print(f"Total: {total} | Successful: {success_true} | Failed: {success_false} | Success ratio: {ratio}%")


def action_payloads(launches_2022: List[Dict[str, Any]]) -> None:
    total = len(launches_2022)
    if total == 0:
        print("Average payloads per launch:0.00")
        return

    payload_counts = []
    for l in launches_2022:
        payloads = l.get("payloads", None)
        if isinstance(payloads, list):
            payload_counts.append(len(payloads))
        else:
            payload_counts.append(0)

    avg = sum(payload_counts) / total
    print(f"Average payloads per launch:{avg:.2f}")


def action_launchpads(launches_2022: List[Dict[str, Any]]) -> None:
    counts: Dict[str, int] = {}
    for l in launches_2022:
        launchpad = l.get("launchpad", None)
        key = launchpad if isinstance(launchpad, str) and launchpad.strip() else "unknown"
        counts[key] = counts.get(key, 0) + 1

    # Sort by count desc, then key asc for stability
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    for launchpad_id, cnt in items:
        print(f"{launchpad_id} — {cnt}")


def get_data(cache_path: str, refresh: bool) -> List[Dict[str, Any]]:
    if not refresh:
        cached = load_cache(cache_path)
        if cached is not None:
            logging.info("Using cached data: %s", cache_path)
            return cached

    logging.info("Fetching data from API: %s", API_URL)
    data = fetch_launches_with_retry(API_URL, timeout_s=HTTP_TIMEOUT_SECONDS, retry_on_timeout=1)
    save_cache(cache_path, data)
    return data


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SpaceX Launches CLI: fetch launches, cache JSON, and print 2022 summaries."
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["report", "payloads", "launchpads"],
        help="Which report to generate.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore cache and refetch from API.",
    )
    parser.add_argument(
        "--cache",
        default=DEFAULT_CACHE_PATH,
        help=f"Path to cache file (default: {DEFAULT_CACHE_PATH}).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    logging.debug("Arguments: %s", vars(args))

    launches = get_data(cache_path=args.cache, refresh=args.refresh)
    launches_2022 = filter_launches_2022(launches)

    if args.action == "report":
        action_report(launches_2022)
    elif args.action == "payloads":
        action_payloads(launches_2022)
    elif args.action == "launchpads":
        action_launchpads(launches_2022)
    else:
        # Should be unreachable due to argparse choices
        print(f"ERROR: Unknown action: {args.action}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
