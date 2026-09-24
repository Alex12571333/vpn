#!/usr/bin/env python3
"""Collect public VPN URI subscriptions and build Happ/Incy import files."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "docs"
TIMEOUT = 30
MAX_BYTES = 20 * 1024 * 1024
URI_RE = re.compile(r"(?im)(?:^|[\s\"'])((?:vless|vmess|trojan|ss|ssr|tuic|hysteria2|hy2|wireguard)://[^\s\"'<>]+)")
SUPPORTED = {"vless", "vmess", "trojan", "ss", "ssr", "tuic", "hysteria2", "hy2", "wireguard"}

# Keep sources to public text subscription endpoints; never clone or execute repositories.
SOURCES = {
    "all_subs": [
        "https://raw.githubusercontent.com/solovyov-jenya2004/all_subs/main/final_sorted",
    ],
    "igareck": [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    ],
    "vless-checker": [
        "https://raw.githubusercontent.com/tiagorrg/vless-checker/main/docs/keys.json",
    ],
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "personal-vpn-subscription-aggregator/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response exceeds 20 MiB limit")
    return data


def find_uris(payload: bytes) -> list[str]:
    text = payload.decode("utf-8-sig", errors="replace")
    # JSON may contain escaped URL separators; parse strings recursively first.
    try:
        obj = json.loads(text)
        strings: list[str] = []

        def walk(value: object) -> None:
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(obj)
        text = "\n".join(strings)
    except (json.JSONDecodeError, RecursionError):
        pass

    result = []
    for match in URI_RE.findall(text):
        uri = match.rstrip(",;)]}")
        try:
            if urlsplit(uri).scheme.lower() in SUPPORTED:
                result.append(uri)
        except ValueError:
            continue
    return result


def sort_key(uri: str) -> tuple[str, str, str, str]:
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    label = unquote(parsed.fragment).lower()
    # Keep each protocol together, then sort by displayed location/name and endpoint.
    return scheme, label, host, uri


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def main() -> int:
    collected: list[str] = []
    failures: list[str] = []
    for source, urls in SOURCES.items():
        source_count = 0
        for url in urls:
            try:
                found = find_uris(fetch(url))
                source_count += len(found)
                collected.extend(found)
            except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                failures.append(f"{source}: {url} ({exc})")
        print(f"{source}: найдено {source_count} конфигураций", file=sys.stderr)

    # Exact URI de-duplication preserves per-source server names while preventing repeats.
    unique = list(dict.fromkeys(uri.strip() for uri in collected if uri.strip()))
    if not unique:
        print("Не получено ни одной конфигурации; существующие файлы не изменены.", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    unique.sort(key=sort_key)
    plain = ("\n".join(unique) + "\n").encode("utf-8")
    encoded = base64.b64encode(plain) + b"\n"
    atomic_write(OUT / "subscription.txt", plain)
    atomic_write(OUT / "subscription.base64", encoded)
    metadata = {
        "servers": len(unique),
        "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sources": list(SOURCES),
        "failed_sources": failures,
    }
    atomic_write(OUT / "status.json", (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode())
    page = f'''<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Моя VPN-подписка</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0b1020;color:#e7ecf7;font:16px/1.55 system-ui,sans-serif;display:grid;min-height:100vh;place-items:center;padding:24px}}
main{{width:min(680px,100%);padding:36px;border:1px solid #26314c;border-radius:24px;background:linear-gradient(145deg,#151f36,#101729);box-shadow:0 24px 80px #0006}}
h1{{margin:0 0 8px;font-size:clamp(28px,6vw,42px)}}p{{color:#aab6d0}}.count{{font-size:14px;color:#6ee7b7}}
a{{display:block;margin-top:14px;padding:16px 18px;border-radius:14px;background:#202d49;color:#fff;text-decoration:none;font-weight:650}}a:hover{{background:#2b3c60}}
small{{display:block;margin-top:24px;color:#8290ae}}
</style><main><h1>VPN-подписка</h1><p>Собранный список конфигураций для импорта в Happ и Incy.</p>
<div class="count">{len(unique)} серверов · обновлено {metadata['updated_at_utc']}</div>
<a href="subscription.txt">Открыть подписку · обычный формат</a>
<a href="subscription.base64">Открыть подписку · Base64</a>
<small>Список автоматически обновляется каждый час. Доступность узлов может меняться.</small></main></html>
'''
    atomic_write(OUT / "index.html", page.encode("utf-8"))
    print(f"Готово: {len(unique)} уникальных конфигураций → {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
