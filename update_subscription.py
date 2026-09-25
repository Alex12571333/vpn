#!/usr/bin/env python3
"""Build small, latency-ranked Happ/Incy pools from public VPN feeds."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import html
import ipaddress
import json
import math
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "docs"
TIMEOUT = 20
TCP_TIMEOUT = 2.0
MAX_BYTES = 25 * 1024 * 1024
MAX_CANDIDATES_PER_POOL = 1500
MAX_GEOLOOKUPS_PER_RUN = 30
NORMAL_LIMIT = 5
WHITELIST_LIMIT = 10
MAX_SERVERS_PER_COUNTRY = 2
PROFILE_TITLE = "velesVPN free"
SCHEMES = {"vless", "vmess", "trojan", "ss", "ssr", "tuic", "hysteria2", "hy2"}
URI_RE = re.compile(r"(?im)(?:^|[\s\"'])((?:vless|vmess|trojan|ss|ssr|tuic|hysteria2|hy2)://[^\s\"'<>]+)")

SOURCES = {
    "normal": {
        "igareck_black": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
        "vless_checker": "https://raw.githubusercontent.com/tiagorrg/vless-checker/main/docs/keys.json",
    },
    "whitelist": {
        "all_subs": "https://raw.githubusercontent.com/solovyov-jenya2004/all_subs/main/final_sorted",
        "igareck_white_cidr": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
        "vless_checker": "https://raw.githubusercontent.com/tiagorrg/vless-checker/main/docs/keys.json",
    },
}


@dataclass
class Candidate:
    uri: str
    source: str
    source_latency_ms: float | None = None
    location_hint: str | None = None
    geo_location: str | None = None

    @property
    def endpoint(self) -> tuple[str, int] | None:
        try:
            parsed = urlsplit(self.uri)
            if parsed.scheme.lower() not in SCHEMES or not parsed.hostname or not parsed.port:
                return None
            return parsed.hostname.lower(), parsed.port
        except ValueError:
            return None


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "vpn-subscription-pool/1.0"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        payload = response.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("response exceeds 25 MiB limit")
    return payload


def extract_uris(payload: bytes) -> list[str]:
    text = payload.decode("utf-8-sig", errors="replace")
    found: list[str] = []
    for match in URI_RE.findall(text):
        try:
            if urlsplit(match).scheme.lower() in SCHEMES:
                found.append(match.rstrip(",;)]}"))
        except ValueError:
            continue
    return found


def all_subs_is_whitelist_feed(payload: bytes) -> bool:
    """Fail closed if the upstream stops identifying itself as a whitelist feed."""
    text = payload.decode("utf-8-sig", errors="replace")
    first_uri = URI_RE.search(text)
    header = text[:first_uri.start()] if first_uri else text[:8192]
    header = header.lower()
    return "profile-title" in header and any(marker in header for marker in
                                               ("белых списк", "white list", "whitelist"))


def checker_candidates(data: object, pool: str) -> list[Candidate]:
    if not isinstance(data, dict):
        return []
    found: list[Candidate] = []
    for group, contents in data.items():
        is_whitelist = isinstance(group, str) and (group.startswith("w_") or group == "russia")
        if is_whitelist != (pool == "whitelist"):
            continue
        # The checker's "other_countries" result is a map of country -> ranked results.
        sections = contents.items() if group == "other_countries" and isinstance(contents, dict) else [(group, contents)]
        for section_name, section in sections:
            if not isinstance(section, dict):
                continue
            entries = section.get("top10", [])
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                uri = item.get("key")
                latency = item.get("latency_ms")
                if not isinstance(uri, str):
                    continue
                try:
                    latency_value = float(latency)
                    if not math.isfinite(latency_value) or latency_value < 0:
                        latency_value = None
                except (TypeError, ValueError):
                    latency_value = None
                if urlsplit(uri).scheme.lower() in SCHEMES:
                    hint = section_name.removeprefix("w_") if isinstance(section_name, str) else None
                    found.append(Candidate(uri.strip(), "vless-checker", latency_value, hint))
    return found


COUNTRIES = [
    (("germany", "deutschland", "германия"), "🇩🇪 Германия"),
    (("czechia", "czech republic", "чехия"), "🇨🇿 Чехия"),
    (("finland", "финляндия"), "🇫🇮 Финляндия"),
    (("poland", "польша"), "🇵🇱 Польша"),
    (("netherlands", "нужерланды", "holland", "нидерланды"), "🇳🇱 Нидерланды"),
    (("sweden", "швеция"), "🇸🇪 Швеция"),
    (("estonia", "эстония"), "🇪🇪 Эстония"),
    (("latvia", "латвия"), "🇱🇻 Латвия"),
    (("lithuania", "литва"), "🇱🇹 Литва"),
    (("france", "франция"), "🇫🇷 Франция"),
    (("united states", "usa", "сша"), "🇺🇸 США"),
    (("united kingdom", "uk", "британия", "англия"), "🇬🇧 Великобритания"),
    (("singapore", "сингапур"), "🇸🇬 Сингапур"),
    (("japan", "япония"), "🇯🇵 Япония"),
    (("turkey", "türkiye", "турция"), "🇹🇷 Турция"),
    (("austria", "австрия"), "🇦🇹 Австрия"),
    (("switzerland", "швейцария"), "🇨🇭 Швейцария"),
    (("canada", "канада"), "🇨🇦 Канада"),
    (("norway", "норвегия"), "🇳🇴 Норвегия"),
    (("belgium", "бельгия"), "🇧🇪 Бельгия"),
    (("italy", "италия"), "🇮🇹 Италия"),
    (("spain", "испания"), "🇪🇸 Испания"),
    (("ukraine", "украина"), "🇺🇦 Украина"),
    (("israel", "израиль"), "🇮🇱 Израиль"),
    (("china", "китай"), "🇨🇳 Китай"),
    (("hong kong", "гонконг"), "🇭🇰 Гонконг"),
    (("uae", "united arab emirates", "оаэ"), "🇦🇪 ОАЭ"),
    (("ireland", "ирландия"), "🇮🇪 Ирландия"),
    (("greece", "греция"), "🇬🇷 Греция"),
    (("portugal", "португалия"), "🇵🇹 Португалия"),
    (("romania", "румыния"), "🇷🇴 Румыния"),
    (("bulgaria", "болгария"), "🇧🇬 Болгария"),
    (("serbia", "сербия"), "🇷🇸 Сербия"),
    (("luxembourg", "люксембург"), "🇱🇺 Люксембург"),
    (("iceland", "исландия"), "🇮🇸 Исландия"),
    (("georgia", "грузия"), "🇬🇪 Грузия"),
    (("russia", "россия"), "🇷🇺 Россия"),
]
CITY_NAMES = {
    "frankfurt": "Франкфурт", "frankfurt am main": "Франкфурт",
    "prague": "Прага", "warsaw": "Варшава", "helsinki": "Хельсинки",
    "amsterdam": "Амстердам", "stockholm": "Стокгольм", "paris": "Париж",
    "london": "Лондон", "zurich": "Цюрих", "vienna": "Вена",
    "tallinn": "Таллин", "riga": "Рига", "vilnius": "Вильнюс",
    "singapore": "Сингапур", "tokyo": "Токио", "istanbul": "Стамбул",
}
COUNTRY_RU = {
    "DE": "Германия", "CZ": "Чехия", "FI": "Финляндия", "PL": "Польша",
    "NL": "Нидерланды", "SE": "Швеция", "EE": "Эстония", "LV": "Латвия",
    "LT": "Литва", "FR": "Франция", "US": "США", "GB": "Великобритания",
    "SG": "Сингапур", "JP": "Япония", "TR": "Турция", "AT": "Австрия",
    "CH": "Швейцария", "CA": "Канада", "NO": "Норвегия", "BE": "Бельгия",
    "IT": "Италия", "ES": "Испания", "UA": "Украина", "IL": "Израиль",
    "CN": "Китай", "HK": "Гонконг", "AE": "ОАЭ", "IE": "Ирландия",
    "GR": "Греция", "PT": "Португалия", "RO": "Румыния", "BG": "Болгария",
    "RS": "Сербия", "LU": "Люксембург", "IS": "Исландия", "GE": "Грузия",
    "RU": "Россия", "KR": "Южная Корея", "VN": "Вьетнам", "ID": "Индонезия",
    "MY": "Малайзия", "TH": "Таиланд", "IN": "Индия", "BR": "Бразилия",
    "MX": "Мексика", "AR": "Аргентина", "DK": "Дания", "CY": "Кипр",
    "SK": "Словакия", "SI": "Словения", "HR": "Хорватия", "MD": "Молдова",
    "KZ": "Казахстан", "UZ": "Узбекистан", "AZ": "Азербайджан",
    "AM": "Армения", "EG": "Египет", "ZA": "ЮАР", "NZ": "Новая Зеландия",
    "AU": "Австралия", "TW": "Тайвань", "PK": "Пакистан", "BD": "Бангладеш",
}


def has_country(candidate: Candidate) -> bool:
    text = f"{candidate.location_hint or ''} {unquote(urlsplit(candidate.uri).fragment)}".lower()
    return any(re.search(rf"(?<![a-zа-я]){re.escape(alias)}(?![a-zа-я])", text)
               for aliases, _ in COUNTRIES for alias in aliases)


def country_key(candidate: Candidate) -> str | None:
    fragment = unquote(urlsplit(candidate.uri).fragment)
    text = f"{candidate.location_hint or ''} {fragment} {candidate.geo_location or ''}".lower()
    for aliases, label in COUNTRIES:
        if any(re.search(rf"(?<![a-zа-я]){re.escape(alias)}(?![a-zа-я])", text) for alias in aliases):
            return label
    for code, name in COUNTRY_RU.items():
        if name.lower() in text:
            return f"{code}:{name}"
    flag = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", text)
    if flag:
        for code, name in COUNTRY_RU.items():
            if "".join(chr(ord(char) + 127397) for char in code) == flag.group():
                return f"{code}:{name}"
    return None


def geolocate(candidate: Candidate) -> None:
    """Fill a missing label from the public server IP; keep failures non-fatal."""
    endpoint = candidate.endpoint
    if endpoint is None:
        return
    host = endpoint[0]
    try:
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            ip = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
        requests = (
            (f"https://ipwho.is/{quote(ip, safe=':.')}?fields=success,country,country_code", "ipwho"),
            (f"https://ipapi.co/{quote(ip, safe=':.')}/json/", "ipapi"),
        )
        for url, provider in requests:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "velesVPN-free-subscription/1.0"})
                with urllib.request.urlopen(request, timeout=5) as response:
                    data = json.loads(response.read(64 * 1024))
                if provider == "ipwho" and not data.get("success"):
                    continue
                if data.get("error"):
                    continue
                code = str(data.get("country_code", data.get("country", ""))).upper()
                country_name = data.get("country") if provider == "ipwho" else data.get("country_name")
                country = COUNTRY_RU.get(code) or str(country_name or "").strip()
                flag = "".join(chr(ord(char) + 127397) for char in code) if re.fullmatch(r"[A-Z]{2}", code) else "🌐"
                if country:
                    candidate.geo_location = f"{flag} {country}"
                    return
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                continue
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, IndexError):
        return


def node_label(candidate: Candidate, pool: str) -> str:
    fragment = unquote(urlsplit(candidate.uri).fragment)
    hint = (candidate.location_hint or "").replace("_", " ")
    text = f"{hint} {fragment}".lower()
    location = candidate.geo_location
    for aliases, label in COUNTRIES:
        if any(re.search(rf"(?<![a-zа-я]){re.escape(alias)}(?![a-zа-я])", text) for alias in aliases):
            location = label
            break
    if location is None:
        flag = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", fragment)
        flag_text = flag.group() if flag else ""
        flag_country = next((name for code, name in COUNTRY_RU.items()
                             if "".join(chr(ord(char) + 127397) for char in code) == flag_text), None)
        location = f"{flag_text} {flag_country or 'Сервер'}" if flag_text else "🌐 Сервер"
    city = next((ru for en, ru in CITY_NAMES.items() if en in text), None)
    if city and city.lower() not in location.lower():
        location += f", {city}"

    if pool == "normal":
        suffix = "ОБЫЧНЫЙ"
    else:
        suffix = "БС"
    return f"{location} · {suffix}"


def labeled_uri(candidate: Candidate, pool: str) -> str:
    parsed = urlsplit(candidate.uri)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query,
                       quote(node_label(candidate, pool), safe="")))


def unique_endpoints(candidates: list[Candidate]) -> list[Candidate]:
    # Prefer a source's already measured configuration where several variants share a server.
    candidates.sort(key=lambda c: (c.source_latency_ms is None,
                                   c.source_latency_ms if c.source_latency_ms is not None else math.inf,
                                   c.uri))
    unique: dict[tuple[str, int], Candidate] = {}
    for candidate in candidates:
        endpoint = candidate.endpoint
        if endpoint is not None:
            unique.setdefault(endpoint, candidate)
    return list(unique.values())[:MAX_CANDIDATES_PER_POOL]


def tcp_probe(candidate: Candidate) -> tuple[Candidate, float | None]:
    endpoint = candidate.endpoint
    if endpoint is None:
        return candidate, None
    started = time.perf_counter()
    try:
        with socket.create_connection(endpoint, timeout=TCP_TIMEOUT):
            return candidate, round((time.perf_counter() - started) * 1000, 1)
    except OSError:
        return candidate, None


def rank_live(candidates: list[Candidate]) -> list[tuple[Candidate, float]]:
    reachable: list[tuple[Candidate, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(tcp_probe, candidate) for candidate in candidates]
        for future in concurrent.futures.as_completed(futures):
            candidate, latency = future.result()
            if latency is not None:
                reachable.append((candidate, latency))
    return sorted(reachable, key=lambda item: (item[1], item[0].uri))


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def select_diverse_pools(
    normal_ranked: list[tuple[Candidate, float]],
    whitelist_ranked: list[tuple[Candidate, float]],
) -> tuple[list[tuple[Candidate, float]], list[tuple[Candidate, float]]]:
    """Pick each country once first, then allow a second node when needed."""
    ranked = sorted(
        [("normal", candidate, latency) for candidate, latency in normal_ranked]
        + [("whitelist", candidate, latency) for candidate, latency in whitelist_ranked],
        key=lambda item: (item[2], item[1].uri),
    )
    limits = {"normal": NORMAL_LIMIT, "whitelist": WHITELIST_LIMIT}
    selected: dict[str, list[tuple[Candidate, float]]] = {"normal": [], "whitelist": []}
    country_counts: dict[str, int] = {}
    selected_ids: set[int] = set()
    geo_attempts = 0

    for allowed_per_country in (1, MAX_SERVERS_PER_COUNTRY):
        for pool_name, candidate, latency in ranked:
            if len(selected[pool_name]) >= limits[pool_name] or id(candidate) in selected_ids:
                continue
            country = country_key(candidate)
            if country is None and geo_attempts < MAX_GEOLOOKUPS_PER_RUN:
                geo_attempts += 1
                geolocate(candidate)
                country = country_key(candidate)
            # Do not publish a node with unknown country: it could exceed the
            # per-country cap when its location cannot be verified.
            if country is None:
                continue
            if country_counts.get(country, 0) >= allowed_per_country:
                continue
            selected[pool_name].append((candidate, latency))
            selected_ids.add(id(candidate))
            country_counts[country] = country_counts.get(country, 0) + 1
        if all(len(selected[name]) >= limits[name] for name in limits):
            break

    print(
        f"Геолокация: {geo_attempts} запросов; выбрано разных стран "
        f"{len(country_counts)}",
        file=sys.stderr,
    )
    print(
        "Отбор по странам: " + ", ".join(f"{name} {len(items)}/{limits[name]}" for name, items in selected.items()),
        file=sys.stderr,
    )
    return selected["normal"], selected["whitelist"]


def write_pool(name: str, ranked: list[tuple[Candidate, float]]) -> list[str]:
    return [labeled_uri(candidate, name) for candidate, _ in ranked]


def main() -> int:
    candidates: dict[str, list[Candidate]] = {"normal": [], "whitelist": []}
    failures: list[str] = []
    fetched: dict[str, bytes] = {}

    for pool, sources in SOURCES.items():
        for source, url in sources.items():
            try:
                fetched[source] = fetched.get(source) or fetch(url)
                payload = fetched[source]
                if source == "vless_checker":
                    candidates[pool].extend(checker_candidates(json.loads(payload), pool))
                else:
                    if source == "all_subs" and not all_subs_is_whitelist_feed(payload):
                        raise ValueError("upstream header no longer identifies a whitelist feed")
                    candidates[pool].extend(Candidate(uri, source) for uri in extract_uris(payload))
            except (urllib.error.URLError, TimeoutError, ValueError, OSError, json.JSONDecodeError) as exc:
                failures.append(f"{pool}/{source}: {exc}")

    normal_candidates = unique_endpoints(candidates["normal"])
    whitelist_candidates = unique_endpoints(candidates["whitelist"])
    normal_endpoints = {candidate.endpoint for candidate in normal_candidates}
    before_overlap_filter = len(whitelist_candidates)
    whitelist_candidates = [candidate for candidate in whitelist_candidates if candidate.endpoint not in normal_endpoints]
    print(f"Пересечение обычных и БС удалено: {before_overlap_filter - len(whitelist_candidates)}", file=sys.stderr)
    print(f"Кандидаты: обычные {len(normal_candidates)}, белые списки {len(whitelist_candidates)}", file=sys.stderr)

    normal_ranked = rank_live(normal_candidates)
    whitelist_ranked = rank_live(whitelist_candidates)
    normal_tcp_reachable = len(normal_ranked)
    whitelist_tcp_reachable = len(whitelist_ranked)
    normal_ranked, whitelist_ranked = select_diverse_pools(normal_ranked, whitelist_ranked)
    normal = write_pool("normal", normal_ranked)
    whitelist = write_pool("whitelist", whitelist_ranked)
    combined = normal + whitelist
    combined_body = [f"#profile-title: {PROFILE_TITLE}", "#profile-update-interval: 1", *combined]
    combined_bytes = ("\n".join(combined_body) + "\n").encode("utf-8")
    atomic_write(OUT / "subscription.txt", combined_bytes)

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    status = {
        "updated_at_utc": timestamp,
        "normal": {"selected": len(normal), "target": NORMAL_LIMIT, "candidates": len(normal_candidates), "tcp_reachable": normal_tcp_reachable},
        "whitelist": {"selected": len(whitelist), "target": WHITELIST_LIMIT, "candidates": len(whitelist_candidates), "tcp_reachable": whitelist_tcp_reachable},
        "source_failures": failures,
        "probe": "TCP connect latency measured from GitHub Actions runner; not a full VPN handshake or a guarantee from the user's network.",
    }
    atomic_write(OUT / "status.json", (json.dumps(status, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    normal_latency = normal_ranked[0][1] if normal_ranked else "—"
    whitelist_latency = whitelist_ranked[0][1] if whitelist_ranked else "—"
    page = f'''<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{PROFILE_TITLE}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0b1020;color:#e7ecf7;font:16px/1.55 system-ui,sans-serif;display:grid;min-height:100vh;place-items:center;padding:24px}}
main{{width:min(720px,100%);padding:36px;border:1px solid #26314c;border-radius:24px;background:linear-gradient(145deg,#151f36,#101729);box-shadow:0 24px 80px #0006}}
h1{{margin:0 0 8px;font-size:clamp(28px,6vw,42px)}}p{{color:#aab6d0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin-top:24px}}
section{{padding:20px;border:1px solid #2b3958;border-radius:16px;background:#111a2c}}h2{{margin:0 0 4px;font-size:19px}}.meta{{font-size:13px;color:#6ee7b7}}
a{{display:block;margin-top:12px;padding:13px 15px;border-radius:12px;background:#202d49;color:#fff;text-decoration:none;font-weight:650}}a:hover{{background:#2b3c60}}small{{display:block;margin-top:24px;color:#8290ae}}
</style><main><h1>{PROFILE_TITLE}</h1><p>Пулы для Happ и Incy. Сборка каждый час; сначала идут узлы с меньшей TCP-задержкой.</p>
<div class="grid"><section><h2>Общий пул: {len(normal)} обычных + {len(whitelist)} для БС</h2><div class="meta">Обновляется каждый час · всего {len(combined)} серверов</div>
<a href="subscription.txt">Добавить единую подписку в Happ</a></section></div>
<small>Проверяется открытие TCP-порта с сервера GitHub Actions. Это не проверка VPN-авторизации; реальная доступность и скорость зависят от вашей сети. Обновлено {html.escape(timestamp)}.</small></main></html>
'''
    atomic_write(OUT / "index.html", page.encode("utf-8"))
    print(f"Отобрано: обычных {len(normal)}/{NORMAL_LIMIT}, белые списки {len(whitelist)}/{WHITELIST_LIMIT}", file=sys.stderr)
    if not normal and not whitelist:
        print("Рабочих TCP-узлов не найдено; Pages не обновлять.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
