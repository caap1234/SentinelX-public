# app/enrichment/geoip_enricher.py
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, Optional

import geoip2.database


# -------------------------
# ENV / Paths
# -------------------------

# Backward compat (si alguien aún define GEOIP_DB_PATH)
_GEOIP_DB_PATH_COMPAT = os.getenv("GEOIP_DB_PATH", "")

GEOIP_COUNTRY_DB_PATH = (
    os.getenv("GEOIP_COUNTRY_DB_PATH")
    or _GEOIP_DB_PATH_COMPAT
    or "/geoip/GeoLite2-Country.mmdb"
)
GEOIP_ASN_DB_PATH = os.getenv("GEOIP_ASN_DB_PATH") or "/geoip/GeoLite2-ASN.mmdb"

ENRICH_CACHE_TTL = int(os.getenv("ENRICH_CACHE_TTL", "86400"))  # seconds
ENRICH_CACHE_MAX = int(os.getenv("ENRICH_CACHE_MAX", "200000"))


# -------------------------
# Readers (lazy, cached)
# -------------------------

_country_reader: Optional[geoip2.database.Reader] = None
_country_loaded_path: Optional[str] = None

_asn_reader: Optional[geoip2.database.Reader] = None
_asn_loaded_path: Optional[str] = None


def _open_reader(path: str) -> Optional[geoip2.database.Reader]:
    if not path:
        return None
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        return geoip2.database.Reader(str(p))
    except Exception:
        return None


def _get_country_reader() -> Optional[geoip2.database.Reader]:
    global _country_reader, _country_loaded_path
    path = GEOIP_COUNTRY_DB_PATH

    if _country_reader is not None and _country_loaded_path == path:
        return _country_reader

    # path changed or first time
    if _country_reader is not None:
        try:
            _country_reader.close()
        except Exception:
            pass
        _country_reader = None
        _country_loaded_path = None

    _country_reader = _open_reader(path)
    _country_loaded_path = path if _country_reader else None
    return _country_reader


def _get_asn_reader() -> Optional[geoip2.database.Reader]:
    global _asn_reader, _asn_loaded_path
    path = GEOIP_ASN_DB_PATH

    if _asn_reader is not None and _asn_loaded_path == path:
        return _asn_reader

    if _asn_reader is not None:
        try:
            _asn_reader.close()
        except Exception:
            pass
        _asn_reader = None
        _asn_loaded_path = None

    _asn_reader = _open_reader(path)
    _asn_loaded_path = path if _asn_reader else None
    return _asn_reader


# -------------------------
# Cache (simple TTL dict)
# -------------------------

@dataclass
class _CacheEntry:
    ts: float
    value: Dict[str, Any]


_geo_cache: Dict[str, _CacheEntry] = {}
_asn_cache: Dict[str, _CacheEntry] = {}


def _now() -> float:
    return time.time()


def _cache_get(cache: Dict[str, _CacheEntry], key: str) -> Optional[Dict[str, Any]]:
    ent = cache.get(key)
    if not ent:
        return None
    if ENRICH_CACHE_TTL > 0 and (_now() - ent.ts) > ENRICH_CACHE_TTL:
        cache.pop(key, None)
        return None
    return ent.value


def _cache_set(cache: Dict[str, _CacheEntry], key: str, value: Dict[str, Any]) -> None:
    # naive eviction: if too big, drop ~10% oldest-ish (cheap)
    if ENRICH_CACHE_MAX > 0 and len(cache) >= ENRICH_CACHE_MAX:
        n_drop = max(1, ENRICH_CACHE_MAX // 10)
        for k in list(cache.keys())[:n_drop]:
            cache.pop(k, None)

    cache[key] = _CacheEntry(ts=_now(), value=value)


# -------------------------
# Helpers
# -------------------------

def _is_private_like(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _ensure_dict(d: Any) -> Dict[str, Any]:
    return d if isinstance(d, dict) else {}


def _set_internal_flags(extra: Dict[str, Any], ip: str, geo: Dict[str, Any]) -> None:
    """
    Marca tráfico interno/no-ruteable para que:
      - no ensucie dashboards
      - reglas puedan ignorarlo por default
    Heurística:
      - geo.country_code == PRV => internal
      - ip loopback (127.0.0.1 / ::1) => internal + internal_kind=loopback
    """
    cc = str(geo.get("country_code") or "").upper()
    is_internal = (cc == "PRV")

    # loopback explícito
    internal_kind: Optional[str] = None
    if ip == "127.0.0.1" or ip == "::1":
        is_internal = True
        internal_kind = "loopback"

    if is_internal:
        extra.setdefault("internal", True)
        extra.setdefault("traffic_class", "internal")
        if internal_kind:
            extra.setdefault("internal_kind", internal_kind)


# -------------------------
# Public API
# -------------------------

def enrich_ip_into_extra(
    *,
    ip: Optional[str],
    extra: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Enrichment inline:
      - Escribe estándar: extra["geo"], extra["asn"]
      - Compat opcional: extra["geoip"] (country only)
      - Marca: extra["enrich"]["geoip_asn"] = true

    No pisa si ya existe geo/asn completo, pero completa faltantes.
    Además marca tráfico interno (PRV/loopback).
    """
    extra = _ensure_dict(extra)
    if not ip:
        return extra

    # If already enriched enough, still ensure internal flags if possible
    geo_existing = _ensure_dict(extra.get("geo"))
    asn_existing = _ensure_dict(extra.get("asn"))

    has_geo = bool(geo_existing.get("country_code"))
    has_asn = ("number" in asn_existing) and (asn_existing.get("number") is not None)

    # -------------------------
    # Private-like (no-ruteable)
    # -------------------------
    if _is_private_like(ip):
        geo_existing.setdefault("is_private", True)
        geo_existing.setdefault("country_code", "PRV")
        geo_existing.setdefault("country_name", "Private")

        asn_existing.setdefault("number", None)
        asn_existing.setdefault("org", None)

        extra["geo"] = geo_existing
        extra["asn"] = asn_existing

        # compat
        geoip = _ensure_dict(extra.get("geoip"))
        geoip.setdefault("is_private", True)
        geoip.setdefault("country_code", "PRV")
        geoip.setdefault("country_name", "Private")
        extra["geoip"] = geoip

        # internal flags (lo que mencioné)
        _set_internal_flags(extra, ip, geo_existing)

        enrich_meta = _ensure_dict(extra.get("enrich"))
        enrich_meta["geoip_asn"] = True
        extra["enrich"] = enrich_meta
        return extra

    # Readers
    country_reader = _get_country_reader()
    asn_reader = _get_asn_reader()

    # ---- Country ----
    if not has_geo:
        cached = _cache_get(_geo_cache, ip)
        if cached is not None:
            geo_existing.update(cached)
        else:
            cc = "UNK"
            name = "Unknown"
            try:
                if country_reader is not None:
                    resp = country_reader.country(ip)
                    cc = resp.country.iso_code or "UNK"
                    name = resp.country.name or "Unknown"
            except Exception:
                cc, name = "UNK", "Unknown"

            val = {"is_private": False, "country_code": cc, "country_name": name}
            _cache_set(_geo_cache, ip, val)
            geo_existing.update(val)
    else:
        # si ya hay geo, asegúrate que is_private sea bool
        geo_existing.setdefault("is_private", False)

    # ---- ASN ----
    if not has_asn:
        cached = _cache_get(_asn_cache, ip)
        if cached is not None:
            asn_existing.update(cached)
        else:
            num = None
            org = None
            try:
                if asn_reader is not None:
                    resp = asn_reader.asn(ip)
                    num = getattr(resp, "autonomous_system_number", None)
                    org = getattr(resp, "autonomous_system_organization", None)
            except Exception:
                num, org = None, None

            val = {"number": num, "org": org}
            _cache_set(_asn_cache, ip, val)
            asn_existing.update(val)

    extra["geo"] = geo_existing
    extra["asn"] = asn_existing

    # compat country-only
    geoip = _ensure_dict(extra.get("geoip"))
    geoip.setdefault("is_private", geo_existing.get("is_private", False))
    geoip.setdefault("country_code", geo_existing.get("country_code"))
    geoip.setdefault("country_name", geo_existing.get("country_name"))
    extra["geoip"] = geoip

    # internal flags (por si geo quedara PRV por alguna razón)
    _set_internal_flags(extra, ip, geo_existing)

    enrich_meta = _ensure_dict(extra.get("enrich"))
    enrich_meta["geoip_asn"] = True
    extra["enrich"] = enrich_meta
    return extra
