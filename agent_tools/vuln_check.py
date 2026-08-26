"""Vulnerability check tools — Shodan passive lookup + Nuclei detection (deferred).

Shodan: passive only, no traffic to asset.
Nuclei: active but non-intrusive detection templates only (deferred — set up later).
"""
from __future__ import annotations

import logging
import os

import httpx

from agent_tools.registry import register

logger = logging.getLogger(__name__)

_SHODAN_BASE = "https://api.shodan.io"


@register(
    name="shodan_lookup",
    description=(
        "Passive Shodan lookup for an asset. Returns open ports, running services, software versions. "
        "Use to answer: 'Is this device running the vulnerable software?' before escalating a CVE alert."
    ),
    parameters={
        "type": "object",
        "properties": {
            "asset": {"type": "string", "description": "IP address or hostname to look up"},
        },
        "required": ["asset"],
    },
)
async def shodan_lookup(asset: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"error": "SHODAN_API_KEY not configured"}

    import ipaddress
    ip = asset
    try:
        ipaddress.ip_address(asset)
    except ValueError:
        try:
            import socket
            ip = socket.gethostbyname(asset)
        except Exception:
            return {"error": f"Could not resolve {asset} to an IP address"}

    try:
        async with httpx.AsyncClient(base_url=_SHODAN_BASE, timeout=15.0) as client:
            resp = await client.get(f"/shodan/host/{ip}", params={"key": api_key})
            if resp.status_code == 404:
                return {"asset": asset, "ip": ip, "found": False, "ports": [], "services": []}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"error": str(exc)[:200]}

    ports = data.get("ports", [])
    services = []
    for item in data.get("data", [])[:10]:
        svc = {
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "cpe": item.get("cpe", []),
        }
        if any(svc[k] for k in ("product", "version")):
            services.append(svc)

    return {
        "asset": asset,
        "ip": ip,
        "found": True,
        "country": data.get("country_name", ""),
        "org": data.get("org", ""),
        "ports": ports,
        "services": services,
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "last_update": data.get("last_update", ""),
    }
