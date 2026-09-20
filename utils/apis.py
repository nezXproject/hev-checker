import base64
import aiohttp
import asyncio
from config import Config

TIMEOUT = aiohttp.ClientTimeout(total=15)

async def _get(session, url, headers=None, params=None):
    try:
        async with session.get(url, headers=headers, params=params) as r:
            data = await r.json(content_type=None)
            return r.status, data
    except Exception as e:
        return None, {"error": str(e)}

async def check_virustotal(target: str, target_type: str) -> dict:
    if not Config.VIRUSTOTAL_API_KEY:
        return {"status": "error", "message": "VirusTotal API key tidak dikonfigurasi."}

    headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
        "url": None,  # handled special
        "hash": f"https://www.virustotal.com/api/v3/files/{target}",
    }

    if target_type == "url":
        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = endpoints.get(target_type)
        if not endpoint:
            return {"status": "error", "message": f"Tipe '{target_type}' tidak didukung VirusTotal."}

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        status, data = await _get(session, endpoint, headers=headers)

    if status == 200 and "data" in data:
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status": "success",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "link": f"https://www.virustotal.com/gui/search/{target}",
        }
    return {"status": "error", "message": f"VirusTotal gagal (HTTP {status})."}

async def check_abuseipdb(ip: str) -> dict:
    if not Config.ABUSEIPDB_API_KEY:
        return {"status": "error", "message": "AbuseIPDB API key tidak dikonfigurasi."}

    headers = {"Key": Config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        status, data = await _get(
            session, "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params,
        )
    if status == 200 and "data" in data:
        d = data["data"]
        return {
            "status": "success",
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "N/A"),
            "isp": d.get("isp", "N/A"),
            "domain": d.get("domain", "N/A"),
            "usage": d.get("usageType", "N/A"),
            "whitelisted": d.get("isWhitelisted", False),
        }
    return {"status": "error", "message": f"AbuseIPDB gagal (HTTP {status})."}

async def check_ipinfo(ip: str) -> dict:
    token = Config.IPINFO_API_KEY
    url = f"https://ipinfo.io/{ip}/json" + (f"?token={token}" if token else "")
    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        status, data = await _get(session, url)
    if status == 200:
        return {
            "status": "success",
            "city": data.get("city", "N/A"),
            "region": data.get("region", "N/A"),
            "country": data.get("country", "N/A"),
            "org": data.get("org", "N/A"),
            "timezone": data.get("timezone", "N/A"),
        }
    return {"status": "error", "message": "IPinfo gagal."}
