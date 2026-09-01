import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_virustotal(target: str, is_url: bool = False) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    if is_url:
        # VirusTotal v3 membutuhkan URL yang di-base64 encode tanpa padding '='
        import base64
        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"

    response = requests.get(endpoint, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {"malicious": malicious, "suspicious": suspicious, "status": "success"}
    return {"status": "error", "message": f"Gagal akses VirusTotal (Kode: {response.status_code})"}

def check_abuseipdb(ip: str) -> dict:
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    
    response = requests.get(endpoint, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "status": "success"
        }
    return {"status": "error", "message": f"Gagal akses AbuseIPDB (Kode: {response.status_code})"}
