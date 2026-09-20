import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
    ALERT_CHANNEL_ID = int(os.getenv("ALERT_CHANNEL_ID", 0))
    LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", 0))
    GUILD_ID = int(os.getenv("GUILD_ID", 0))

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "")

    CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", 6))
    AUTO_ALERT_THRESHOLD = int(os.getenv("AUTO_ALERT_THRESHOLD", 1))
    ABUSE_SCORE_THRESHOLD = int(os.getenv("ABUSE_SCORE_THRESHOLD", 25))

    DB_PATH = "data/hev.db"
