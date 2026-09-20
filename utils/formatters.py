import discord

def risk_emoji(malicious: bool, score: int = 0) -> str:
    if malicious or score >= 50:
        return "🔴"
    if score >= 20:
        return "🟠"
    return "🟢"

def build_result_embed(target: str, target_type: str, vt: dict, abuse: dict = None,
                       ipinfo: dict = None, is_blacklisted: bool = False) -> discord.Embed:
    is_malicious = False
    score = 0

    if vt and vt.get("status") == "success":
        if vt["malicious"] >= 1:
            is_malicious = True
        if vt.get("suspicious", 0) >= 3:
            is_malicious = True

    if abuse and abuse.get("status") == "success":
        score = abuse["score"]
        if score >= 25:
            is_malicious = True

    color = discord.Color.red() if is_malicious else discord.Color.green()
    title_emoji = risk_emoji(is_malicious, score)
    embed = discord.Embed(
        title=f"{title_emoji} Laporan Reputasi: {target}",
        color=color,
        description=f"**Tipe:** `{target_type.upper()}`"
    )

    if vt:
        if vt.get("status") == "success":
            embed.add_field(
                name="🦠 VirusTotal",
                value=(
                    f"Malicious: **{vt['malicious']}**\n"
                    f"Suspicious: **{vt['suspicious']}**\n"
                    f"Harmless: {vt.get('harmless', 0)}\n"
                    f"Reputation: {vt.get('reputation', 0)}\n"
                    f"[Lihat detail]({vt.get('link', 'https://virustotal.com')})"
                ),
                inline=True
            )
        else:
            embed.add_field(name="🦠 VirusTotal", value=vt.get("message", "N/A"), inline=True)

    if abuse:
        if abuse.get("status") == "success":
            embed.add_field(
                name="🚨 AbuseIPDB",
                value=(
                    f"Confidence: **{abuse['score']}%**\n"
                    f"Total Reports: {abuse['reports']}\n"
                    f"Country: {abuse['country']}\n"
                    f"ISP: {abuse['isp']}\n"
                    f"Usage: {abuse['usage']}"
                ),
                inline=True
            )
        else:
            embed.add_field(name="🚨 AbuseIPDB", value=abuse.get("message", "N/A"), inline=True)

    if ipinfo and ipinfo.get("status") == "success":
        embed.add_field(
            name="🌍 Geolokasi",
            value=f"{ipinfo['city']}, {ipinfo['region']}, {ipinfo['country']}\nOrg: {ipinfo['org']}",
            inline=False
        )

    if is_blacklisted:
        embed.add_field(name="⛔ Status", value="Target ada di **blacklist** server ini!", inline=False)

    if is_malicious:
        embed.add_field(
            name="⚠️ Kesimpulan",
            value="**PENGINGAT KEAMANAN: Aset terdeteksi berbahaya!**",
            inline=False
        )
    else:
        embed.add_field(
            name="✅ Kesimpulan",
            value="Aset tampaknya aman dari ancaman utama.",
            inline=False
        )

    return embed, is_malicious
