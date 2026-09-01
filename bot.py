import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from checker import check_virustotal, check_abuseipdb

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
ALERT_CHANNEL_ID = int(os.getenv("ALERT_CHANNEL_ID", 0))

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"hev Checker berhasil login sebagai {bot.user}")

@bot.command(name="check")
async def check_target(ctx, target: str):
    await ctx.send(f"🔍 Sedang memindai `{target}` pada pangkalan data keamanan...")

    # Deteksi sederhana apakah input berupa URL atau IP
    is_url = "." in target and not target.replace(".", "").isdigit()
    
    vt_result = check_virustotal(target, is_url=is_url)
    
    abuse_result = None
    if not is_url:
        abuse_result = check_abuseipdb(target)

    # Susun hasil analisis
    embed = discord.Embed(title=f"Laporan Reputasi: {target}", color=discord.Color.blue())
    is_malicious = False

    if vt_result["status"] == "success":
        mal = vt_result["malicious"]
        susp = vt_result["suspicious"]
        embed.add_field(name="VirusTotal", value=𝚏"Jahat: {mal} | Mencurigakan: {susp}", inline=False)
        if mal > 0:
            is_malicious = True
    else:
        embed.add_field(name="VirusTotal", value=vt_result["message"], inline=False)

    if not is_url and abuse_result:
        if abuse_result["status"] == "success":
            score = abuse_result["score"]
            reports = abuse_result["reports"]
            embed.add_field(name="AbuseIPDB", value=f"Skor Penyalahgunaan: {score}% | Laporan: {reports}", inline=False)
            if score > 25:
                is_malicious = True
        else:
            embed.add_field(name="AbuseIPDB", abuse_result["message"], inline=False)

    if is_malicious:
        embed.color = discord.Color.red()
        embed.description = "⚠️ **PENGINGAT KEAMANAN: Aset terdeteksi berbahaya!**"
        
        # Kirim peringatan otomatis ke channel khusus tim jika diatur
        if ALERT_CHANNEL_ID:
            channel = bot.get_channel(ALERT_CHANNEL_ID)
            if channel:
                await channel.send(f"🚨 **PERINGATAN TIM KEAMANAN!** Target `{target}` yang dikirim oleh {ctx.author.mention} terindikasi berbahaya!", embed=embed)
    else:
        embed.color = discord.Color.green()
        embed.description = "✅ Aset tampaknya aman dari ancaman utama."

    await ctx.send(embed=embed)

bot.run(TOKEN)
