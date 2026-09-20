import discord
from discord import app_commands
from discord.ext import commands
import asyncio
import json

from utils.apis import check_virustotal, check_abuseipdb, check_ipinfo
from utils.formatters import build_result_embed
from utils.db import db
from config import Config

def detect_type(target: str) -> str:
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return "url"
    if target.count(":") >= 2 and all(c in "0123456789abcdefABCDEF:" for c in target):
        return "ip"
    if target.replace(".", "").isdigit() and target.count(".") == 3:
        return "ip"
    if all(c in "0123456789abcdefABCDEF" for c in target) and len(target) in (32, 40, 64):
        return "hash"
    if "." in target:
        return "domain"
    return "unknown"

class Checker(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def run_check(self, target: str, user_id: int, silent: bool = False):
        target_type = detect_type(target)
        if target_type == "unknown":
            return None, "❌ Tipe target tidak dikenali. Gunakan IP, domain, URL, atau hash."

        if await db.is_whitelisted(target):
            return None, f"✅ `{target}` ada di whitelist, dilewati."

        vt, abuse, ipinfo = None, None, None
        tasks = [check_virustotal(target, target_type)]

        if target_type == "ip":
            tasks.append(check_abuseipdb(target))
            tasks.append(check_ipinfo(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        vt = results[0] if not isinstance(results[0], Exception) else None
        if target_type == "ip":
            abuse = results[1] if not isinstance(results[1], Exception) else None
            ipinfo = results[2] if not isinstance(results[2], Exception) else None

        is_bl = await db.is_blacklisted(target)
        embed, is_malicious = build_result_embed(target, target_type, vt, abuse, ipinfo, is_bl)

        await db.add_history(user_id, target, target_type, is_malicious)
        await db.set_cache(target, json.dumps({"malicious": is_malicious}))

        return embed, is_malicious

    @commands.hybrid_command(name="check", description="Cek reputasi IP/domain/URL/hash")
    @app_commands.describe(target="IP, domain, URL, atau file hash")
    async def check(self, ctx: commands.Context, target: str):
        await ctx.defer()
        embed, result = await self.run_check(target, ctx.author.id)

        if embed is None:
            await ctx.send(result)
            return

        is_malicious = result

        if is_malicious and Config.ALERT_CHANNEL_ID:
            channel = self.bot.get_channel(Config.ALERT_CHANNEL_ID)
            if channel and channel.id != ctx.channel.id:
                await channel.send(
                    f"🚨 **PERINGATAN TIM KEAMANAN!** Target `{target}` "
                    f"dikirim oleh {ctx.author.mention} terindikasi berbahaya!",
                    embed=embed,
                )

        await ctx.send(embed=embed)

    @commands.hybrid_command(name="bulk", description="Cek banyak target sekaligus (pisahkan dengan koma)")
    async def bulk(self, ctx: commands.Context, *, targets: str):
        await ctx.defer()
        items = [t.strip() for t in targets.split(",") if t.strip()]
        if len(items) > 10:
            items = items[:10]
            await ctx.send("⚠️ Dibatasi 10 target per bulk check.")

        for target in items:
            embed, result = await self.run_check(target, ctx.author.id)
            if embed is None:
                await ctx.send(f"`{target}` → {result}")
            else:
                await ctx.send(embed=embed)
                await asyncio.sleep(1)

    @commands.hybrid_command(name="history", description="Lihat riwayat pengecekan kamu")
    async def history(self, ctx: commands.Context):
        rows = await db.get_history(ctx.author.id, limit=10)
        if not rows:
            await ctx.send("📭 Belum ada riwayat.")
            return
        embed = discord.Embed(title="📜 Riwayat Pengecekan", color=discord.Color.blue())
        for target, ttype, mal, ts in rows:
            emoji = "🔴" if mal else "🟢"
            embed.add_field(
                name=f"{emoji} {target}",
                value=f"Tipe: `{ttype}` | <t:{ts}:R>",
                inline=False
            )
        await ctx.send(embed=embed)

async def setup(bot):
    await bot.add_cog(Checker(bot))
