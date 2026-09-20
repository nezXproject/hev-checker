import discord
from discord import app_commands
from discord.ext import commands
from utils.db import db

class Admin(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_command(name="whitelist", description="Tambah target ke whitelist")
    @commands.has_permissions(administrator=True)
    async def whitelist(self, ctx: commands.Context, target: str):
        await db.add_whitelist(target, ctx.author.id)
        await ctx.send(f"✅ `{target}` ditambahkan ke whitelist.")

    @commands.hybrid_command(name="blacklist", description="Tambah target ke blacklist")
    @commands.has_permissions(administrator=True)
    async def blacklist(self, ctx: commands.Context, target: str, *, reason: str = ""):
        await db.add_blacklist(target, ctx.author.id, reason)
        await ctx.send(f"⛔ `{target}` ditambahkan ke blacklist. Alasan: {reason or 'N/A'}")

    @commands.hybrid_command(name="stats", description="Statistik penggunaan bot")
    async def stats(self, ctx: commands.Context):
        s = await db.get_stats()
        embed = discord.Embed(title="📊 Statistik hev Checker", color=discord.Color.blurple())
        embed.add_field(name="Total Scan", value=s["total"], inline=True)
        embed.add_field(name="Malicious", value=s["malicious"], inline=True)
        embed.add_field(name="Aman", value=s["safe"], inline=True)
        await ctx.send(embed=embed)

    @commands.hybrid_command(name="ping", description="Cek latensi bot")
    async def ping(self, ctx: commands.Context):
        await ctx.send(f"🏓 Pong! Latensi: `{round(self.bot.latency * 1000)}ms`")

async def setup(bot):
    await bot.add_cog(Admin(bot))
