import discord
from discord.ext import commands
from config import Config
from utils.db import db
import asyncio

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

@bot.event
async def on_ready():
    await db.init()
    try:
        synced = await bot.tree.sync()
        print(f"✅ Sinkronisasi {len(synced)} slash command.")
    except Exception as e:
        print(f"❌ Gagal sync: {e}")
    print(f"✅ hev Checker login sebagai {bot.user} (ID: {bot.user.id})")
    await bot.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching, name="ancaman siber 🔍")
    )

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ Kamu tidak punya izin untuk perintah ini.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Argumen kurang: `{error.param.name}`")
    else:
        await ctx.send(f"⚠️ Terjadi error: `{error}`")

async def main():
    async with bot:
        await bot.load_extension("cogs.checker")
        await bot.load_extension("cogs.admin")
        await bot.start(Config.DISCORD_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
