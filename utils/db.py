import aiosqlite
import time
from config import Config

class Database:
    def __init__(self, path: str = Config.DB_PATH):
        self.path = path

    async def init(self):
        async with aiosqlite.connect(self.path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    target TEXT PRIMARY KEY,
                    result TEXT,
                    timestamp INTEGER
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target TEXT,
                    target_type TEXT,
                    is_malicious INTEGER,
                    timestamp INTEGER
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    target TEXT PRIMARY KEY,
                    added_by INTEGER,
                    timestamp INTEGER
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    target TEXT PRIMARY KEY,
                    added_by INTEGER,
                    reason TEXT,
                    timestamp INTEGER
                )
            """)
            await db.commit()

    async def get_cache(self, target: str):
        async with aiosqlite.connect(self.path) as db:
            async with db.execute(
                "SELECT result, timestamp FROM cache WHERE target = ?", (target,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    result, ts = row
                    if time.time() - ts < Config.CACHE_TTL_HOURS * 3600:
                        return result
                    await db.execute("DELETE FROM cache WHERE target = ?", (target,))
                    await db.commit()
        return None

    async def set_cache(self, target: str, result: str):
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cache (target, result, timestamp) VALUES (?, ?, ?)",
                (target, result, int(time.time())),
            )
            await db.commit()

    async def add_history(self, user_id: int, target: str, target_type: str, is_malicious: bool):
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO history (user_id, target, target_type, is_malicious, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_id, target, target_type, int(is_malicious), int(time.time())),
            )
            await db.commit()

    async def get_history(self, user_id: int = None, limit: int = 10):
        async with aiosqlite.connect(self.path) as db:
            if user_id:
                q = "SELECT target, target_type, is_malicious, timestamp FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?"
                args = (user_id, limit)
            else:
                q = "SELECT target, target_type, is_malicious, timestamp FROM history ORDER BY id DESC LIMIT ?"
                args = (limit,)
            async with db.execute(q, args) as cursor:
                return await cursor.fetchall()

    async def add_whitelist(self, target: str, user_id: int):
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO whitelist (target, added_by, timestamp) VALUES (?, ?, ?)",
                (target, user_id, int(time.time())),
            )
            await db.commit()

    async def is_whitelisted(self, target: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("SELECT 1 FROM whitelist WHERE target = ?", (target,)) as c:
                return await c.fetchone() is not None

    async def add_blacklist(self, target: str, user_id: int, reason: str = ""):
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO blacklist (target, added_by, reason, timestamp) VALUES (?, ?, ?, ?)",
                (target, user_id, reason, int(time.time())),
            )
            await db.commit()

    async def is_blacklisted(self, target: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("SELECT 1 FROM blacklist WHERE target = ?", (target,)) as c:
                return await c.fetchone() is not None

    async def get_stats(self):
        async with aiosqlite.connect(self.path) as db:
            async with db.execute("SELECT COUNT(*) FROM history") as c:
                total = (await c.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM history WHERE is_malicious = 1") as c:
                mal = (await c.fetchone())[0]
        return {"total": total, "malicious": mal, "safe": total - mal}

db = Database()
