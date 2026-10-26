import os, json, asyncpg

class Store:
    def __init__(self): self.pool = None
    async def connect(self):
        url=os.environ.get('DATABASE_URL')
        if not url: raise RuntimeError('DATABASE_URL missing; configure Railway PostgreSQL')
        self.pool=await asyncpg.create_pool(dsn=url,min_size=1,max_size=5)
        async with self.pool.acquire() as c:
            await c.execute('''CREATE TABLE IF NOT EXISTS guild_config(guild_id BIGINT PRIMARY KEY, data JSONB NOT NULL DEFAULT '{}'::jsonb);
            CREATE TABLE IF NOT EXISTS backups(id BIGSERIAL PRIMARY KEY, guild_id BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), data JSONB NOT NULL);
            CREATE INDEX IF NOT EXISTS backups_guild_idx ON backups(guild_id,created_at DESC);
            CREATE TABLE IF NOT EXISTS incidents(id BIGSERIAL PRIMARY KEY, guild_id BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), actor_id BIGINT, kind TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incidents_guild_idx ON incidents(guild_id,created_at DESC);
            CREATE TABLE IF NOT EXISTS warnings(id BIGSERIAL PRIMARY KEY, guild_id BIGINT NOT NULL, user_id BIGINT NOT NULL, mod_id BIGINT NOT NULL, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());''')
    async def config(self,gid):
        r=await self.pool.fetchrow('SELECT data FROM guild_config WHERE guild_id=$1',gid)
        return dict(json.loads(r['data']) if isinstance(r['data'],str) else r['data']) if r else {}
    async def put(self,gid,config):
        await self.pool.execute('INSERT INTO guild_config(guild_id,data) VALUES($1,$2::jsonb) ON CONFLICT(guild_id) DO UPDATE SET data=EXCLUDED.data',gid,json.dumps(config))
    async def incident(self,gid,actor,kind,detail):
        await self.pool.execute('INSERT INTO incidents(guild_id,actor_id,kind,detail) VALUES($1,$2,$3,$4)',gid,actor,kind,detail[:1500])
    async def backup(self,gid,data):
        return await self.pool.fetchval('INSERT INTO backups(guild_id,data) VALUES($1,$2::jsonb) RETURNING id',gid,json.dumps(data))
    async def latest(self,gid,bid=None):
        if bid is None: return await self.pool.fetchrow('SELECT * FROM backups WHERE guild_id=$1 ORDER BY id DESC LIMIT 1',gid)
        return await self.pool.fetchrow('SELECT * FROM backups WHERE guild_id=$1 AND id=$2',gid,bid)
    async def close(self):
        if self.pool: await self.pool.close()
