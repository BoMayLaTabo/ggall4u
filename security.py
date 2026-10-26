import asyncio, collections, datetime, re, time
import discord

UTC=datetime.timezone.utc
class Security:
    def __init__(self,bot,store):
        self.bot=bot; self.store=store; self.events=collections.defaultdict(collections.deque); self.msgs=collections.defaultdict(collections.deque); self.join_events=collections.defaultdict(collections.deque); self.cooldowns={}
    def count(self,key,window):
        q=self.events[key]; now=time.monotonic(); q.append(now)
        while q and now-q[0]>window: q.popleft()
        return len(q)
    async def log(self,guild,actor,kind,detail):
        await self.store.incident(guild.id,actor,kind,detail)
        cfg=await self.store.config(guild.id); ch=guild.get_channel(cfg.get('log_channel_id',0))
        if ch:
            try: await ch.send(f'🛡️ **{discord.utils.escape_markdown(kind)}** | actor `{actor}` | {discord.utils.escape_mentions(detail[:400])}',allowed_mentions=discord.AllowedMentions.none())
            except (discord.Forbidden,discord.HTTPException): pass
    async def audit_actor(self,guild,action,target_id):
        if not guild.me.guild_permissions.view_audit_log: return None
        await asyncio.sleep(1.2)
        try:
            async for entry in guild.audit_logs(limit=8,action=action):
                if (datetime.datetime.now(UTC)-entry.created_at).total_seconds()>15: continue
                if getattr(entry.target,'id',None)==target_id: return entry.user
        except (discord.Forbidden,discord.HTTPException): pass
        return None
    async def punish(self,guild,actor,kind):
        if not actor or actor.id==self.bot.user.id or actor.id==guild.owner_id: return
        cfg=await self.store.config(guild.id)
        if actor.id in cfg.get('trusted',[]): return
        member=guild.get_member(actor.id)
        if not member or member.top_role>=guild.me.top_role: await self.log(guild,actor.id,'cannot_contain',kind); return
        now=time.monotonic()
        if now-self.cooldowns.get((guild.id,actor.id),0)<60: return
        self.cooldowns[(guild.id,actor.id)]=now
        try:
            await member.timeout(datetime.timedelta(hours=1),reason='Security: '+kind)
            # Remove manageable roles, excluding managed roles. This action can be disruptive.
            removable=[r for r in member.roles if not r.is_default() and not r.managed and r<guild.me.top_role]
            if removable: await member.remove_roles(*removable,reason='Security containment: '+kind)
            await self.log(guild,actor.id,'contained',kind)
        except (discord.Forbidden,discord.HTTPException) as e: await self.log(guild,actor.id,'contain_failed',str(e))
    async def audit_event(self,guild,action,target_id,kind,limit=2):
        cfg=await self.store.config(guild.id)
        if not cfg.get('antinuke',True): return
        actor=await self.audit_actor(guild,action,target_id)
        if not actor: await self.log(guild,0,'unattributed_'+kind,str(target_id)); return
        n=self.count((guild.id,actor.id,kind),30)
        await self.log(guild,actor.id,kind,f'target={target_id}, 30s_count={n}')
        if n>=limit: await self.punish(guild,actor,kind)
    async def join(self,member):
        cfg=await self.store.config(member.guild.id)
        if not cfg.get('antiraid',True): return
        now=time.monotonic(); q=self.join_events[member.guild.id]; q.append(now)
        while q and now-q[0]>30:q.popleft()
        if len(q)>=8:
            await self.log(member.guild,member.id,'raid_detected',f'{len(q)} joins/30s')
            # No mass-ban based solely on joining. Temporarily timeout new joiners if permitted.
            if member.guild.me.guild_permissions.moderate_members:
                try: await member.timeout(datetime.timedelta(minutes=10),reason='Temporary raid protection')
                except (discord.Forbidden,discord.HTTPException): pass
        age=(datetime.datetime.now(UTC)-member.created_at).total_seconds()
        if age<86400 and cfg.get('new_account_timeout',False):
            try: await member.timeout(datetime.timedelta(minutes=10),reason='Account under 24 hours')
            except (discord.Forbidden,discord.HTTPException): pass
    async def message(self,message):
        if not message.guild or message.author.bot: return
        cfg=await self.store.config(message.guild.id)
        if not cfg.get('antispam',True): return
        if message.author.id==message.guild.owner_id or message.author.id in cfg.get('trusted',[]):return
        if isinstance(message.author,discord.Member) and message.author.guild_permissions.manage_messages:return
        key=(message.guild.id,message.author.id); q=self.msgs[key]; now=time.monotonic()
        content=message.content or ''
        q.append((now,content))
        while q and now-q[0][0]>8:q.popleft()
        repeats=sum(1 for _,s in q if s==content and len(content)>4)
        links=len(re.findall(r'https?://',content,re.I))
        mentions=len(message.mentions)+len(message.role_mentions)
        violation=len(q)>=6 or repeats>=4 or links>=4 or mentions>=6 or message.mention_everyone
        if not violation:return
        try: await message.delete()
        except (discord.Forbidden,discord.HTTPException):pass
        await self.log(message.guild,message.author.id,'spam',f'rate={len(q)}, repeated={repeats}, links={links}, mentions={mentions}')
        if isinstance(message.author,discord.Member):
            try: await message.author.timeout(datetime.timedelta(minutes=10),reason='Automated anti-spam')
            except (discord.Forbidden,discord.HTTPException):pass
        q.clear()
