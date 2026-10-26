import os, asyncio, datetime, json, logging
import discord
from discord import app_commands
from discord.ext import commands, tasks
import uvicorn
from store import Store
from security import Security
from recovery import snapshot,parse,preview,restore_missing
from dashboard import build_app

logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s %(message)s')
for k in ('DISCORD_TOKEN','DISCORD_CLIENT_ID','DISCORD_CLIENT_SECRET','DASHBOARD_URL','SESSION_SECRET','DATABASE_URL'):
    if not os.getenv(k):raise RuntimeError('Missing environment variable: '+k)
intents=discord.Intents.default();intents.members=True
intents.message_content=os.getenv('ENABLE_MESSAGE_CONTENT','true').lower()=='true'
class SecurityBot(commands.Bot):
    async def setup_hook(self):
        await self.tree.sync()

bot=SecurityBot(command_prefix=commands.when_mentioned, intents=intents,help_command=None)
store=Store();security=Security(bot,store)

def admin():return app_commands.checks.has_permissions(administrator=True)
def mod():return app_commands.checks.has_permissions(moderate_members=True)
async def respond(interaction,text,ephemeral=True):
    if interaction.response.is_done():await interaction.followup.send(text[:1900],ephemeral=ephemeral)
    else:await interaction.response.send_message(text[:1900],ephemeral=ephemeral)

@bot.event
async def on_ready():logging.info('Ready as %s | %s guilds',bot.user,len(bot.guilds))
@bot.event
async def on_guild_channel_delete(channel):await security.audit_event(channel.guild,discord.AuditLogAction.channel_delete,channel.id,'channel_delete')
@bot.event
async def on_guild_role_delete(role):await security.audit_event(role.guild,discord.AuditLogAction.role_delete,role.id,'role_delete')
@bot.event
async def on_guild_role_update(before,after):
    if before.permissions!=after.permissions:await security.audit_event(after.guild,discord.AuditLogAction.role_update,after.id,'role_permission_change',2)
@bot.event
async def on_guild_channel_update(before,after):
    if before.overwrites!=after.overwrites:await security.audit_event(after.guild,discord.AuditLogAction.channel_update,after.id,'channel_permission_change',2)
@bot.event
async def on_member_ban(guild,user):await security.audit_event(guild,discord.AuditLogAction.ban,user.id,'mass_ban',3)
@bot.event
async def on_member_remove(member):
    # Audit logs distinguish kicks from voluntary leaves; skip if not reliably attributable.
    actor=await security.audit_actor(member.guild,discord.AuditLogAction.kick,member.id)
    if actor:
        n=security.count((member.guild.id,actor.id,'mass_kick'),30)
        await security.log(member.guild,actor.id,'kick',f'target={member.id}, count={n}')
        if n>=3:await security.punish(member.guild,actor,'mass_kick')
@bot.event
async def on_webhooks_update(channel):
    await security.log(channel.guild,0,'webhook_changed',f'channel={channel.id}; inspect audit logs')
@bot.event
async def on_member_join(member):await security.join(member)
@bot.event
async def on_message(message):await security.message(message)

@bot.tree.command(description='Security overview')
@app_commands.guild_only()
@admin()
async def security_status(i:discord.Interaction):
    cfg=await store.config(i.guild_id)
    await respond(i,'🛡️ Security: '+', '.join(f'{x}={cfg.get(x,True)}' for x in ('antinuke','antiraid','antispam')))
@bot.tree.command(description='Configure security protection')
@app_commands.guild_only()
@admin()
@app_commands.choices(feature=[app_commands.Choice(name=x,value=x) for x in ('antinuke','antiraid','antispam')])
async def security_set(i:discord.Interaction,feature:app_commands.Choice[str],enabled:bool):
    cfg=await store.config(i.guild_id);cfg[feature.value]=enabled;await store.put(i.guild_id,cfg)
    await security.log(i.guild,i.user.id,'config',f'{feature.value}={enabled}')
    await respond(i,f'{feature.value}: {enabled}')
@bot.tree.command(description='Choose a security logging channel')
@app_commands.guild_only()
@admin()
async def security_logs(i:discord.Interaction,channel:discord.TextChannel):
    cfg=await store.config(i.guild_id);cfg['log_channel_id']=channel.id;await store.put(i.guild_id,cfg)
    await respond(i,'Logging channel: '+channel.mention)
@bot.tree.command(description='Trust an administrator (server owner only)')
@app_commands.guild_only()
async def trusted_add(i:discord.Interaction,member:discord.Member):
    if i.user.id!=i.guild.owner_id:return await respond(i,'Only the server owner can change trust.')
    cfg=await store.config(i.guild_id);ids=set(cfg.get('trusted',[]));ids.add(member.id);cfg['trusted']=sorted(ids);await store.put(i.guild_id,cfg)
    await respond(i,f'Trusted: {member.mention}')
@bot.tree.command(description='Remove a trusted user (server owner only)')
@app_commands.guild_only()
async def trusted_remove(i:discord.Interaction,member:discord.Member):
    if i.user.id!=i.guild.owner_id:return await respond(i,'Only the server owner can change trust.')
    cfg=await store.config(i.guild_id);cfg['trusted']=[x for x in cfg.get('trusted',[]) if x!=member.id];await store.put(i.guild_id,cfg)
    await respond(i,'Removed from trusted list.')
@bot.tree.command(description='Create server structure backup')
@app_commands.guild_only()
@admin()
async def backup_create(i:discord.Interaction):
    await i.response.defer(ephemeral=True,thinking=True)
    bid=await store.backup(i.guild_id,await snapshot(i.guild))
    await respond(i,f'Backup #{bid} created (roles/channels structure; not messages).')
@bot.tree.command(description='Preview latest backup differences')
@app_commands.guild_only()
@admin()
async def recovery_preview(i:discord.Interaction):
    row=await store.latest(i.guild_id)
    if not row:return await respond(i,'No backup yet.')
    diff=preview(i.guild,parse(row));await respond(i,f'Backup #{row["id"]}:\n'+json.dumps(diff,ensure_ascii=False)[:1500])
@bot.tree.command(description='Restore missing roles and channels from backup, without permissions')
@app_commands.guild_only()
async def recovery_full(i:discord.Interaction,confirmation:str):
    if i.user.id!=i.guild.owner_id:return await respond(i,'Only the server owner can restore.')
    if confirmation!=f'RESTORE-{i.guild_id}':return await respond(i,f'To confirm, run again with confirmation: RESTORE-{i.guild_id}')
    await i.response.defer(ephemeral=True,thinking=True)
    row=await store.latest(i.guild_id)
    if not row:return await respond(i,'No backup available.')
    try:
        result=await restore_missing(i.guild,parse(row),f'Owner-requested recovery by {i.user.id}')
        await security.log(i.guild,i.user.id,'recovery',json.dumps(result)[:500]);await respond(i,'Recovery result: '+json.dumps(result,ensure_ascii=False)[:1200])
    except (discord.Forbidden,discord.HTTPException) as e:await respond(i,'Recovery incomplete: '+str(e))
@bot.tree.command(description='Temporarily lock text channels by denying send_messages to everyone')
@app_commands.guild_only()
@admin()
async def lockdown(i:discord.Interaction,confirmation:str):
    if confirmation!=f'LOCK-{i.guild_id}':return await respond(i,f'Confirm with LOCK-{i.guild_id}')
    await i.response.defer(ephemeral=True,thinking=True)
    count=0
    for c in i.guild.text_channels:
        try:
            await c.set_permissions(i.guild.default_role,send_messages=False,reason=f'Lockdown by {i.user.id}')
            count+=1
        except (discord.Forbidden,discord.HTTPException):pass
    await respond(i,f'Locked {count} text channels. IMPORTANT: original overwrites are not saved; unlock manually or restore from external permissions backup.')
@bot.tree.command(description='Ban member')
@app_commands.guild_only()
@app_commands.checks.has_permissions(ban_members=True)
async def ban(i:discord.Interaction,member:discord.Member,reason:str='No reason'):
    if member.id==i.guild.owner_id or member.top_role>=i.user.top_role or member.top_role>=i.guild.me.top_role:return await respond(i,'Role hierarchy prevents this action.')
    await member.ban(reason=f'{reason} | by {i.user.id}',delete_message_seconds=0);await respond(i,'Banned.')
@bot.tree.command(description='Kick member')
@app_commands.guild_only()
@app_commands.checks.has_permissions(kick_members=True)
async def kick(i:discord.Interaction,member:discord.Member,reason:str='No reason'):
    if member.id==i.guild.owner_id or member.top_role>=i.user.top_role or member.top_role>=i.guild.me.top_role:return await respond(i,'Role hierarchy prevents this action.')
    await member.kick(reason=f'{reason} | by {i.user.id}');await respond(i,'Kicked.')
@bot.tree.command(description='Timeout member in minutes')
@app_commands.guild_only()
@mod()
async def timeout(i:discord.Interaction,member:discord.Member,minutes:app_commands.Range[int,1,40320],reason:str='No reason'):
    if member.id==i.guild.owner_id or member.top_role>=i.user.top_role or member.top_role>=i.guild.me.top_role:return await respond(i,'Role hierarchy prevents this action.')
    await member.timeout(datetime.timedelta(minutes=minutes),reason=reason);await respond(i,'Timed out.')
@bot.tree.command(description='Delete up to 100 recent messages')
@app_commands.guild_only()
@app_commands.checks.has_permissions(manage_messages=True)
async def purge(i:discord.Interaction,count:app_commands.Range[int,1,100]):
    if not isinstance(i.channel,discord.TextChannel):return await respond(i,'Text channel only.')
    await i.response.defer(ephemeral=True,thinking=True)
    deleted=await i.channel.purge(limit=count,reason=f'Purge by {i.user.id}');await respond(i,f'Deleted {len(deleted)} messages.')
@bot.tree.command(description='Add a moderation warning')
@app_commands.guild_only()
@app_commands.checks.has_permissions(moderate_members=True)
async def warn(i:discord.Interaction,member:discord.Member,reason:str):
    await store.pool.execute('INSERT INTO warnings(guild_id,user_id,mod_id,reason) VALUES($1,$2,$3,$4)',i.guild_id,member.id,i.user.id,reason)
    await respond(i,'Warning recorded.')
@bot.tree.command(description='List recent member warnings')
@app_commands.guild_only()
@mod()
async def warnings(i:discord.Interaction,member:discord.Member):
    rows=await store.pool.fetch('SELECT reason,created_at FROM warnings WHERE guild_id=$1 AND user_id=$2 ORDER BY id DESC LIMIT 10',i.guild_id,member.id)
    await respond(i,'\n'.join(f'{r["created_at"]:%Y-%m-%d}: {r["reason"][:120]}' for r in rows) or 'No warnings.')
@bot.tree.command(description='Recent security incidents')
@app_commands.guild_only()
@admin()
async def incidents(i:discord.Interaction):
    rows=await store.pool.fetch('SELECT kind,actor_id,created_at FROM incidents WHERE guild_id=$1 ORDER BY id DESC LIMIT 15',i.guild_id)
    await respond(i,'\n'.join(f'{r["created_at"]:%m-%d %H:%M} {r["kind"]} actor:{r["actor_id"]}' for r in rows) or 'No incidents.')
@bot.tree.command(description='Bot latency and uptime health')
@app_commands.guild_only()
async def ping(i:discord.Interaction):await respond(i,f'Pong {bot.latency*1000:.0f} ms')
@bot.tree.command(description='Link to dashboard')
@app_commands.guild_only()
async def dashboard(i:discord.Interaction):await respond(i,os.environ['DASHBOARD_URL'])

@bot.tree.error
async def on_error(i,error):
    if isinstance(error,app_commands.CommandInvokeError):
        logging.exception('Command error',exc_info=error.original)
        msg='Action failed; check bot permissions and logs.'
    elif isinstance(error,app_commands.MissingPermissions):msg='Insufficient permissions.'
    else:msg='Command unavailable or invalid.'
    try:await respond(i,msg)
    except discord.HTTPException:pass

@tasks.loop(minutes=5)
async def periodic_backup():
    interval=max(5,int(os.getenv('BACKUP_INTERVAL_MINUTES','30')))
    for g in bot.guilds:
        row=await store.latest(g.id)
        if row and (datetime.datetime.now(datetime.timezone.utc)-row['created_at']).total_seconds()<interval*60:continue
        try:await store.backup(g.id,await snapshot(g))
        except Exception:logging.exception('Backup failed for guild %s',g.id)
@periodic_backup.before_loop
async def before_backup():await bot.wait_until_ready()

async def run():
    await store.connect()
    app=build_app(bot,store)
    server=uvicorn.Server(uvicorn.Config(app,host='0.0.0.0',port=int(os.getenv('PORT','8080')),log_level='info'))
    periodic_backup.start()
    try:
        async with bot:
            # Global commands are synced in setup_hook after login.
            await asyncio.gather(bot.start(os.environ['DISCORD_TOKEN']),server.serve())
    finally:
        periodic_backup.cancel();await store.close()
if __name__=='__main__':asyncio.run(run())
