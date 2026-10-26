import discord, json

async def snapshot(guild):
    return {'version':1,'guild_id':guild.id,'name':guild.name,
        'roles':[{'id':r.id,'name':r.name,'permissions':r.permissions.value,'colour':r.colour.value,'hoist':r.hoist,'mentionable':r.mentionable,'position':r.position} for r in guild.roles if not r.is_default() and not r.managed],
        'channels':[{'id':c.id,'name':c.name,'type':str(c.type),'position':c.position,'category_id':c.category_id,'topic':getattr(c,'topic',None),'slowmode_delay':getattr(c,'slowmode_delay',0),
          'overwrites':[{'id':t.id,'kind':'role' if isinstance(t,discord.Role) else 'member','allow':ow.pair()[0].value,'deny':ow.pair()[1].value} for t,ow in c.overwrites.items()]} for c in guild.channels]}

def parse(row):
    if not row: return None
    data=row['data']; return json.loads(data) if isinstance(data,str) else data

def preview(guild,data):
    roles={r.name for r in guild.roles}; channels={(str(c.type),c.name) for c in guild.channels}
    return {'missing_roles':[r['name'] for r in data['roles'] if r['name'] not in roles],
        'missing_channels':[c['name'] for c in data['channels'] if (c['type'],c['name']) not in channels]}

async def restore_missing(guild,data,reason):
    # Additive only. Never delete existing entities, downgrade roles, or overwrite live permissions.
    created_roles=[]; created_channels=[]
    roles_by_id={r.id:r for r in guild.roles}
    for entry in sorted(data['roles'],key=lambda r:r['position']):
        existing=discord.utils.get(guild.roles,name=entry['name'])
        if existing: roles_by_id[entry['id']]=existing; continue
        # Restore roles with NO privileges by default; manual admin review required before granting permissions.
        r=await guild.create_role(name=entry['name'],permissions=discord.Permissions.none(),colour=discord.Colour(entry['colour']),hoist=False,mentionable=False,reason=reason)
        roles_by_id[entry['id']]=r; created_roles.append(r.name)
    cats={c.id:c for c in guild.categories}
    for entry in sorted((x for x in data['channels'] if x['type']=='category'),key=lambda x:x['position']):
        c=discord.utils.get(guild.categories,name=entry['name'])
        if not c: c=await guild.create_category(entry['name'],reason=reason); created_channels.append(c.name)
        cats[entry['id']]=c
    for entry in sorted((x for x in data['channels'] if x['type']!='category'),key=lambda x:x['position']):
        kind=entry['type']; name=entry['name']; category=cats.get(entry['category_id'])
        if any(str(c.type)==kind and c.name==name for c in guild.channels): continue
        if kind in ('text','news'):
            await guild.create_text_channel(name,category=category,topic=entry.get('topic'),slowmode_delay=entry.get('slowmode_delay',0),reason=reason)
        elif kind=='voice': await guild.create_voice_channel(name,category=category,reason=reason)
        elif kind=='stage_voice': await guild.create_stage_channel(name,category=category,reason=reason)
        elif kind=='forum': await guild.create_forum(name,category=category,reason=reason)
        else: continue
        created_channels.append(name)
    return {'roles':created_roles,'channels':created_channels,'notice':'Permissions and overwrites are NOT restored automatically; review manually.'}
