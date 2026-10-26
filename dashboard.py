import os, secrets, urllib.parse, time, hmac, hashlib, base64, json
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from recovery import snapshot, parse, preview, restore_missing
from html import escape

API='https://discord.com/api/v10'
def build_app(bot,store):
    app=FastAPI(title='/gg.all.4u Dashboard',docs_url=None,redoc_url=None)
    client_id=os.environ['DISCORD_CLIENT_ID']; secret=os.environ['DISCORD_CLIENT_SECRET']; base=os.environ['DASHBOARD_URL'].rstrip('/')
    signing=os.environ['SESSION_SECRET'].encode()
    if len(signing)<32: raise RuntimeError('SESSION_SECRET must have >=32 chars')
    def sign(data):
        raw=base64.urlsafe_b64encode(json.dumps(data,separators=(',',':')).encode()).decode()
        mac=hmac.new(signing,raw.encode(),hashlib.sha256).hexdigest()
        return raw+'.'+mac
    def verify(token):
        try:
            raw,mac=token.rsplit('.',1)
            if not hmac.compare_digest(hmac.new(signing,raw.encode(),hashlib.sha256).hexdigest(),mac): return None
            data=json.loads(base64.urlsafe_b64decode(raw+'==='))
            return data if data['exp']>time.time() else None
        except Exception:return None
    def session(request):
        data=verify(request.cookies.get('tds_session',''))
        if not data: raise HTTPException(401,'Login required')
        return data
    def csrf(request,s):
        if not hmac.compare_digest(request.headers.get('x-csrf-token',''),s['csrf']):raise HTTPException(403,'Invalid CSRF token')
        if request.headers.get('origin')!=base:raise HTTPException(403,'Invalid origin')
    async def allowed(gid,s):
        g=bot.get_guild(gid)
        if not g:raise HTTPException(404,'Guild not connected')
        if s['uid']==g.owner_id:return g
        # Revalidate permissions with Discord on every request (do not trust stale OAuth guild list).
        member=g.get_member(s['uid'])
        if not member:
            try:member=await g.fetch_member(s['uid'])
            except (Exception):raise HTTPException(403,'Member unavailable')
        if not member.guild_permissions.administrator:raise HTTPException(403,'Administrator required')
        return g
    @app.get('/health')
    async def health():return {'ok':bot.is_ready(),'guilds':len(bot.guilds)}
    @app.get('/',response_class=HTMLResponse)
    async def home(request:Request):
        s=verify(request.cookies.get('tds_session',''))
        if not s:return HTMLResponse(PAGE.replace('__BOOT__',json.dumps({'loggedIn':False,'guilds':[],'csrf':''})))
        guilds=[]
        for g in bot.guilds:
            try:
                await allowed(g.id,s)
                guilds.append({'id':str(g.id),'name':g.name})
            except HTTPException:pass
        return HTMLResponse(PAGE.replace('__BOOT__',json.dumps({'loggedIn':True,'guilds':guilds,'csrf':s['csrf']})))
    @app.get('/login')
    async def login():
        state=secrets.token_urlsafe(24)
        q=urllib.parse.urlencode({'client_id':client_id,'redirect_uri':base+'/callback','response_type':'code','scope':'identify','state':state})
        r=RedirectResponse('https://discord.com/oauth2/authorize?'+q)
        r.set_cookie('oauth_state',state,secure=True,httponly=True,samesite='lax',max_age=600)
        return r
    @app.get('/callback')
    async def callback(request:Request,code:str,state:str):
        if not state or not hmac.compare_digest(state,request.cookies.get('oauth_state','')):raise HTTPException(403,'OAuth state mismatch')
        async with httpx.AsyncClient(timeout=15) as c:
            token=await c.post(API+'/oauth2/token',data={'client_id':client_id,'client_secret':secret,'grant_type':'authorization_code','code':code,'redirect_uri':base+'/callback'})
            if token.status_code!=200:raise HTTPException(401,'OAuth failed')
            me=await c.get(API+'/users/@me',headers={'Authorization':'Bearer '+token.json()['access_token']})
            if me.status_code!=200:raise HTTPException(401,'Identity failed')
        r=RedirectResponse('/')
        r.set_cookie('tds_session',sign({'uid':int(me.json()['id']),'csrf':secrets.token_urlsafe(24),'exp':int(time.time()+3600)}),secure=True,httponly=True,samesite='lax',max_age=3600)
        r.delete_cookie('oauth_state');return r
    @app.get('/logout')
    async def logout():
        r=RedirectResponse('/');r.delete_cookie('tds_session');return r
    @app.get('/api/guild/{gid}')
    async def info(gid:int,request:Request):
        s=session(request);g=await allowed(gid,s);cfg=await store.config(gid)
        return {'guild':g.name,'id':str(gid),'config':cfg,'recent_incidents':[dict(r) for r in await store.pool.fetch('SELECT id,created_at,actor_id,kind,detail FROM incidents WHERE guild_id=$1 ORDER BY id DESC LIMIT 20',gid)]}
    @app.post('/api/guild/{gid}/toggle')
    async def toggle(gid:int,request:Request):
        s=session(request);csrf(request,s);await allowed(gid,s)
        data=await request.json();key=data.get('key')
        if key not in ('antinuke','antiraid','antispam'):raise HTTPException(400,'Invalid key')
        cfg=await store.config(gid);cfg[key]=not cfg.get(key,True);await store.put(gid,cfg)
        await store.incident(gid,s['uid'],'dashboard_toggle',f'{key}={cfg[key]}')
        return {'key':key,'enabled':cfg[key]}
    @app.get('/api/guild/{gid}/details')
    async def details(gid:int,request:Request):
        s=session(request);g=await allowed(gid,s);cfg=await store.config(gid)
        incidents=await store.pool.fetch('SELECT id,created_at,actor_id,kind,detail FROM incidents WHERE guild_id=$1 ORDER BY id DESC LIMIT 50',gid)
        backups=await store.pool.fetch('SELECT id,created_at FROM backups WHERE guild_id=$1 ORDER BY id DESC LIMIT 30',gid)
        return {'guild':g.name,'id':str(gid),'config':cfg,'incidents':[{'id':r['id'],'time':r['created_at'].isoformat(),'actor':str(r['actor_id'] or ''),'kind':r['kind'],'detail':r['detail']} for r in incidents],'backups':[{'id':r['id'],'time':r['created_at'].isoformat()} for r in backups]}
     @app.post('/api/guild/{gid}/trusted')
     async def trusted(gid:int, request:Request):
        s = session(request)
        csrf(request, s)
        g = await allowed(gid, s)

        if g.owner_id != s['uid']:
            raise HTTPException(403, 'Server owner only')

        d = await request.json()
        uid = str(d.get('user_id', ''))

        if not uid.isdigit() or len(uid) > 20:
            raise HTTPException(400, 'Invalid user ID')

        member = await g.fetch_member(int(uid))
        cfg = await store.config(gid)
        ids = set(map(int, cfg.get('trusted', [])))

        if d.get('action') == 'add':
            ids.add(member.id)
        elif d.get('action') == 'remove':
            ids.discard(member.id)
        else:
            raise HTTPException(400, 'Invalid action')

        cfg['trusted'] = sorted(ids)
        await store.put(gid, cfg)

        await store.incident(
            gid, s['uid'], 'dashboard_trusted',
            f"{d['action']} {uid}"
        )

        return {'trusted': cfg['trusted']}
    @app.post('/api/guild/{gid}/backup')
    async def create_backup(gid:int,request:Request):
        s=session(request);csrf(request,s);g=await allowed(gid,s)
        bid=await store.backup(gid,await snapshot(g));await store.incident(gid,s['uid'],'dashboard_backup',str(bid))
        return {'backup_id':bid}
    @app.get('/api/guild/{gid}/preview')
    async def preview_backup(gid:int,request:Request,backup_id:int|None=None):
        s=session(request);g=await allowed(gid,s)
        row=await store.latest(gid,backup_id)
        if not row:raise HTTPException(404,'Backup not found')
        return {'backup_id':row['id'],'changes':preview(g,parse(row))}
    @app.post('/api/guild/{gid}/restore')
    async def restore_backup(gid:int,request:Request):
        s=session(request);csrf(request,s);g=await allowed(gid,s)
        if g.owner_id!=s['uid']:raise HTTPException(403,'Server owner only')
        d=await request.json()
        if d.get('confirmation')!=f'RESTORE-{gid}':raise HTTPException(400,'Confirmation mismatch')
        bid=d.get('backup_id')
        if not isinstance(bid,int):raise HTTPException(400,'Select backup')
        row=await store.latest(gid,bid)
