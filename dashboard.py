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
    async def trusted(gid:int,request:Request):
        s=session(request);csrf(request,s);g=await allowed(gid,s)
        if g.owner_id!=s['uid']:raise HTTPException(403,'Server owner only')
        d=await request.json();uid=str(d.get('user_id',''))
        if not uid.isdigit() or len(uid)>20:raise HTTPException(400,'Invalid user ID')
        member=await g.fetch_member(int(uid))
        cfg=await store.config(gid);ids=set(map(int,cfg.get('trusted',[])))
        if d.get('action')=='add':ids.add(member.id)
        elif d.get('action')=='remove':ids.discard(member.id)
        else:raise HTTPException(400,'Invalid action')
        cfg['trusted']=sorted(ids);await store.put(gid,cfg)
        await store.incident(gid,s['uid'],'dashboard_trusted',f"{d['action']} {uid}")
        return {'trusted':cfg['trusted']}
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
        if not row:raise HTTPException(404,'Backup not found')
        result=await restore_missing(g,parse(row),f'Dashboard restore by {s["uid"]}')
        await store.incident(gid,s['uid'],'dashboard_restore',f'backup={bid} roles={len(result["roles"])} channels={len(result["channels"])}')
        return result
    return app

PAGE = r"""<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>/gg.all.4u Security</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#edf1ff;font:15px system-ui,Arial}header{padding:22px 5%;border-bottom:1px solid #29314a;display:flex;justify-content:space-between;align-items:center;background:#11182c}h1{font-size:23px;margin:0}h2{font-size:20px}main{max-width:1180px;margin:auto;padding:25px 18px}nav{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}.tab,button,select,input{background:#202b45;color:#fff;border:1px solid #394765;border-radius:9px;padding:11px 14px;font:inherit}button{cursor:pointer}button:hover,.tab.active{background:#5147a7}.danger{background:#722c48}.panel{background:#141e33;border:1px solid #303d58;border-radius:14px;padding:20px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.muted{color:#aab7d3}.item{padding:13px;border-bottom:1px solid #303d58;overflow-wrap:anywhere}input{max-width:100%}#notice{white-space:pre-wrap;color:#cbd5ff;padding:10px}a{color:#b4b4ff}.hide{display:none}small{color:#b6c1db}</style><header><h1>🛡 /gg.all.4u <small>Security Dashboard</small></h1><a id="logout" href="/logout">Đăng xuất</a></header><main><section id="login" class="panel hide"><h2>Quản lý bảo mật Discord</h2><p>Đăng nhập để quản lý các máy chủ bạn có quyền quản trị.</p><a href="/login">Đăng nhập bằng Discord</a></section><section id="app" class="hide"><label>Máy chủ: <select id="guild"></select></label><button onclick="refresh()">Làm mới</button><nav id="tabs"></nav><div id="view"></div><div id="notice" role="status"></div></section></main><script>const BOOT=__BOOT__;const $=id=>document.getElementById(id);let data={},tab='overview';if(!BOOT.loggedIn){$('login').classList.remove('hide');$('logout').classList.add('hide')}else{$('app').classList.remove('hide');$('guild').innerHTML=BOOT.guilds.map(g=>'<option value="'+g.id+'">'+esc(g.name)+'</option>').join('');$('guild').onchange=refresh;refresh()}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function gid(){return $('guild').value}async function api(path,body){let r=await fetch('/api/guild/'+gid()+path,body===undefined?{}:{method:'POST',headers:{'content-type':'application/json','x-csrf-token':BOOT.csrf},body:JSON.stringify(body)});let j=await r.json();if(!r.ok)throw Error(j.detail||r.status);return j}async function refresh(){if(!gid()){$('view').textContent='Bot chưa có server nào bạn được phép quản lý.';return}try{data=await api('/details');render();$('notice').textContent=''}catch(e){$('notice').textContent=e.message}}const tabs=[['overview','Tổng quan'],['protection','Anti-Nuke / Raid'],['backup','Backup'],['recovery','Recovery'],['logs','Security Logs'],['trusted','Trusted Users']];function render(){ $('tabs').innerHTML=tabs.map(([k,n])=>'<button class="tab '+(tab===k?'active':'')+'" onclick="tab=''+k+'';render()">'+n+'</button>').join('');let cfg=data.config||{},v='';if(tab==='overview')v='<div class="grid">'+[['Server',data.guild],['Anti-Nuke',cfg.antinuke!==false?'Bật':'Tắt'],['Anti-Raid',cfg.antiraid!==false?'Bật':'Tắt'],['Anti-Spam',cfg.antispam!==false?'Bật':'Tắt'],['Bản sao lưu',data.backups.length],['Sự cố gần đây',data.incidents.length]].map(([a,b])=>'<div class="panel"><small>'+esc(a)+'</small><h2>'+esc(b)+'</h2></div>').join('')+'</div>';if(tab==='protection')v='<div class="panel"><h2>Điều khiển bảo vệ</h2>'+['antinuke','antiraid','antispam'].map(k=>'<div class="item"><b>'+k.toUpperCase()+'</b> — '+(cfg[k]!==false?'Đang bật':'Đang tắt')+' <button onclick="toggle(''+k+'')">Đổi trạng thái</button></div>').join('')+'</div>';if(tab==='backup')v='<div class="panel"><h2>Sao lưu cấu trúc</h2><p class="muted">Lưu vai trò và kênh vào PostgreSQL.</p><button onclick="backup()">Tạo backup ngay</button>'+data.backups.map(b=>'<div class="item">#'+b.id+' — '+esc(b.time)+'</div>').join('')+'</div>';if(tab==='recovery')v='<div class="panel"><h2>Khôi phục an toàn</h2><p class="muted">Chỉ tạo lại vai trò/kênh thiếu. Không khôi phục tin nhắn, quyền hay overwrites.</p><select id="bid">'+data.backups.map(b=>'<option value="'+b.id+'">Backup #'+b.id+' — '+esc(b.time)+'</option>').join('')+'</select> <button onclick="preview()">Xem trước</button><pre id="diff"></pre><button class="danger" onclick="restore()">Khôi phục (chủ server)</button></div>';if(tab==='logs')v='<div class="panel"><h2>50 sự cố gần nhất</h2>'+data.incidents.map(x=>'<div class="item"><b>'+esc(x.kind)+'</b> • '+esc(x.time)+'<br><small>Actor: '+esc(x.actor)+'</small><p>'+esc(x.detail)+'</p></div>').join('')+'</div>';if(tab==='trusted')v='<div class="panel"><h2>Trusted Users</h2><p class="muted">Chỉ chủ server được thay đổi.</p><input id="uid" placeholder="Discord User ID" inputmode="numeric"> <button onclick="trusted('add')">Thêm</button> <button onclick="trusted('remove')">Xóa</button><h3>Danh sách</h3>'+((cfg.trusted||[]).map(x=>'<div class="item">'+esc(x)+'</div>').join('')||'Chưa có người tin cậy')+'</div>';$('view').innerHTML=v}async function action(f){try{let x=await f();$('notice').textContent=JSON.stringify(x,null,2);await refresh()}catch(e){$('notice').textContent='Lỗi: '+e.message}}function toggle(key){action(()=>api('/toggle',{key}))}function backup(){action(()=>api('/backup',{}))}function trusted(actionName){let user_id=$('uid').value.trim();if(!/^\d{15,20}$/.test(user_id))return alert('Nhập User ID hợp lệ');action(()=>api('/trusted',{action:actionName,user_id}))}async function preview(){try{let x=await api('/preview?backup_id='+$('bid').value);$('diff').textContent=JSON.stringify(x,null,2)}catch(e){$('notice').textContent=e.message}}function restore(){let bid=Number($('bid').value),confirmation=prompt('Nhập RESTORE-'+gid()+' để xác nhận khôi phục backup #'+bid);if(!confirmation)return;action(()=>api('/restore',{backup_id:bid,confirmation}))}</script></html>"""
