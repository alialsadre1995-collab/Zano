// server.js — مالك + مشرفين بكلمات سر + user-info + حظر دائم JSON (ملفان فقط)
const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors:{ origin:'*', methods:['GET','POST','DELETE'] } });

app.use(cors());
app.use(express.json());

/* إعدادات */
const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'super-secret';
const ADMIN_PASS  = process.env.ADMIN_PASS  || '1200@';       // كلمة سر عامة للأدمن (اختياري)
const OWNER_PASS  = process.env.OWNER_PASS  || 'super@1200';  // كلمة سر المالك

/* ملفات التخزين */
const BANS_FILE  = path.join(__dirname,'bans.json');
const ROLES_FILE = path.join(__dirname,'roles.json');

/* مخازن */
const messages = [];
const sockets  = new Map(); // socket.id -> user
let bans  = [];
let roles = { mods:[] };    // {username, role:'admin'|'mod', passHash?, perms:{}}
const lastJoin = new Map();

const now = ()=> Date.now();
const FIVE_MIN = 5*60*1000;

/* أدوات */
function ipFromHeaders(h){ const xf=h['x-forwarded-for']; if(Array.isArray(xf)) return xf[0]; if(xf) return xf.split(',')[0].trim(); return ''; }
function ipFromReq(req){ return ipFromHeaders(req.headers) || req.socket?.remoteAddress || ''; }
function ipFromSocket(s){ return ipFromHeaders(s.handshake.headers) || s.handshake.address || ''; }
function latinOrGuest(name){ return /^[A-Za-z0-9_.-]{3,20}$/.test(name||'') ? name : 'Guest'+Math.floor(1000+Math.random()*9000); }
function colorFor(name){ const h=crypto.createHash('md5').update(name).digest('hex'); const n=parseInt(h.slice(0,2),16); return ['#30c0ff','#22c55e','#f59e0b','#e879f9','#f43f5e','#38bdf8'][n%6]; }
function sys(text){ io.emit('system',{text}); }
function hash(p){ return crypto.createHash('sha256').update(String(p)).digest('hex'); }
function isBanned({ip,deviceId}){
  return bans.some(b=> (b.targetType==='ip' && ip && b.targetValue===ip) ||
                       (b.targetType==='deviceId' && deviceId && b.targetValue===deviceId));
}
/* JSON */
function loadJson(file, fallback){ try{ if(fs.existsSync(file)) return JSON.parse(fs.readFileSync(file,'utf8')||'null')||fallback; }catch(_){} return fallback; }
function saveJson(file, data){ try{ fs.writeFileSync(file, JSON.stringify(data,null,2)); }catch(_){} }
function loadAll(){ bans = loadJson(BANS_FILE,[]); roles = loadJson(ROLES_FILE,{mods:[]}); }
loadAll();

const DEFAULT_PERMS = {
  admin:{kick:true,banDevice:true,banIp:true,unban:true,clear:true},
  mod:{kick:true,banDevice:true,banIp:false,unban:false,clear:false}
};
function permsFor(role){
  if(role==='owner') return {kick:true,banDevice:true,banIp:true,unban:true,clear:true};
  if(role==='admin') return DEFAULT_PERMS.admin;
  if(role==='mod')   return DEFAULT_PERMS.mod;
  return {};
}
function findMod(name){ return (roles.mods||[]).find(m => (m.username||'').toLowerCase()===(name||'').toLowerCase()); }

/* JWT */
function auth(req,res,next){
  const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):'';
  if(!t) return res.status(401).json({error:'no token'});
  try{ req.user=jwt.verify(t,JWT_SECRET); next(); }catch{ res.status(401).json({error:'bad token'}); }
}
function needRole(role){ return (req,res,next)=> (req.user && req.user.role===role) ? next() : res.status(403).json({error:'forbidden'}); }
function allow(permsKey){
  return (req,res,next)=>{
    const u=req.user; if(!u) return res.status(401).json({error:'no auth'});
    if(u.role==='owner') return next();
    const p=u.perms||{}; if(p[permsKey]) return next();
    return res.status(403).json({error:'forbidden'});
  };
}

/* ===== دخول مستخدم عادي */
app.post('/api/login',(req,res)=>{
  const { username='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username);
  const mod = findMod(uname);
  // لو للمشرف كلمة سر، ما نرفع الدور تلقائيًا
  const elevate = mod && !mod.passHash;
  const role = elevate ? mod.role : 'user';
  const userId = crypto.randomUUID();
  const token = jwt.sign({userId,username:uname,role,deviceId,perms: elevate?(mod.perms||permsFor(role)):{}}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role });
});

/* ===== دخول مشرف باسمه وكلمة سره */
app.post('/api/login-mod',(req,res)=>{
  const { username='', password='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username);
  const mod = findMod(uname);
  if(!mod || !mod.passHash) return res.status(401).json({error:'not a moderator'});
  if(mod.passHash !== hash(password)) return res.status(401).json({error:'wrong password'});
  const userId = crypto.randomUUID();
  const role   = mod.role||'mod';
  const token = jwt.sign({userId,username:uname,role,deviceId,perms:mod.perms||permsFor(role)}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role });
});

/* ===== دخول أدمن عام (اختياري) */
app.post('/api/login-pass',(req,res)=>{
  const { username='Admin', password='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(password!==ADMIN_PASS) return res.status(401).json({error:'wrong password'});
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username||'Admin');
  const userId = crypto.randomUUID();
  const role   = 'admin';
  const token = jwt.sign({userId,username:uname,role,deviceId,perms:permsFor(role)}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role });
});

/* ===== دخول المالك */
app.post('/api/login-owner',(req,res)=>{
  const { username='Owner', password='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(password!==OWNER_PASS) return res.status(401).json({error:'wrong password'});
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username||'Owner');
  const userId = crypto.randomUUID();
  const role   = 'owner';
  const token = jwt.sign({userId,username:uname,role,deviceId,perms:permsFor(role)}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role });
});

/* ===== إدارة الحظر */
app.get('/api/admin/bans', auth, allow('unban'), (req,res)=> res.json([...bans].sort((a,b)=>(b.ts||0)-(a.ts||0))));
app.post('/api/admin/unban', auth, allow('unban'), (req,res)=>{
  const {targetType,targetValue}=req.body||{};
  if(!['ip','deviceId'].includes(targetType)||!targetValue) return res.status(400).json({error:'bad params'});
  let removed=0;
  for(let i=bans.length-1;i>=0;i--){
    if(bans[i].targetType===targetType && bans[i].targetValue===targetValue){ bans.splice(i,1); removed++; }
  }
  if(removed){ saveJson(BANS_FILE,bans); sys('تم فك الحظر'); }
  res.json({ok:true,removed});
});
app.post('/api/admin/ban', auth, (req,res,next)=> allow(req.body?.targetType==='ip'?'banIp':'banDevice')(req,res,next), (req,res)=>{
  const {targetType,targetValue,reason=''}=req.body||{};
  if(!['ip','deviceId'].includes(targetType)||!targetValue) return res.status(400).json({error:'bad params'});
  if(!bans.find(b=> b.targetType===targetType && b.targetValue===targetValue)){
    bans.push({targetType,targetValue,reason,by:req.user.username,ts:now()});
    saveJson(BANS_FILE,bans);
  }
  let name = '';
  for(const [,u] of sockets){
    if((targetType==='ip' && u.ip===targetValue) || (targetType==='deviceId' && u.deviceId===targetValue)){ name=u.username; break; }
  }
  sys(`تم حظر ${name||'مستخدم'}`);
  for(const [sid,u] of sockets.entries()){
    if( (targetType==='ip' && u.ip===targetValue) || (targetType==='deviceId' && u.deviceId===targetValue) ){
      const s=io.sockets.sockets.get(sid);
      if(s){ s.emit('banned',{reason:'banned'}); s.disconnect(true); }
    }
  }
  res.json({ok:true});
});
app.post('/api/admin/kick', auth, allow('kick'), (req,res)=>{
  const {deviceId}=req.body||{}; if(!deviceId) return res.status(400).json({error:'bad params'});
  let done=false, name='';
  for(const [sid,u] of sockets.entries()){
    if(u.deviceId===deviceId){ const s=io.sockets.sockets.get(sid); if(s){ done=true; name=u.username; s.emit('banned',{reason:'kicked'}); s.disconnect(true);} }
  }
  if(done) sys(`تم طرد ${name||'مستخدم'}`);
  res.json({ok:done});
});

/* ===== كشف معلومات */
app.get('/api/admin/user-info', auth, (req,res)=>{
  const byId=req.query.userId, byName=(req.query.username||'').toLowerCase();
  for(const [,u] of sockets.entries()){
    if( (byId && u.userId===byId) || (byName && (u.username||'').toLowerCase()===byName) ){
      return res.json({userId:u.userId,username:u.username,role:u.role,ip:u.ip,deviceId:u.deviceId,connectedAt:u.connectedAt});
    }
  }
  res.status(404).json({error:'not found'});
});

/* ===== إدارة المشرفين (مالك فقط) */
app.get('/api/owner/mods', auth, needRole('owner'), (req,res)=> res.json(roles.mods||[]));
app.post('/api/owner/mods', auth, needRole('owner'), (req,res)=>{
  const {username,role='mod',password} = req.body||{};
  if(!username) return res.status(400).json({error:'no username'});
  let mod=findMod(username);
  if(!mod){ mod={username,role,perms:permsFor(role)}; roles.mods.push(mod); }
  else { mod.role=role; mod.perms=permsFor(role); }
  if(password) mod.passHash=hash(password);
  saveJson(ROLES_FILE,roles);
  res.json({ok:true,mod});
});
app.delete('/api/owner/mods/:username', auth, needRole('owner'), (req,res)=>{
  const uname=req.params.username.toLowerCase();
  roles.mods=(roles.mods||[]).filter(m=>(m.username||'').toLowerCase()!==uname);
  saveJson(ROLES_FILE,roles);
  res.json({ok:true});
});

/* ===== Socket.IO */
io.use((socket,next)=>{
  try{
    const t=socket.handshake.auth?.token||'';
    if(!t) return next(new Error('no token'));
    const u=jwt.verify(t,JWT_SECRET);
    if(isBanned({ip:ipFromSocket(socket),deviceId:u.deviceId})) return next(new Error('banned'));
    socket.user=u; next();
  }catch(e){ next(new Error('bad token')); }
});
function presence(){
  const arr=[]; for(const [,u] of sockets){ arr.push({userId:u.userId,username:u.username,color:u.color,deviceId:u.deviceId}); }
  return arr;
}
io.on('connection',socket=>{
  const p=socket.user||{};
  const u={
    socketId:socket.id, userId:p.userId, username:p.username,
    role: p.role, perms: p.perms||{}, deviceId:p.deviceId||'',
    ip: ipFromSocket(socket), color: colorFor(p.username), connectedAt: now()
  };
  sockets.set(socket.id,u);

  // رسالة انضمام (مرة كل 5 دقائق لنفس الشخص/الجهاز)
  const joinKey = u.deviceId || ('ip:'+u.ip);
  const last = lastJoin.get(joinKey)||0;
  if(now()-last>FIVE_MIN){ sys(`${u.username} انضم إلى الغرفة`); lastJoin.set(joinKey,now()); }

  socket.emit('history', messages.slice(-200));
  io.emit('presence', presence());

  socket.on('chat:msg',(d={})=>{
    const text=(d.text||'').toString().slice(0,1500).trim(); if(!text) return;
    if(isBanned({ip:u.ip,deviceId:u.deviceId})){ socket.emit('banned',{reason:'banned'}); socket.disconnect(); return; }
    const msg={from:u.username,userId:u.userId,color:u.color,text,ts:now()};
    messages.push(msg); if(messages.length>1500) messages.shift();
    io.emit('chat:new', msg);
  });

  socket.on('dm:send',({toId,text}={})=>{
    const t=(text||'').toString().slice(0,1500).trim(); if(!toId||!t) return;
    const target=[...sockets.values()].find(x=>x.userId===toId); if(!target) return;
    const payload={fromId:u.userId,toId:target.userId,text:t,ts:now()};
    socket.to(target.socketId).emit('dm:new',payload); socket.emit('dm:new',payload);
  });

  socket.on('disconnect',()=>{ sockets.delete(socket.id); io.emit('presence', presence()); });
});

/* صفحة */
app.get('/',(req,res)=>{ res.setHeader('Content-Type','text/html; charset=utf-8'); fs.createReadStream(path.join(__dirname,'page.html')).pipe(res); });
app.get('/healthz',(req,res)=>res.json({ok:true}));

server.listen(PORT, ()=> console.log('listening on '+PORT));
