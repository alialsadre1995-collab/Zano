// server.js — Pro Lite + Profiles + Admin Panel completed
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server,{ cors:{origin:'*'} });

app.use(express.json({limit:'2mb'}));

// ---------- storage (Render Disk optional) ----------
const DATA = process.env.DATA_DIR || path.join(__dirname);
const ROLES_FILE = path.join(DATA, 'roles.json');
const BANS_FILE  = path.join(DATA, 'bans.json');
const AUDIT_FILE = path.join(DATA, 'audit.json');

function readJSON(f, def){ try{ return JSON.parse(fs.readFileSync(f,'utf8')); }catch{ return def; } }
function writeJSON(f, obj){ fs.writeFileSync(f, JSON.stringify(obj,null,2)); }

// init
if(!fs.existsSync(ROLES_FILE)) writeJSON(ROLES_FILE,{mods:[]});
if(!fs.existsSync(BANS_FILE))  writeJSON(BANS_FILE,[]);
if(!fs.existsSync(AUDIT_FILE)) writeJSON(AUDIT_FILE,[]);

// ---------- in-memory ----------
const users = new Map(); // socketId -> session {userId, username, role, ip, deviceId, avatar, status}
const tokenMap = new Map(); // token -> session-lite
function tok(){ return Math.random().toString(36).slice(2)+Date.now().toString(36); }
function now(){ return Date.now(); }

// roles
const OWNER_USER = 'Owner';
const OWNER_PASS = '1200@';
const ADMIN_USER = 'Admin';
const ADMIN_PASS = '1200@';

// helpers
function roleOf(username, password){
  if(username===OWNER_USER && password===OWNER_PASS) return 'owner';
  if(username===ADMIN_USER && password===ADMIN_PASS) return 'admin';
  const roles = readJSON(ROLES_FILE,{mods:[]});
  const mod = roles.mods.find(m=>m.username?.toLowerCase()===username?.toLowerCase());
  if(mod){
    if(!mod.password || password===mod.password) return 'mod';
    return 'user'; // wrong pass → يدخل كمستخدم عادي
  }
  return 'user';
}
function maskIp(ip){ return (ip||'').replace(/^::ffff:/,''); }

// ban utils
function loadBans(){ return readJSON(BANS_FILE,[]); }
function saveBans(arr){ writeJSON(BANS_FILE, arr); }
function isBanned({ip,deviceId}){
  const bans = loadBans();
  return bans.some(b => (b.ip && b.ip===ip) || (b.deviceId && b.deviceId===deviceId));
}

// ---------- API ----------
app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'page.html')));

// smart login (user/admin/owner)
app.post('/api/login-smart', (req,res)=>{
  const { username, password, deviceId } = req.body||{};
  if(!username && !deviceId) return res.status(400).json({error:'bad'});
  const ip = maskIp(req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress);

  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});

  let uname = username?.trim() || '';
  if(!/^[A-Za-z0-9_]{3,20}$/.test(uname)) uname = 'Guest'+Math.floor(Math.random()*9000+1000);
  const role = roleOf(uname, (password||'').trim());

  const t = tok();
  tokenMap.set(t,{userId:t, username:uname, role, deviceId, ip, avatar:'', status:''});
  res.json({ ok:true, token:t, userId:t, username:uname, role });
});

// profile (self get/set)
function auth(req,res,next){
  const t = (req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  const s = tokenMap.get(t);
  if(!s) return res.status(401).json({error:'auth'});
  req.session = s; next();
}
function authOwner(req,res,next){
  if(!req.session) return res.status(401).json({error:'auth'});
  if(req.session.role!=='owner') return res.status(403).json({error:'forbidden'});
  next();
}
function authAdmin(req,res,next){
  if(!req.session) return res.status(401).json({error:'auth'});
  if(!['owner','admin','mod'].includes(req.session.role)) return res.status(403).json({error:'forbidden'});
  next();
}

app.get('/api/profile', auth, (req,res)=>{
  const u = req.session;
  res.json({ ok:true, username:u.username, avatar:u.avatar||'', status:u.status||'' });
});
app.post('/api/profile', auth, (req,res)=>{
  const { avatar='', status='' } = req.body||{};
  req.session.avatar = (''+avatar).slice(0,300);
  req.session.status = (''+status).slice(0,120);
  // broadcast change to everyone
  io.emit('profile:update',{ userId:req.session.userId, username:req.session.username, avatar:req.session.avatar, status:req.session.status });
  res.json({ ok:true });
});

// owner mods manage
app.get('/api/owner/mods', auth, authOwner, (req,res)=>{
  res.json({ ok:true, mods: readJSON(ROLES_FILE,{mods:[]}).mods });
});
app.post('/api/owner/mods', auth, authOwner, (req,res)=>{
  const { username, role, password, remove } = req.body||{};
  const roles = readJSON(ROLES_FILE,{mods:[]});
  const name = (username||'').trim();
  if(!/^[A-Za-z0-9_]{3,20}$/.test(name)) return res.status(400).json({error:'badName'});

  if(remove){ roles.mods = roles.mods.filter(m=>m.username.toLowerCase()!==name.toLowerCase()); writeJSON(ROLES_FILE,roles); return res.json({ok:true, removed:true}); }

  const rec = roles.mods.find(m=>m.username.toLowerCase()===name.toLowerCase());
  if(rec){ rec.password = password||''; }
  else roles.mods.push({username:name, password:password||''});
  writeJSON(ROLES_FILE,roles);
  res.json({ ok:true, saved:true });
});

// admin ban list
app.get('/api/admin/bans', auth, authAdmin, (req,res)=>{
  res.json({ ok:true, bans: loadBans() });
});

// admin user info (by username)
app.post('/api/admin/user-info', auth, authAdmin, (req,res)=>{
  const { username } = req.body||{};
  const u = [...users.values()].find(s=>s.username.toLowerCase()===String(username||'').toLowerCase());
  if(!u) return res.status(404).json({error:'notfound'});
  res.json({ ok:true, user:{
    userId:u.userId, username:u.username, role:u.role, ip:u.ip, deviceId:u.deviceId, avatar:u.avatar||'', status:u.status||''
  }});
});

// ---------- sockets ----------
io.use((socket,next)=>{
  const t = socket.handshake.auth?.token;
  const s = tokenMap.get(t);
  if(!s) return next(new Error('auth'));
  if(isBanned({ip:s.ip, deviceId:s.deviceId})) return next(new Error('banned'));
  socket.data.session = s;
  next();
});

function broadcastUsers(){
  const list = [...users.values()].map(u=>({
    userId:u.userId, username:u.username, role:u.role, avatar:u.avatar||'', status:u.status||''
  }));
  io.emit('userlist', list);
}

io.on('connection', (sock)=>{
  const s = sock.data.session;
  users.set(sock.id, s);
  writeJSON(AUDIT_FILE, readJSON(AUDIT_FILE,[]).concat({t:now(), act:'join', u:s.username, ip:s.ip, dev:s.deviceId}));

  io.emit('sys', {text:`${s.username} انضمّ.`});
  broadcastUsers();

  sock.on('msg', txt=>{
    const t = (''+txt).slice(0,1000);
    io.emit('msg', {from:s.username, text:t, role:s.role, t:now()});
  });

  // DM
  sock.on('dm', ({toUserId,text})=>{
    const t = (''+text).slice(0,800);
    const dest = [...users.values()].find(u=>u.userId===toUserId);
    if(dest){
      const targetSocket = [...users.entries()].find(([id,u])=>u.userId===dest.userId)?.[0];
      if(targetSocket){
        io.to(targetSocket).emit('dm', {from:s.username, fromId:s.userId, text:t, t:now()});
        sock.emit('dm:sent',{toId:dest.userId, text:t, t:now()});
      }
    }
  });

  // admin ops
  function canAdmin(){ return ['owner','admin','mod'].includes(s.role); }

  sock.on('admin:clear', ()=>{ if(!canAdmin()) return; io.emit('clear'); });
  sock.on('admin:pin', txt=>{ if(!canAdmin()) return; io.emit('pin', (''+txt).slice(0,200)); });
  sock.on('admin:kick', userId=>{
    if(!canAdmin()) return;
    const ent = [...users.entries()].find(([id,u])=>u.userId===userId);
    if(ent){ const [id,u] = ent; io.to(id).disconnect(true); io.emit('sys',{text:`${u.username} طُرد.`}); }
  });
  sock.on('admin:ban', ({userId, ip, deviceId})=>{
    if(!canAdmin()) return;
    const bans = loadBans();
    if(userId){
      const ent = [...users.entries()].find(([id,u])=>u.userId===userId);
      if(ent){ const [id,u] = ent; bans.push({deviceId:u.deviceId, ip:u.ip, by:s.username, t:now()}); saveBans(bans); io.to(id).disconnect(true); io.emit('sys',{text:`${u.username} تمّ حظره.`}); return; }
    }
    if(ip) { bans.push({ip, by:s.username, t:now()}); saveBans(bans); io.emit('sys',{text:`تمّ حظر IP.`}); }
    else if(deviceId){ bans.push({deviceId, by:s.username, t:now()}); saveBans(bans); io.emit('sys',{text:`تمّ حظر جهاز.`}); }
  });
  sock.on('admin:unban', ({ip,deviceId})=>{
    if(!canAdmin()) return;
    let arr = loadBans();
    const before = arr.length;
    if(ip) arr = arr.filter(b=>b.ip!==ip);
    if(deviceId) arr = arr.filter(b=>b.deviceId!==deviceId);
    saveBans(arr);
    io.emit('sys',{text:`فُكّ الحظر (${before-arr.length}).`});
  });

  sock.on('disconnect', ()=>{
    users.delete(sock.id);
    writeJSON(AUDIT_FILE, readJSON(AUDIT_FILE,[]).concat({t:now(), act:'leave', u:s.username, ip:s.ip, dev:s.deviceId}));
    io.emit('sys',{text:`${s.username} خرج.`});
    broadcastUsers();
  });
});

// ---------- start ----------
const PORT = process.env.PORT || 10000;
server.listen(PORT, ()=> console.log('up on '+PORT));
