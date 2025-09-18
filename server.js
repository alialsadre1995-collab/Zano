// server.js – Pro Lite: Login + Rooms + Userlist + DM + Admin tools
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

// ===== أسرار / إعدادات =====
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-please-change';
const OWNER_PASS = process.env.OWNER_PASS || 'super@1200';
const ADMIN_PASS = process.env.ADMIN_PASS || '1200@';
const OWNER_2FA  = process.env.OWNER_2FA  || ''; // خليه فاضي لو ما تبي 2FA

// ===== تخزين دائم (اختياري: Disk) =====
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const BANS_FILE   = path.join(DATA_DIR, 'bans.json');
const ROLES_FILE  = path.join(DATA_DIR, 'roles.json');
const DM_LOG_FILE = path.join(DATA_DIR, 'dm_log.json');
const AUDIT_FILE  = path.join(DATA_DIR, 'audit.json');

function ensureFile(f, fallback){ try{ if(!fs.existsSync(f)) fs.writeFileSync(f, JSON.stringify(fallback,null,2)); }catch(e){ console.error('ensureFile', f, e); } }
ensureFile(BANS_FILE, []);
ensureFile(ROLES_FILE, { mods: [] });
ensureFile(DM_LOG_FILE, []);
ensureFile(AUDIT_FILE, []);

const readJSON  = f => JSON.parse(fs.readFileSync(f,'utf8'));
const writeJSON = (f,v) => fs.writeFileSync(f, JSON.stringify(v,null,2));

// ===== أدوات =====
const ipFromReq = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
const latinOrGuest=(name='')=>{
  const t=(name||'').trim();
  if(!t) return 'Guest'+Math.floor(1000+Math.random()*9000);
  return /^[ -~]+$/.test(t) ? t : 'Guest'+Math.floor(1000+Math.random()*9000);
};
const normalizePwd = (s='') => (s||'').toString()
  .replace(/\u0660/g,'0').replace(/\u0661/g,'1').replace(/\u0662/g,'2').replace(/\u0663/g,'3').replace(/\u0664/g,'4')
  .replace(/\u0665/g,'5').replace(/\u0666/g,'6').replace(/\u0667/g,'7').replace(/\u0668/g,'8').replace(/\u0669/g,'9')
  .trim();

const permsFor = role => {
  if (role==='owner') return ['*'];
  if (role==='admin') return ['kick','ban','unban','userinfo','clear','mods','pin'];
  if (role==='mod')   return ['kick','ban','unban','userinfo','clear','pin'];
  return [];
};

function isBanned({ ip, deviceId }){
  try {
    const bans = readJSON(BANS_FILE);
    return bans.some(b =>
      (ip && b.ip && b.ip===ip) ||
      (deviceId && b.deviceId && b.deviceId===deviceId)
    );
  } catch { return false; }
}

function addAudit(type,data){
  try { const a=readJSON(AUDIT_FILE); a.push({ t:Date.now(), type, ...data }); writeJSON(AUDIT_FILE,a); }
  catch(e){ console.error('audit',e); }
}

// ===== تسجيل الدخول =====
app.post('/api/login-smart',(req,res)=>{
  let { username='', password='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  const uname = latinOrGuest(username);
  const pwd = normalizePwd(password);

  // 2FA للمالك: "pass code"
  let passOnly=pwd, code='';
  if (OWNER_2FA) {
    const sp=pwd.split(' ');
    if (sp.length>=2){ code=sp.pop(); passOnly=sp.join(' '); }
  }

  // المالك أولاً (حتى لو محظور)
  if (passOnly && passOnly===OWNER_PASS){
    if (OWNER_2FA && code!==OWNER_2FA) return res.status(401).json({error:'wrong 2fa'});
    const payload = { userId: crypto.randomUUID(), username: uname, role:'owner', deviceId, perms:permsFor('owner') };
    const token   = jwt.sign(payload, JWT_SECRET, {expiresIn:'7d'});
    addAudit('login_owner',{username:uname, ip, deviceId});
    return res.json({ token, ...payload });
  }

  // تحقق الحظر للباقي
  if (isBanned({ ip, deviceId })){
    addAudit('login_blocked',{username:uname, ip, deviceId});
    return res.status(403).json({error:'banned'});
  }

  // أدمن عام
  if (passOnly && passOnly===ADMIN_PASS){
    const payload = { userId: crypto.randomUUID(), username: uname, role:'admin', deviceId, perms:permsFor('admin') };
    const token   = jwt.sign(payload, JWT_SECRET, {expiresIn:'7d'});
    addAudit('login_admin',{username:uname, ip, deviceId});
    return res.json({ token, ...payload });
  }

  // مشرفين من roles.json
  try {
    const roles = readJSON(ROLES_FILE);
    const hit = (roles.mods||[]).find(m=> m.username.toLowerCase()===uname.toLowerCase());
    if (hit){
      const ok = !hit.password || hit.password===passOnly;
      if (!ok) return res.status(401).json({error:'wrong password'});
      const payload = { userId: crypto.randomUUID(), username: uname, role:'mod', deviceId, perms:permsFor('mod') };
      const token   = jwt.sign(payload, JWT_SECRET, {expiresIn:'7d'});
      addAudit('login_mod',{username:uname, ip, deviceId});
      return res.json({ token, ...payload });
    }
  } catch(e){ console.error('roles read',e); }

  // مستخدم عادي (بدون كلمة سر)
  if (!passOnly){
    const payload = { userId: crypto.randomUUID(), username: uname, role:'user', deviceId, perms:[] };
    const token   = jwt.sign(payload, JWT_SECRET, {expiresIn:'7d'});
    addAudit('login_user',{username:uname, ip, deviceId});
    return res.json({ token, ...payload });
  }

  return res.status(401).json({error:'wrong password'});
});

// ===== إدارة (مالك فقط عبر REST) =====
function authOwner(req,res,next){
  try {
    const tok=(req.headers.authorization||'').split(' ')[1];
    const dec=jwt.verify(tok, JWT_SECRET);
    if (dec.role!=='owner') return res.status(403).json({error:'forbidden'});
    req.user=dec; next();
  } catch { return res.status(401).json({error:'unauth'}); }
}
app.get('/api/admin/bans', authOwner, (req,res)=>{ try{res.json(readJSON(BANS_FILE))}catch{res.json([])} });
app.post('/api/admin/unban', authOwner, (req,res)=>{
  const { ip, deviceId } = req.body||{};
  try {
    let bans=readJSON(BANS_FILE);
    bans=bans.filter(b=> !((ip&&b.ip===ip)||(deviceId&&b.deviceId===deviceId)));
    writeJSON(BANS_FILE,bans);
    res.json({ok:true,bans});
  }catch{ res.status(500).json({error:'fail'}) }
});
app.post('/api/owner/mods', authOwner, (req,res)=>{
  const { username, role='mod', password='' } = req.body||{};
  if(!username) return res.status(400).json({error:'no username'});
  try{
    const roles=readJSON(ROLES_FILE);
    const list=roles.mods||[];
    const i=list.findIndex(m=>m.username.toLowerCase()===username.toLowerCase());
    if(role==='delete'){ if(i>=0) list.splice(i,1); }
    else if(i>=0){ list[i].password=password; }
    else { list.push({username,password}); }
    roles.mods=list; writeJSON(ROLES_FILE,roles);
    res.json({ok:true,mods:list});
  }catch(e){ console.error(e); res.status(500).json({error:'fail'})}
});

// ===== صفحة الواجهة =====
app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'page.html')));

// ===== سوكت: غرفة واحدة "العرب" =====
/** تخزين حيّ */
const USERS = new Map(); // socketId -> {userId, username, role, deviceId}
const ROOM  = 'العرب';
let PINNED  = '';        // رسالة مثبتة
const lastJoinMsg = new Map(); // userId -> timestamp (منع تكرار "انضم" خلال 5 دقائق)

io.use((socket,next)=>{
  try{
    const token = socket.handshake.auth?.token;
    const dec = jwt.verify(token, JWT_SECRET);
    socket.user = dec;
    next();
  }catch{ next(new Error('unauthorized')) }
});

io.on('connection', (socket)=>{
  const u = socket.user; // {userId, username, role, deviceId, perms}
  USERS.set(socket.id, u);
  socket.join(ROOM);

  // أرسل قائمة المتواجدين للمستخدم فقط
  socket.emit('userlist', listUsers());
  // أرسل الرسالة المثبتة
  if (PINNED) socket.emit('pin', PINNED);

  // إعلان انضمام بدون تكرار خلال 5 دق
  const now=Date.now(), last=lastJoinMsg.get(u.userId)||0;
  if (now-last>5*60*1000){
    io.to(ROOM).emit('sys', { kind:'join', text:`${u.username} دخل الغرفة.` });
    lastJoinMsg.set(u.userId, now);
  }

  // أبلِغ الجميع بقائمة جديدة
  io.to(ROOM).emit('userlist', listUsers());

  socket.on('msg', (text='')=>{
    text=(''+text).slice(0,1000).trim();
    if(!text) return;
    io.to(ROOM).emit('msg', { from:u.username, role:u.role, t:Date.now(), text });
  });

  socket.on('dm', ({toUserId, text=''})=>{
    text=(''+text).slice(0,1000).trim();
    if(!toUserId || !text) return;
    const toSockId = findSocketByUserId(toUserId);
    if(!toSockId) return;
    io.to(toSockId).emit('dm', { fromId:u.userId, from:u.username, text, t:Date.now() });
    socket.emit('dm:sent', { toId:toUserId, text, t:Date.now() });
    // سجل DM (اختياري)
    try{ const d=readJSON(DM_LOG_FILE); d.push({t:Date.now(), from:u.userId, to:toUserId, text}); writeJSON(DM_LOG_FILE,d);}catch{}
  });

  // أدوات إدارة
  socket.on('admin:clear', ()=>{ if(can(u,'clear')) io.to(ROOM).emit('clear'); });
  socket.on('admin:pin', (text)=>{ if(can(u,'pin')){ PINNED=(''+text).slice(0,500); io.to(ROOM).emit('pin', PINNED); }});
  socket.on('admin:kick', (userId)=>{
    if(!can(u,'kick')) return;
    const sid=findSocketByUserId(userId); if(!sid) return;
    io.to(sid).emit('sys',{kind:'kick',text:'تم طردك من الغرفة.'});
    io.sockets.sockets.get(sid)?.disconnect(true);
    io.to(ROOM).emit('sys',{kind:'act',text:`${u.username} طرد عضوًا.`});
  });
  socket.on('admin:ban', ({userId, ip, deviceId})=>{
    if(!can(u,'ban')) return;
    try{
      const bans=readJSON(BANS_FILE);
      if (ip) bans.push({ip});
      if (deviceId) bans.push({deviceId});
      writeJSON(BANS_FILE,bans);
      const sid = userId && findSocketByUserId(userId);
      if (sid){ io.sockets.sockets.get(sid)?.disconnect(true); }
      io.to(ROOM).emit('sys',{kind:'act',text:`${u.username} حظر عضوًا.`});
    }catch{}
  });
  socket.on('admin:unban', ({ip,deviceId})=>{
    if(!can(u,'unban')) return;
    try{
      let bans=readJSON(BANS_FILE);
      bans=bans.filter(b=> !((ip&&b.ip===ip)||(deviceId&&b.deviceId===deviceId)));
      writeJSON(BANS_FILE,bans);
      io.to(ROOM).emit('sys',{kind:'act',text:`${u.username} فك حظر.`});
    }catch{}
  });

  socket.on('disconnect', ()=>{
    USERS.delete(socket.id);
    io.to(ROOM).emit('userlist', listUsers());
    io.to(ROOM).emit('sys', {kind:'leave', text:`${u.username} غادر.`});
  });
});

function listUsers(){
  const arr=[];
  USERS.forEach(v=> arr.push({userId:v.userId, username:v.username, role:v.role}));
  return arr;
}
function findSocketByUserId(uid){
  for (const [sid,v] of USERS.entries()) if (v.userId===uid) return sid;
  return null;
}
function can(user, perm){
  if (!user) return false;
  if (user.role==='owner') return true;
  if (user.perms?.includes(perm)) return true;
  if (user.perms?.includes('*')) return true;
  return false;
}

const PORT = process.env.PORT || 10000;
server.listen(PORT, ()=> console.log('UP on', PORT));
