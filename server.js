// server.js
// يعمل مع Render (أو محليًا) بملف واحد

const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] }
});

app.use(cors());
app.use(express.json());

// ===== إعدادات عامة =====
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const ADMIN_PASS = process.env.ADMIN_PASS || '1200@';
const PORT = process.env.PORT || 3000;

// ===== مخازن بالذاكرة =====
const messages = [];                 // تاريخ الرسائل العامة
const sockets = new Map();           // socket.id -> u
const usersById = new Map();         // userId -> u (آخر جلسة)
const sessions = new Map();          // token -> payload
const bans = [];                     // [{targetType:'ip'|'deviceId', targetValue, username?, ts}]

// ===== مساعدات =====
function now(){ return Date.now(); }
function ipFromReq(req){
  const xf = req.headers['x-forwarded-for'];
  return (Array.isArray(xf) ? xf[0] : (xf||'')).split(',')[0].trim() || req.socket?.remoteAddress || '';
}
function ipFromSocket(socket){
  const xf = socket.handshake.headers['x-forwarded-for'];
  return (xf?.split(',')[0].trim()) || socket.handshake.address || '';
}
function latinOrGuest(name){
  const ok = /^[A-Za-z0-9_.-]{3,20}$/.test(name||'');
  if(!ok) return 'Guest'+Math.floor(1000+Math.random()*9000);
  return name;
}
function colorFor(name){
  // لون ثابت حسب الاسم
  const h = crypto.createHash('md5').update(name).digest('hex');
  const n = parseInt(h.slice(0,2),16);
  return ['#30c0ff','#22c55e','#f59e0b','#e879f9','#f43f5e','#38bdf8'][n%6];
}
function isBanned(check){
  // check: {ip, deviceId}
  return bans.some(b=>{
    if(b.targetType==='ip' && b.targetValue && check.ip && check.ip===b.targetValue) return true;
    if(b.targetType==='deviceId' && b.targetValue && check.deviceId && check.deviceId===b.targetValue) return true;
    return false;
  });
}
function authMiddleware(req,res,next){
  const h = req.headers.authorization||'';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({error:'no token'});
  try{
    const p = jwt.verify(token, JWT_SECRET);
    req.user = p;
    return next();
  }catch(e){
    return res.status(401).json({error:'bad token'});
  }
}
function adminOnly(req,res,next){
  if(!req.user || !['admin','mod'].includes(req.user.role)) {
    return res.status(403).json({error:'forbidden'});
  }
  next();
}

// ===== APIs: تسجيل الدخول =====
app.post('/api/login', (req,res)=>{
  const { username = '', deviceId = '' } = req.body||{};
  const ip = ipFromReq(req);
  const uname = latinOrGuest(username);
  const role = 'user';

  // منع دخول المحظور
  if(isBanned({ip, deviceId})) return res.status(403).json({error:'banned'});

  const userId = crypto.randomUUID();
  const token = jwt.sign({ userId, username: uname, role, deviceId }, JWT_SECRET, { expiresIn:'7d' });
  sessions.set(token, { userId, username: uname, role, deviceId });

  return res.json({ token, userId, username: uname, role });
});

app.post('/api/login-pass', (req,res)=>{
  const { username = 'Admin', password = '', deviceId = '' } = req.body||{};
  const ip = ipFromReq(req);
  if(password !== ADMIN_PASS) return res.status(401).json({error:'wrong password'});

  if(isBanned({ip, deviceId})) return res.status(403).json({error:'banned'});

  const uname = latinOrGuest(username||'Admin');
  const role = 'admin';
  const userId = crypto.randomUUID();
  const token = jwt.sign({ userId, username: uname, role, deviceId }, JWT_SECRET, { expiresIn:'7d' });
  sessions.set(token, { userId, username: uname, role, deviceId });

  return res.json({ token, userId, username: uname, role });
});

// ===== APIs: إدارة =====

// قائمة الحظر
app.get('/api/admin/bans', authMiddleware, adminOnly, (req,res)=>{
  // أحدث أولاً
  const sorted = [...bans].sort((a,b)=> (b.ts||0)-(a.ts||0));
  res.json(sorted);
});

// فكّ الحظر
app.post('/api/admin/unban', authMiddleware, adminOnly, (req,res)=>{
  const { targetType, targetValue } = req.body||{};
  if(!['ip','deviceId'].includes(targetType) || !targetValue) {
    return res.status(400).json({error:'bad params'});
  }
  const before = bans.length;
  for(let i=bans.length-1; i>=0; i--){
    if(bans[i].targetType===targetType && bans[i].targetValue===targetValue){
      bans.splice(i,1);
    }
  }
  return res.json({ ok:true, removed: before - bans.length });
});

// حظر (IP/جهاز)
app.post('/api/admin/ban', authMiddleware, adminOnly, (req,res)=>{
  const { targetType, targetValue, reason='' } = req.body||{};
  if(!['ip','deviceId'].includes(targetType) || !targetValue) {
    return res.status(400).json({error:'bad params'});
  }
  // لا نكرر
  if(!bans.find(b=> b.targetType===targetType && b.targetValue===targetValue)){
    bans.push({ targetType, targetValue, reason, username: req.user.username, ts: now() });
  }
  return res.json({ ok:true });
});

// طرد (بالجهاز)
app.post('/api/admin/kick', authMiddleware, adminOnly, (req,res)=>{
  const { deviceId } = req.body||{};
  if(!deviceId) return res.status(400).json({error:'bad params'});

  // ابحث عن سوكيت يحمل نفس الـ deviceId
  for(const [sid,u] of sockets.entries()){
    if(u.deviceId === deviceId){
      const s = io.sockets.sockets.get(sid);
      if(s){ s.emit('banned',{reason:'kicked'}); s.disconnect(true); }
    }
  }
  res.json({ ok:true });
});

// كشف معلومات (حسب userId أو username)
app.get('/api/admin/user-info', authMiddleware, adminOnly, (req,res)=>{
  const { userId, username } = req.query||{};
  let found = null;

  if(userId){
    for(const u of sockets.values()){ if(u.userId===userId){ found=u; break; } }
  }else if(username){
    for(const u of sockets.values()){ if(u.username===username){ found=u; break; } }
  }
  if(!found) return res.status(404).json({error:'not found'});

  res.json({
    userId: found.userId,
    username: found.username,
    role: found.role,
    deviceId: found.deviceId,
    ip: found.ip,
    socketId: found.socketId
  });
});

// ===== Socket.IO =====
io.use((socket,next)=>{
  try{
    const token = socket.handshake.auth?.token;
    if(!token) return next(new Error('no token'));
    const p = jwt.verify(token, JWT_SECRET);
    socket.user = p; // {userId, username, role, deviceId}
    socket.ip = ipFromSocket(socket);

    if(isBanned({ip: socket.ip, deviceId: p.deviceId})){
      return next(new Error('banned'));
    }
    next();
  }catch(e){ next(new Error('bad token')); }
});

function presenceList(){
  const arr=[];
  for(const [,u] of sockets.entries()){
    arr.push({ userId:u.userId, username:u.username, color:u.color, deviceId:u.deviceId });
  }
  return arr;
}

io.on('connection', (socket)=>{
  const p = socket.user;
  const u = {
    socketId: socket.id,
    userId: p.userId,
    username: p.username,
    role: p.role,
    deviceId: p.deviceId || '',
    ip: socket.ip,
    color: colorFor(p.username)
  };
  sockets.set(socket.id, u);
  usersById.set(u.userId, u);

  // أرسل التاريخ والحضور
  socket.emit('history', messages.slice(-200));
  io.emit('presence', presenceList());

  // رسالة عامة
  socket.on('chat:msg', (data={})=>{
    const text = (data.text||'').toString().slice(0, 1500).trim();
    if(!text) return;
    if(isBanned({ip: u.ip, deviceId: u.deviceId})){
      socket.emit('banned',{reason:'banned'}); socket.disconnect(); return;
    }
    const msg = { from:u.username, userId:u.userId, color:u.color, text, ts: now() };
    messages.push(msg); if(messages.length>1000) messages.shift();
    io.emit('chat:new', msg);
  });

  // رسائل خاصة
  socket.on('dm:send', ({toId, text}={})=>{
    const t = (text||'').toString().slice(0, 1500).trim();
    if(!toId || !t) return;
    const target = [...sockets.values()].find(x=> x.userId===toId);
    if(!target) return;
    const payload = { fromId:u.userId, toId: target.userId, text:t, ts: now() };
    // للطرفين
    socket.to(target.socketId).emit('dm:new', payload);
    socket.emit('dm:new', payload);
  });

  socket.on('disconnect', ()=>{
    sockets.delete(socket.id);
    io.emit('presence', presenceList());
  });
});

// ===== تقديم الصفحة =====
const fs = require('fs');
const path = require('path');
app.get('/', (req,res)=>{
  res.setHeader('Content-Type','text/html; charset=utf-8');
  fs.createReadStream(path.join(__dirname,'page.html')).pipe(res);
});

// صحة
app.get('/healthz', (req,res)=> res.json({ok:true}));

server.listen(PORT, ()=> console.log('listening on '+PORT));
