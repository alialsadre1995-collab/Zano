// server.js — serves page.html at "/" + API + Socket.IO
require('dotenv').config();
const path = require('path');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()),
    methods: ['GET','POST'],
    credentials: true
  }
});

const PORT = process.env.PORT || 10000;
if ((process.env.TRUST_PROXY || '').toLowerCase() === 'true') app.set('trust proxy', 1);

// middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()), credentials: true }));
app.use(express.json());
app.use(cookieParser());

// serve page.html
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'page.html')));
app.get('/healthz', (req,res)=>res.json({ok:true}));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ROOM_NAME = 'غرفه العرب';
const now = () => Date.now();

// in-memory stores
const users = new Map();        // userId -> { username, role, deviceId, passHash?, color, lastSeenAt }
const usernameIndex = new Map();// username -> userId
const deviceIndex = new Map();  // deviceId -> userId
const onlineSockets = new Map();// socket.id -> { userId }
const bans = new Map();         // key -> { type, reason, by, createdAt, expiresAt }
const kicks = new Map();        // deviceId -> { by, reason, at }
const history = [];             // [{from, userId, color, text, ts, mid}]
const dmHistory = new Map();    // dmKey -> [{fromId,toId,text,ts,mid}]
const englishOnly = s => /^[A-Za-z0-9_.-]{3,20}$/.test(s || '');
const hasArabic = s => /[\u0600-\u06FF]/.test(s || '');
const colorPool = ['#60a5fa','#f472b6','#f59e0b','#34d399','#a78bfa','#f87171','#22d3ee','#c084fc','#fb923c','#4ade80'];
const pickColor = () => colorPool[Math.floor(Math.random()*colorPool.length)];
const dmKey = (a,b) => [a,b].sort().join(':');

// fixed admin
const FIXED_ADMIN_USER = process.env.FIXED_ADMIN_USER || 'Admin';
const FIXED_ADMIN_PASS = process.env.FIXED_ADMIN_PASS || '1200@';
async function ensureFixedAdmin(){
  if (usernameIndex.has(FIXED_ADMIN_USER)) return;
  const userId = nanoid(21);
  const passHash = await bcrypt.hash(FIXED_ADMIN_PASS, 10);
  const deviceId = 'fixed-admin-device';
  users.set(userId, { username: FIXED_ADMIN_USER, role: 'admin', deviceId, passHash, color: '#ffffff', lastSeenAt: 0 });
  usernameIndex.set(FIXED_ADMIN_USER, userId);
  deviceIndex.set(deviceId, userId);
  console.log('Fixed admin ready:', FIXED_ADMIN_USER);
}

// auth helpers
const signToken = p => jwt.sign(p, JWT_SECRET, { expiresIn: '30d' });
const authRequired = (req,res,next)=>{
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'unauthorized' }); }
};
const adminOrMod = (req,res,next)=>{
  const u = users.get(req.user.userId);
  if (u && (u.role==='admin' || u.role==='mod')) return next();
  res.status(403).json({ error:'forbidden' });
};

// REST
app.post('/api/login-pass', async (req,res)=>{
  let { username, password, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username) || hasArabic(username)) username = 'Guest' + Math.floor(1000+Math.random()*9000);
  const id = usernameIndex.get(username);
  if (!id) return res.status(404).json({ error:'No such user' });
  const u = users.get(id);
  if (!u?.passHash) return res.status(400).json({ error:'User has no password set' });
  const ok = await bcrypt.compare(password || '', u.passHash);
  if (!ok) return res.status(403).json({ error:'Wrong password' });
  const devId = deviceId || u.deviceId || nanoid(16);
  u.deviceId = devId; deviceIndex.set(devId, id);
  const token = signToken({ userId:id, username:u.username, deviceId:devId });
  res.json({ ok:true, token, userId:id, role:u.role, deviceId:devId, username:u.username, color:u.color || '#fff' });
});

app.post('/api/login', (req,res)=>{
  let { username, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username) || hasArabic(username)) username = 'Guest' + Math.floor(1000+Math.random()*9000);

  const ban = (bans.get(deviceId) || bans.get(usernameIndex.get(username) || '') || null);
  if (ban && (!ban.expiresAt || ban.expiresAt > now())) return res.status(403).json({ error: 'banned' });

  let userId = deviceIndex.get(deviceId || '');
  if (!userId){
    if (usernameIndex.has(username)){
      const exId = usernameIndex.get(username);
      const ex = users.get(exId);
      if (ex?.passHash) return res.status(400).json({ error:'Password protected user. Use /api/login-pass' });
      userId = exId; ex.deviceId = deviceId || ex.deviceId || nanoid(16); ex.username = username;
    }else{
      userId = nanoid(21);
      const devId = deviceId || nanoid(16);
      users.set(userId, { username, role:'user', deviceId: devId, color: pickColor(), lastSeenAt: 0 });
      usernameIndex.set(username, userId); deviceIndex.set(devId, userId);
    }
  } else {
    const u = users.get(userId);
    if (u?.passHash) return res.status(400).json({ error:'Password protected user. Use /api/login-pass' });
    u.username = username;
  }
  const u = users.get(userId);
  const token = signToken({ userId, username: u.username, deviceId: u.deviceId });
  res.json({ ok:true, token, userId, role:u.role, deviceId: u.deviceId, username: u.username, color:u.color });
});

app.get('/api/me', authRequired, (req,res)=>{
  const u = users.get(req.user.userId);
  if (!u) return res.status(404).json({ error:'User not found' });
  res.json({ userId:req.user.userId, username:u.username, role:u.role, deviceId:u.deviceId, color:u.color });
});

app.get('/api/admin/bans', authRequired, adminOrMod, (req,res)=>{
  res.json(Array.from(bans, ([key,val])=>({ key, ...val })));
});
app.get('/api/admin/kicks', authRequired, adminOrMod, (req,res)=>{
  res.json(Array.from(kicks, ([key,val])=>({ key, ...val })));
});
app.post('/api/admin/ban', authRequired, adminOrMod, (req,res)=>{
  const { targetType, targetValue, reason, minutes } = req.body || {};
  if (!['userId','deviceId','ip'].includes(targetType)) return res.status(400).json({ error:'invalid type' });
  const expiresAt = minutes ? now() + minutes*60*1000 : null;
  bans.set(targetValue, { type: targetType, reason: reason||'', by: req.user.userId, createdAt: now(), expiresAt });
  res.json({ ok:true });
});
app.post('/api/admin/unban', authRequired, adminOrMod, (req,res)=>{
  bans.delete((req.body||{}).key);
  res.json({ ok:true });
});
app.post('/api/admin/kick', authRequired, adminOrMod, (req,res)=>{
  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).json({ error:'deviceId required' });
  kicks.set(deviceId, { by:req.user.userId, reason: reason||'', at: now() });
  for (const [sid, meta] of onlineSockets.entries()){
    const u = users.get(meta.userId);
    if (u?.deviceId === deviceId){
      const s = io.sockets.sockets.get(sid);
      if (s) s.disconnect(true);
    }
  }
  res.json({ ok:true });
});
app.post('/api/admin/role', authRequired, (req,res)=>{
  const caller = users.get(req.user.userId);
  if (!caller || caller.role !== 'admin') return res.status(403).json({ error:'forbidden' });
  const { userId, role } = req.body || {};
  if (!['user','mod','admin'].includes(role)) return res.status(400).json({ error:'bad role' });
  const u = users.get(userId); if (!u) return res.status(404).json({ error:'no user' });
  u.role = role; res.json({ ok:true });
});
app.post('/api/admin/clear', authRequired, adminOrMod, (req,res)=>{
  history.length = 0; io.to(ROOM_NAME).emit('admin:clear'); res.json({ ok:true });
});

// socket.io
io.use((socket, next)=>{
  try{ socket.user = jwt.verify(socket.handshake.auth?.token, JWT_SECRET); next(); }
  catch{ next(new Error('unauthorized')); }
});
io.on('connection', (socket)=>{
  const { userId } = socket.user || {};
  const u = users.get(userId); if (!u) return socket.disconnect(true);

  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() || socket.request.socket.remoteAddress || '0.0.0.0';
  const banned = [u.deviceId, userId, ip].map(k=>bans.get(k)).find(b=>b && (!b.expiresAt || b.expiresAt > now()));
  if (banned){ socket.emit('banned', { reason: banned.reason || 'banned' }); return socket.disconnect(true); }

  socket.join(ROOM_NAME);
  onlineSockets.set(socket.id, { userId });

  if (!u.lastSeenAt || u.lastSeenAt < now()-5*60*1000){
    io.to(ROOM_NAME).emit('system', { type:'join', userId, username: u.username, ts: now() });
  }

  socket.emit('history', history.slice(-200));
  emitPresence();

  socket.on('chat:msg', p=>{
    const text = (p?.text || '').toString().trim().slice(0,600);
    if (!text) return;
    const rec = { from:u.username, userId, color:u.color || '#fff', text, ts: now(), mid: nanoid(10) };
    history.push(rec); io.to(ROOM_NAME).emit('chat:new', rec);
  });
  socket.on('chat:reply', p=>{
    const text = (p?.text || '').toString().trim().slice(0,600);
    const ref = (p?.ref || '').toString().slice(0,20);
    if (!text || !ref) return;
    const rec = { from:u.username, userId, color:u.color || '#fff', text, ts: now(), mid:nanoid(10), ref };
    history.push(rec); io.to(ROOM_NAME).emit('chat:new', rec);
  });
  socket.on('dm:send', p=>{
    const toId = (p?.toId || '').toString(); const text = (p?.text || '').toString().trim().slice(0,600);
    if (!toId || !text) return;
    const key = dmKey(userId, toId); const rec = { fromId:userId, toId, text, ts: now(), mid:nanoid(10) };
    const arr = dmHistory.get(key) || []; arr.push(rec); dmHistory.set(key, arr);
    for (const [sid, meta] of onlineSockets.entries()){
      if (meta.userId===userId || meta.userId===toId){ const s = io.sockets.sockets.get(sid); s && s.emit('dm:new', rec); }
    }
  });

  socket.on('admin:ban', data=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    const { targetType, targetValue, reason, minutes } = data || {};
    if (!['userId','deviceId','ip'].includes(targetType)) return;
    bans.set(targetValue, { type:targetType, reason:reason||'', by:userId, createdAt: now(), expiresAt: minutes ? now()+minutes*60*1000 : null });
    io.to(ROOM_NAME).emit('admin:update');
  });
  socket.on('admin:kick', data=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    const dv = data?.deviceId; if (!dv) return;
    kicks.set(dv, { by:userId, reason:data?.reason||'', at: now() });
    for (const [sid, meta] of onlineSockets.entries()){
      const t = users.get(meta.userId);
      if (t?.deviceId===dv){ const s = io.sockets.sockets.get(sid); s && s.disconnect(true); }
    }
  });
  socket.on('admin:role', data=>{
    const caller = users.get(userId);
    if (!caller || caller.role!=='admin') return;
    const { targetUserId, role } = data || {};
    if (!['user','mod','admin'].includes(role)) return;
    const t = users.get(targetUserId); if (!t) return; t.role = role; io.to(ROOM_NAME).emit('admin:update');
  });
  socket.on('admin:clear', ()=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    history.length = 0; io.to(ROOM_NAME).emit('admin:clear');
  });

  socket.on('disconnect', ()=>{
    onlineSockets.delete(socket.id);
    u.lastSeenAt = now();
    emitPresence();
  });
});

function emitPresence(){
  const uniq = new Map();
  for (const {userId} of onlineSockets.values()){
    const u = users.get(userId);
    if (u) uniq.set(userId, { userId, username: u.username, color: u.color || '#fff', role: u.role });
  }
  io.to(ROOM_NAME).emit('presence', Array.from(uniq.values()));
}

ensureFixedAdmin().then(()=> server.listen(PORT, ()=>console.log('Server on', PORT)))
.catch(err=>{ console.error(err); process.exit(1); });
