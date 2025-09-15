
// server.js — Backend (no public). Single room "غرفه العرب" + DMs. Admin tools. In-memory MVP.
require('dotenv').config();
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

app.use(helmet());
app.use(cors({ origin: (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim()), credentials: true }));
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ROOM_NAME = 'غرفه العرب';

// In-memory
const users = new Map();        // userId -> { username, role, deviceId, passHash?, color, lastSeenAt }
const usernameIndex = new Map();// username -> userId
const deviceIndex = new Map();  // deviceId -> userId
const onlineSockets = new Map();// socket.id -> { userId }
const bans = new Map();         // key -> { type, reason, by, createdAt, expiresAt }
const kicks = new Map();        // deviceId/userId -> { by, reason, at }
const history = [];             // [{from, userId, text, ts, mid}]
const dmHistory = new Map();    // key = dmKey(a,b) -> [{fromId,toId,text,ts,mid}]

const englishOnly = s => /^[A-Za-z0-9_.-]{3,20}$/.test(s || '');
const hasArabic = s => /[\u0600-\u06FF]/.test(s || '');
const now = () => Date.now();
const colorPool = ['#60a5fa','#f472b6','#f59e0b','#34d399','#a78bfa','#f87171','#22d3ee','#c084fc','#fb923c','#4ade80'];
function pickColor(){ return colorPool[Math.floor(Math.random()*colorPool.length)]; }
function dmKey(a,b){ return [a,b].sort().join(':'); }

// ----- Fixed admin -----
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
  console.log('Fixed admin created:', FIXED_ADMIN_USER);
}

// ----- Auth helpers -----
function signToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }); }
function authRequired(req,res,next){
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'unauthorized' }); }
}
function adminOrMod(req,res,next){
  const u = users.get(req.user.userId);
  if (u && (u.role==='admin' || u.role==='mod')) return next();
  res.status(403).json({ error:'forbidden' });
}

// ----- REST API -----
// Login with password
app.post('/api/login-pass', async (req,res)=>{
  let { username, password, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username) || hasArabic(username)) username = 'Guest' + Math.floor(1000+Math.random()*9000).toString();
  const id = usernameIndex.get(username);
  if (!id) return res.status(404).json({ error:'No such user' });
  const u = users.get(id);
  if (!u?.passHash) return res.status(400).json({ error:'User has no password set' });
  const ok = await bcrypt.compare(password || '', u.passHash);
  if (!ok) return res.status(403).json({ error:'Wrong password' });
  const devId = deviceId || u.deviceId || nanoid(16);
  u.deviceId = devId;
  deviceIndex.set(devId, id);
  const token = signToken({ userId:id, username:u.username, deviceId:devId });
  res.json({ ok:true, token, userId:id, role:u.role, deviceId:devId, username:u.username, color:u.color || '#fff' });
});
// Quick login (no pass) for non-protected usernames
app.post('/api/login', (req,res)=>{
  let { username, deviceId } = req.body || {};
  username = (username || '').trim();
  if (!englishOnly(username) || hasArabic(username)) username = 'Guest' + Math.floor(1000+Math.random()*9000).toString();

  // banned by device?
  const ban = (bans.get(deviceId) || bans.get(usernameIndex.get(username) || '') || null);
  if (ban && (!ban.expiresAt || ban.expiresAt > now())) return res.status(403).json({ error: 'banned' });

  let userId = deviceIndex.get(deviceId || '');
  if (!userId){
    if (usernameIndex.has(username)){
      const existingId = usernameIndex.get(username);
      const existing = users.get(existingId);
      if (existing?.passHash) return res.status(400).json({ error:'Password protected user. Use /api/login-pass' });
      // reuse same account
      userId = existingId;
      existing.deviceId = deviceId || existing.deviceId || nanoid(16);
      existing.username = username;
    }else{
      userId = nanoid(21);
      const devId = deviceId || nanoid(16);
      users.set(userId, { username, role:'user', deviceId: devId, color: pickColor(), lastSeenAt: 0 });
      usernameIndex.set(username, userId);
      deviceIndex.set(devId, userId);
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

// Who am I
app.get('/api/me', authRequired, (req,res)=>{
  const u = users.get(req.user.userId);
  if (!u) return res.status(404).json({ error:'User not found' });
  res.json({ userId:req.user.userId, username:u.username, role:u.role, deviceId:u.deviceId, color:u.color });
});

// Admin: lists
app.get('/api/admin/bans', authRequired, adminOrMod, (req,res)=>{
  const list = Array.from(bans.entries()).map(([key,val])=>({ key, ...val }));
  res.json(list);
});
app.get('/api/admin/kicks', authRequired, adminOrMod, (req,res)=>{
  const list = Array.from(kicks.entries()).map(([key,val])=>({ key, ...val }));
  res.json(list);
});

// Admin: actions
app.post('/api/admin/ban', authRequired, adminOrMod, (req,res)=>{
  const { targetType, targetValue, reason, minutes } = req.body || {};
  if (!['userId','deviceId','ip'].includes(targetType)) return res.status(400).json({ error:'invalid type' });
  const expiresAt = minutes ? now() + minutes*60*1000 : null;
  bans.set(targetValue, { type: targetType, reason: reason||'', by: req.user.userId, createdAt: now(), expiresAt });
  res.json({ ok:true });
});
app.post('/api/admin/unban', authRequired, adminOrMod, (req,res)=>{
  const { key } = req.body || {};
  bans.delete(key);
  res.json({ ok:true });
});
app.post('/api/admin/kick', authRequired, adminOrMod, (req,res)=>{
  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).json({ error:'deviceId required' });
  kicks.set(deviceId, { by:req.user.userId, reason: reason||'', at: now() });
  // disconnect all sockets of that device
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
  const u = users.get(userId);
  if (!u) return res.status(404).json({ error:'no user' });
  u.role = role;
  res.json({ ok:true });
});
app.post('/api/admin/clear', authRequired, adminOrMod, (req,res)=>{
  history.length = 0;
  io.to(ROOM_NAME).emit('admin:clear');
  res.json({ ok:true });
});

// ----- Socket.IO -----
io.use((socket, next)=>{
  try{
    const token = socket.handshake.auth?.token;
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded; next();
  }catch(e){ next(new Error('unauthorized')); }
});

io.on('connection', (socket)=>{
  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
             socket.request.socket.remoteAddress || '0.0.0.0';
  const { userId, deviceId, username } = socket.user || {};
  const u = users.get(userId);
  if (!u) { socket.disconnect(true); return; }

  // bans check
  const checkBan = (k) => {
    const b = bans.get(k);
    return b && (!b.expiresAt || b.expiresAt > now()) ? b : null;
  };
  const activeBan = checkBan(deviceId) || checkBan(userId) || checkBan(ip);
  if (activeBan){
    socket.emit('banned', { reason: activeBan.reason || 'banned' }); // hide IP
    return socket.disconnect(true);
  }

  // Join room
  socket.join(ROOM_NAME);
  onlineSockets.set(socket.id, { userId });
  const last5min = now() - 5*60*1000;
  const shouldAnnounceJoin = !u.lastSeenAt || u.lastSeenAt < last5min;
  if (shouldAnnounceJoin){
    io.to(ROOM_NAME).emit('system', { type:'join', userId, username: u.username, ts: now() });
  }

  // Send recent history (limited)
  socket.emit('history', history.slice(-200));

  // Presence
  emitPresence();

  // Chat message
  socket.on('chat:msg', (p)=>{
    const text = (p?.text || '').toString().trim().slice(0, 600);
    if (!text) return;
    const mid = nanoid(10);
    const rec = { from: u.username, userId, color: u.color || '#fff', text, ts: now(), mid };
    history.push(rec);
    io.to(ROOM_NAME).emit('chat:new', rec);
  });

  // Reply (just attach ref mid)
  socket.on('chat:reply', (p)=>{
    const text = (p?.text || '').toString().trim().slice(0, 600);
    const ref = (p?.ref || '').toString().slice(0,20);
    if (!text || !ref) return;
    const mid = nanoid(10);
    const rec = { from: u.username, userId, color: u.color || '#fff', text, ts: now(), mid, ref };
    history.push(rec);
    io.to(ROOM_NAME).emit('chat:new', rec);
  });

  // DM
  socket.on('dm:send', (p)=>{
    const toId = (p?.toId || '').toString();
    const text = (p?.text || '').toString().trim().slice(0,600);
    if (!toId || !text) return;
    const key = dmKey(userId, toId);
    const mid = nanoid(10);
    const arr = dmHistory.get(key) || [];
    const rec = { fromId:userId, toId, text, ts: now(), mid };
    arr.push(rec); dmHistory.set(key, arr);
    // deliver to both sides
    for (const [sid, meta] of onlineSockets.entries()){
      if (meta.userId === userId || meta.userId === toId){
        const s = io.sockets.sockets.get(sid);
        if (s) s.emit('dm:new', rec);
      }
    }
  });

  // Admin socket actions
  socket.on('admin:ban', (data)=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    const { targetType, targetValue, reason, minutes } = data || {};
    if (!['userId','deviceId','ip'].includes(targetType)) return;
    const expiresAt = minutes ? now() + minutes*60*1000 : null;
    bans.set(targetValue, { type:targetType, reason:reason||'', by:userId, createdAt: now(), expiresAt });
    // don't expose IP to chat
    io.to(ROOM_NAME).emit('admin:update');
  });

  socket.on('admin:kick', (data)=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    const targetDevice = data?.deviceId;
    if (!targetDevice) return;
    kicks.set(targetDevice, { by:userId, reason:data?.reason||'', at: now() });
    for (const [sid, meta] of onlineSockets.entries()){
      const tUser = users.get(meta.userId);
      if (tUser?.deviceId === targetDevice){
        const s = io.sockets.sockets.get(sid);
        if (s) s.disconnect(true);
      }
    }
  });

  socket.on('admin:role', (data)=>{
    const caller = users.get(userId);
    if (!caller || caller.role!=='admin') return;
    const { targetUserId, role } = data || {};
    if (!['user','mod','admin'].includes(role)) return;
    const t = users.get(targetUserId);
    if (!t) return;
    t.role = role;
    io.to(ROOM_NAME).emit('admin:update');
  });

  socket.on('admin:clear', ()=>{
    const caller = users.get(userId);
    if (!caller || (caller.role!=='admin' && caller.role!=='mod')) return;
    history.length = 0;
    io.to(ROOM_NAME).emit('admin:clear');
  });

  socket.on('disconnect', ()=>{
    onlineSockets.delete(socket.id);
    const last5min = now() - 5*60*1000;
    u.lastSeenAt = now();
    const shouldAnnounceLeave = !u.lastSeenAt || u.lastSeenAt < last5min;
    // we just set lastSeenAt, so compare with previous stored? Keep simple: do not spam leave within 5m
    // We'll skip leave announce always if they reconnect quickly (already handled by join suppression).
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

ensureFixedAdmin().then(()=>{
  server.listen(PORT, ()=> console.log('Server running on', PORT));
}).catch(err=>{
  console.error('Failed to init admin', err);
  process.exit(1);
});
