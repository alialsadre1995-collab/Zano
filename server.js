// server.js — نسخة مختومة
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
const io = new Server(server, { cors:{ origin:'*', methods:['GET','POST'] } });

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret';
const ADMIN_PASS = process.env.ADMIN_PASS || '1200@';

// ===== مخازن بالذاكرة
const messages = [];                    // تاريخ العام
const sockets  = new Map();             // socket.id -> user
const bans     = [];                    // [{targetType:'ip'|'deviceId',targetValue,reason,by,ts}]
const lastJoin = new Map();             // key(ip|device) -> ts لتفادي تكرار الانضمام 5 دقائق

// ===== مساعدات
const now = ()=> Date.now();
const fiveMin = 5*60*1000;

function ipFromHeaders(h){
  const xf = h['x-forwarded-for'];
  if (Array.isArray(xf)) return xf[0];
  if (xf) return xf.split(',')[0].trim();
  return '';
}
function ipFromReq(req){
  return ipFromHeaders(req.headers) || req.socket?.remoteAddress || '';
}
function ipFromSocket(socket){
  return ipFromHeaders(socket.handshake.headers) || socket.handshake.address || '';
}
function latinOrGuest(name){
  return /^[A-Za-z0-9_.-]{3,20}$/.test(name||'') ? name : ('Guest'+Math.floor(1000+Math.random()*9000));
}
function colorFor(name){
  const h = crypto.createHash('md5').update(name).digest('hex');
  const n = parseInt(h.slice(0,2),16);
  return ['#30c0ff','#22c55e','#f59e0b','#e879f9','#f43f5e','#38bdf8'][n%6];
}
function isBanned({ip,deviceId}){
  return bans.some(b=> (b.targetType==='ip' && b.targetValue===ip) ||
                       (b.targetType==='deviceId' && b.targetValue===deviceId));
}
function sys(text){ io.emit('system',{text}); }

function auth(req,res,next){
  const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):'';
  if(!t) return res.status(401).json({error:'no token'});
  try{ req.user=jwt.verify(t,JWT_SECRET); next(); }catch{ res.status(401).json({error:'bad token'}); }
}
function adminOnly(req,res,next){
  if(!req.user || !['admin','mod'].includes(req.user.role)) return res.status(403).json({error:'forbidden'});
  next();
}

// ===== تسجيل دخول
app.post('/api/login', (req,res)=>{
  const { username='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username);
  const userId = crypto.randomUUID();
  const token = jwt.sign({userId,username:uname,role:'user',deviceId}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role:'user' });
});

app.post('/api/login-pass', (req,res)=>{
  const { username='Admin', password='', deviceId='' } = req.body||{};
  const ip = ipFromReq(req);
  if(password!==ADMIN_PASS) return res.status(401).json({error:'wrong password'});
  if(isBanned({ip,deviceId})) return res.status(403).json({error:'banned'});
  const uname = latinOrGuest(username||'Admin');
  const userId = crypto.randomUUID();
  const token = jwt.sign({userId,username:uname,role:'admin',deviceId}, JWT_SECRET, {expiresIn:'7d'});
  res.json({ token, userId, username:uname, role:'admin' });
});

// ===== إدارة
app.get('/api/admin/bans', auth, adminOnly, (req,res)=>{
  res.json([...bans].sort((a,b)=>(b.ts||0)-(a.ts||0)));
});
app.post('/api/admin/unban', auth, adminOnly, (req,res)=>{
  const {targetType,targetValue}=req.body||{};
  if(!['ip','deviceId'].includes(targetType)||!targetValue) return res.status(400).json({error:'bad params'});
  let removed=0;
  for(let i=bans.length-1;i>=0;i--){
    if(bans[i].targetType===targetType && bans[i].targetValue===targetValue){ bans.splice(i,1); removed++; }
  }
  if(removed) sys(`تم فك الحظر عن ${targetType==='ip'?'IP':'جهاز'}: ${targetValue}`);
  res.json({ok:true,removed});
});
app.post('/api/admin/ban', auth, adminOnly, (req,res)=>{
  const {targetType,targetValue,reason=''}=req.body||{};
  if(!['ip','deviceId'].includes(targetType)||!targetValue) return res.status(400).json({error:'bad params'});
  if(!bans.find(b=> b.targetType===targetType && b.targetValue===targetValue)){
    bans.push({targetType,targetValue,reason,by:req.user.username,ts:now()});
    sys(`تم الحظر (${targetType==='ip'?'IP':'جهاز'}): ${targetValue} بواسطة ${req.user.username}`);
  }
  // اقطع الاتصال الفوري لو متصل
  for(const [sid,u] of sockets.entries()){
    if( (targetType==='ip' && u.ip===targetValue) || (targetType==='deviceId' && u.deviceId===targetValue) ){
      const s=io.sockets.sockets.get(sid);
      if(s){ s.emit('banned',{reason:'banned'}); s.disconnect(true); }
    }
  }
  res.json({ok:true});
});
app.post('/api/admin/kick', auth, adminOnly, (req,res)=>{
  const {deviceId}=req.body||{};
  if(!deviceId) return res.status(400).json({error:'bad params'});
  let done=false, name='';
  for(const [sid,u] of sockets.entries()){
    if(u.deviceId===deviceId){
      const s=io.sockets.sockets.get(sid);
      if(s){ done=true; name=u.username; s.emit('banned',{reason:'kicked'}); s.disconnect(true); }
    }
  }
  if(done) sys(`تم طرد ${name||'مستخدم'}`);
  res.json({ok:true});
});
app.get('/api/admin/user-info', auth, adminOnly, (req,res)=>{
  const { userId, username } = req.query||{};
  let found=null;
  for(const u of sockets.values()){
    if((userId && u.userId===userId) || (username && u.username===username)){ found=u; break; }
  }
  if(!found) return res.status(404).json({error:'not found'});
  res.json({ userId:found.userId, username:found.username, role:found.role, deviceId:found.deviceId, ip:found.ip, socketId:found.socketId });
});

// ===== Socket.IO
io.use((socket,next)=>{
  try{
    const token=socket.handshake.auth?.token; if(!token) return next(new Error('no token'));
    const p=jwt.verify(token,JWT_SECRET); socket.user=p;
    socket.ip = ipFromSocket(socket);
    if(isBanned({ip:socket.ip,deviceId:p.deviceId})) return next(new Error('banned'));
    next();
  }catch(e){ next(new Error('bad token')); }
});
function presence(){
  const arr=[];
  for(const [,u] of sockets){ arr.push({userId:u.userId,username:u.username,color:u.color,deviceId:u.deviceId,ip:u.ip}); }
  return arr;
}
io.on('connection',(socket)=>{
  const p=socket.user;
  const u={
    socketId:socket.id,
    userId:p.userId, username:p.username, role:p.role,
    deviceId:p.deviceId||'', ip:socket.ip, color:colorFor(p.username)
  };
  sockets.set(socket.id,u);

  // إعلان انضمام (مع منع تكرار 5 دقائق لكل IP/جهاز)
  const key = u.deviceId || ('ip:'+u.ip);
  const last = lastJoin.get(key) || 0;
  if(now()-last > fiveMin){
    sys(`${u.username} انضم إلى الغرفة`);
    lastJoin.set(key, now());
  }

  // أرسل التاريخ والحضور
  socket.emit('history', messages.slice(-200));
  io.emit('presence', presence());

  socket.on('chat:msg',(d={})=>{
    const text=(d.text||'').toString().slice(0,1500).trim();
    if(!text) return;
    if(isBanned({ip:u.ip,deviceId:u.deviceId})){ socket.emit('banned',{reason:'banned'}); socket.disconnect(); return; }
    const msg={from:u.username,userId:u.userId,color:u.color,text,ts:now()};
    messages.push(msg); if(messages.length>1500) messages.shift();
    io.emit('chat:new', msg);
  });

  socket.on('dm:send',({toId,text}={})=>{
    const t=(text||'').toString().slice(0,1500).trim(); if(!toId||!t) return;
    const target=[...sockets.values()].find(x=>x.userId===toId);
    if(!target) return;
    const payload={fromId:u.userId,toId:target.userId,text:t,ts:now()};
    socket.to(target.socketId).emit('dm:new',payload);
    socket.emit('dm:new',payload);
  });

  socket.on('disconnect',()=>{
    sockets.delete(socket.id);
    io.emit('presence', presence());
  });
});

// صفحة
app.get('/',(req,res)=>{
  res.setHeader('Content-Type','text/html; charset=utf-8');
  fs.createReadStream(path.join(__dirname,'page.html')).pipe(res);
});
app.get('/healthz',(req,res)=>res.json({ok:true}));

server.listen(PORT, ()=> console.log('listening on '+PORT));
