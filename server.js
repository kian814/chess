require('dotenv').config();
const express=require('express'),http=require('http'),cors=require('cors'),helmet=require('helmet');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),rateLimit=require('express-rate-limit');
const Database=require('better-sqlite3');
const {Server}=require('socket.io');
const {Chess}=require('chess.js');
const crypto=require('crypto');

const PORT=Number(process.env.PORT||3000);
const SECRET=process.env.JWT_SECRET;
if(!SECRET||SECRET.length<32){console.error('Set JWT_SECRET to a random value of at least 32 characters.');process.exit(1);}
const db=new Database(process.env.DB_FILE||'shahmat.sqlite');
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, nick TEXT NOT NULL, rating INTEGER NOT NULL DEFAULT 1000, games INTEGER NOT NULL DEFAULT 0, wins INTEGER NOT NULL DEFAULT 0, losses INTEGER NOT NULL DEFAULT 0, draws INTEGER NOT NULL DEFAULT 0, peak INTEGER NOT NULL DEFAULT 1000, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS games(id TEXT PRIMARY KEY, white TEXT NOT NULL, black TEXT NOT NULL, fen TEXT NOT NULL, pgn TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, result TEXT NOT NULL DEFAULT '', tc TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS moves(id INTEGER PRIMARY KEY AUTOINCREMENT, game_id TEXT NOT NULL, ply INTEGER NOT NULL, san TEXT NOT NULL, uci TEXT NOT NULL, fen TEXT NOT NULL, by_user TEXT NOT NULL, created INTEGER NOT NULL, UNIQUE(game_id,ply));
CREATE TABLE IF NOT EXISTS chat(id INTEGER PRIMARY KEY AUTOINCREMENT, game_id TEXT NOT NULL, user_id TEXT NOT NULL, nick TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tournaments(id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tournament_players(tournament_id TEXT NOT NULL, user_id TEXT NOT NULL, joined INTEGER NOT NULL, PRIMARY KEY(tournament_id,user_id));
`);
const app=express(),server=http.createServer(app);
app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(cors({origin:(process.env.CORS_ORIGIN||'').split(',').filter(Boolean).length?(process.env.CORS_ORIGIN||'').split(','):false}));
app.use(express.json({limit:'32kb'}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));
const io=new Server(server,{cors:{origin:(process.env.CORS_ORIGIN||'').split(',').filter(Boolean).length?(process.env.CORS_ORIGIN||'').split(','):false,methods:['GET','POST']}});
const online=new Map(),queues=new Map();
const now=()=>Date.now(), id=()=>crypto.randomUUID();
const stmt=(s)=>db.prepare(s);
function tokenFor(u){return jwt.sign({sub:u.id},SECRET,{expiresIn:'7d',issuer:'shahmat'});}
function auth(req,res,next){try{const h=req.headers.authorization||'';const t=h.startsWith('Bearer ')?h.slice(7):'';const p=jwt.verify(t,SECRET,{issuer:'shahmat'});const u=stmt('SELECT id,username,nick,rating,games,wins,losses,draws,peak FROM users WHERE id=?').get(p.sub);if(!u)return res.status(401).json({error:'unauthorized'});req.user=u;next();}catch{return res.status(401).json({error:'unauthorized'});}}
function safeUser(u){return {id:u.id,username:u.username,nick:u.nick,rating:u.rating,games:u.games,wins:u.wins,losses:u.losses,draws:u.draws,peak:u.peak};}
app.get('/health',(_,r)=>r.json({ok:true,service:'ShahMat online',firebase:false}));
app.post('/api/auth/register',(req,res)=>{const {username,password,nick}=req.body||{};if(typeof username!=='string'||!/^[a-zA-Z0-9_]{3,20}$/.test(username)||typeof password!=='string'||password.length<10||password.length>72||typeof nick!=='string'||nick.trim().length<2||nick.trim().length>20)return res.status(400).json({error:'نام کاربری ۳ تا ۲۰ حرف، رمز حداقل ۱۰ کاراکتر و نام مستعار ۲ تا ۲۰ حرف باشد.'});try{const uid=id();stmt('INSERT INTO users(id,username,pass,nick,created) VALUES(?,?,?,?,?)').run(uid,username.toLowerCase(),bcrypt.hashSync(password,12),nick.trim(),now());const u=stmt('SELECT id,username,nick,rating,games,wins,losses,draws,peak FROM users WHERE id=?').get(uid);res.status(201).json({token:tokenFor(u),user:safeUser(u)});}catch{res.status(409).json({error:'این نام کاربری قبلاً گرفته شده است.'});}});
app.post('/api/auth/login',(req,res)=>{const {username,password}=req.body||{};const u=stmt('SELECT * FROM users WHERE username=?').get(String(username||'').toLowerCase());if(!u||!bcrypt.compareSync(String(password||''),u.pass))return res.status(401).json({error:'نام کاربری یا رمز عبور اشتباه است.'});const pub=safeUser(u);res.json({token:tokenFor(u),user:pub});});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
app.patch('/api/me',auth,(req,res)=>{const n=String(req.body?.nick||'').trim();if(n.length<2||n.length>20)return res.status(400).json({error:'نام مستعار باید ۲ تا ۲۰ حرف باشد.'});stmt('UPDATE users SET nick=? WHERE id=?').run(n,req.user.id);res.json({ok:true,nick:n});});
app.get('/api/leaderboard',(_,res)=>res.json(stmt('SELECT id,nick,rating,games,wins,losses,draws,peak FROM users ORDER BY rating DESC LIMIT 100').all()));
app.get('/api/tournaments',(_,res)=>res.json(stmt("SELECT t.id,t.name,t.status,t.created,u.nick AS owner,(SELECT COUNT(*) FROM tournament_players p WHERE p.tournament_id=t.id) AS players FROM tournaments t JOIN users u ON u.id=t.owner ORDER BY t.created DESC LIMIT 50").all()));
app.post('/api/tournaments',auth,(req,res)=>{const name=String(req.body?.name||'').trim();if(name.length<3||name.length>50)return res.status(400).json({error:'نام تورنمنت باید ۳ تا ۵۰ حرف باشد.'});const tid=id();stmt('INSERT INTO tournaments(id,name,owner,created) VALUES(?,?,?,?)').run(tid,name,req.user.id,now());stmt('INSERT INTO tournament_players(tournament_id,user_id,joined) VALUES(?,?,?)').run(tid,req.user.id,now());res.status(201).json({id:tid,name,status:'open'});});
app.post('/api/tournaments/:id/join',auth,(req,res)=>{const t=stmt('SELECT * FROM tournaments WHERE id=?').get(req.params.id);if(!t||t.status!=='open')return res.status(404).json({error:'تورنمنت در دسترس نیست.'});try{stmt('INSERT INTO tournament_players(tournament_id,user_id,joined) VALUES(?,?,?)').run(t.id,req.user.id,now());res.json({ok:true});}catch{res.status(409).json({error:'قبلاً عضو شده‌اید.'});}});
function getGame(gid){return stmt('SELECT * FROM games WHERE id=?').get(gid);}
function isPlayer(g,u){return g&&(g.white===u||g.black===u);}
function gamePublic(g){return {id:g.id,white:g.white,black:g.black,fen:g.fen,pgn:g.pgn,status:g.status,result:g.result,tc:g.tc};}
function elo(ra,rb,score){const ea=1/(1+Math.pow(10,(rb-ra)/400));return Math.round(ra+32*(score-ea));}
function finishGame(g,result){if(g.status!=='active')return;const whiteScore=result==='1-0'?1:result==='0-1'?0:.5;const a=stmt('SELECT * FROM users WHERE id=?').get(g.white),b=stmt('SELECT * FROM users WHERE id=?').get(g.black);if(!a||!b)return;const ar=elo(a.rating,b.rating,whiteScore),br=elo(b.rating,a.rating,1-whiteScore);const tx=db.transaction(()=>{stmt("UPDATE games SET status='ended',result=?,updated=? WHERE id=?").run(result,now(),g.id);for(const [u,nr,score] of [[a,ar,whiteScore],[b,br,1-whiteScore]]){stmt('UPDATE users SET rating=?,peak=MAX(peak,?),games=games+1,wins=wins+?,losses=losses+?,draws=draws+? WHERE id=?').run(nr,nr,score===1?1:0,score===0?1:0,score===.5?1:0,u.id);}});tx();const updated=getGame(g.id);io.to('game:'+g.id).emit('game:ended',{game:gamePublic(updated),ratings:{white:ar-a.rating,black:br-b.rating}});}
io.use((socket,next)=>{try{const p=jwt.verify(socket.handshake.auth?.token||'',SECRET,{issuer:'shahmat'});const u=stmt('SELECT id,username,nick,rating FROM users WHERE id=?').get(p.sub);if(!u)return next(new Error('unauthorized'));socket.user=u;next();}catch{next(new Error('unauthorized'));}});
io.on('connection',socket=>{
 const u=socket.user;online.set(u.id,socket.id);socket.emit('session:ready',{user:u});
 socket.on('queue:join',({tc='5+0'}={})=>{if(!['1+0','3+0','3+2','5+0','10+0','15+10'].includes(tc))return;queues.set(u.id,{user:u,tc,at:now()});socket.emit('queue:waiting',{rating:u.rating});pair(tc);});
 socket.on('queue:cancel',()=>queues.delete(u.id));
 socket.on('game:join',({gameId})=>{const g=getGame(gameId);if(!isPlayer(g,u.id))return socket.emit('error:notice',{message:'اجازه ورود به این بازی را ندارید.'});socket.join('game:'+gameId);socket.emit('game:state',{game:gamePublic(g),moves:stmt('SELECT ply,san,uci,fen,by_user FROM moves WHERE game_id=? ORDER BY ply').all(gameId)});});
 socket.on('game:move',({gameId,from,to,promotion='q'}={})=>{const g=getGame(gameId);if(!isPlayer(g,u.id)||g.status!=='active')return;const chess=new Chess(g.fen);const expected=chess.turn()==='w'?g.white:g.black;if(expected!==u.id)return;let move;try{move=chess.move({from,to,promotion});}catch{return;}if(!move)return;const ply=stmt('SELECT COUNT(*) n FROM moves WHERE game_id=?').get(gameId).n;const tx=db.transaction(()=>{stmt('INSERT INTO moves(game_id,ply,san,uci,fen,by_user,created) VALUES(?,?,?,?,?,?,?)').run(gameId,ply,move.san,from+to+(promotion||''),chess.fen(),u.id,now());stmt('UPDATE games SET fen=?,pgn=?,updated=? WHERE id=?').run(chess.fen(),chess.pgn(),now(),gameId);});tx();io.to('game:'+gameId).emit('game:moved',{gameId,move:{from,to,promotion,san:move.san,fen:chess.fen(),ply}});if(chess.isGameOver()){const result=chess.isDraw()?'1/2-1/2':chess.isCheckmate()?(chess.turn()==='w'?'0-1':'1-0'):'1/2-1/2';finishGame(getGame(gameId),result);}});
 socket.on('game:resign',({gameId}={})=>{const g=getGame(gameId);if(!isPlayer(g,u.id)||g.status!=='active')return;finishGame(g,g.white===u.id?'0-1':'1-0');});
 socket.on('game:draw:offer',({gameId}={})=>{const g=getGame(gameId);if(isPlayer(g,u.id)&&g.status==='active')io.to('game:'+gameId).emit('game:draw:offered',{by:u.id});});
 socket.on('game:draw:accept',({gameId}={})=>{const g=getGame(gameId);if(isPlayer(g,u.id)&&g.status==='active')finishGame(g,'1/2-1/2');});
 socket.on('chat:send',({gameId,body}={})=>{const g=getGame(gameId),msg=String(body||'').trim();if(!isPlayer(g,u.id)||!msg||msg.length>300)return;const created=now();stmt('INSERT INTO chat(game_id,user_id,nick,body,created) VALUES(?,?,?,?,?)').run(gameId,u.id,u.nick,msg,created);io.to('game:'+gameId).emit('chat:message',{userId:u.id,nick:u.nick,body:msg,created});});
 socket.on('disconnect',()=>{if(online.get(u.id)===socket.id)online.delete(u.id);queues.delete(u.id);});
});
function pair(tc){const list=[...queues.values()].filter(x=>x.tc===tc&&now()-x.at<45000).sort((a,b)=>a.at-b.at);if(list.length<2)return;let best=null;for(let i=0;i<list.length;i++)for(let j=i+1;j<list.length;j++){const d=Math.abs(list[i].user.rating-list[j].user.rating);if(d<=Math.min(100+Math.floor((now()-list[i].at)/5000)*50,600)&&(!best||d<best.d))best={a:list[i],b:list[j],d};}if(!best)return;queues.delete(best.a.user.id);queues.delete(best.b.user.id);const white=Math.random()<.5?best.a.user:best.b.user,black=white.id===best.a.user.id?best.b.user:best.a.user,gid=id(),tcs={'1+0':60,'3+0':180,'3+2':180,'5+0':300,'10+0':600,'15+10':900};stmt("INSERT INTO games(id,white,black,fen,status,tc,created,updated) VALUES(?,?,?,?,?,?,?,?)").run(gid,white.id,black.id,new Chess().fen(),'active',tc,now(),now());for(const player of [best.a.user,best.b.user]){const sid=online.get(player.id);if(sid)io.to(sid).emit('queue:matched',{gameId:gid,white: white.id===player.id,opponent:{nick:player.id===white.id?black.nick:white.nick,rating:player.id===white.id?black.rating:white.rating},clock:tcs[tc]});}}
server.listen(PORT,()=>console.log(`ShahMat server listening on ${PORT}`));
