const express=require("express"),fs=require("fs"),path=require("path"),webpush=require("web-push");
const app=express();app.use(express.json());app.use(express.static(path.join(__dirname,"public")));
const DB=path.join(__dirname,"data.json");
let db=fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB)): {events:[],announcements:[],subscriptions:[]};
const save=()=>fs.writeFileSync(DB,JSON.stringify(db,null,2));
const pub=process.env.VAPID_PUBLIC_KEY||"BIWpm8hQkp5baHHWghKCnKWDrV66BXkYROf4tshTITqR-BOrfiByXvKgJXNeHsEwYdc6XgwVen2S4QsnsNDmwOk", priv=process.env.VAPID_PRIVATE_KEY||"66hgvyhsi299p9yAkK0Q62Uojja6jdIb4BYoNEAyEy4";
if(pub&&priv)webpush.setVapidDetails("mailto:admin@mdpwiesiolka.pl",pub,priv);
async function pushAll(payload){if(!pub||!priv)return;for(const s of [...db.subscriptions])try{await webpush.sendNotification(s,JSON.stringify(payload))}catch(e){if([404,410].includes(e.statusCode))db.subscriptions=db.subscriptions.filter(x=>x.endpoint!==s.endpoint)}save()}
app.get("/api/data",(req,res)=>res.json({events:db.events,announcements:db.announcements}));
app.post("/api/events",(req,res)=>{let e={id:Date.now(),title:req.body.title,date:req.body.date,place:req.body.place||"Remiza OSP Wiesiółka",desc:req.body.desc||"",responses:{}};db.events.push(e);save();pushAll({title:"📅 Nowa zbiórka — MDP WIESIÓŁKA",body:`${e.title} • ${new Date(e.date).toLocaleString("pl-PL")}`});res.json(e)});
app.delete("/api/events/:id",(req,res)=>{db.events=db.events.filter(e=>e.id!=req.params.id);save();res.json({ok:true})});
app.post("/api/events/:id/response",(req,res)=>{let e=db.events.find(e=>e.id==req.params.id);if(!e)return res.status(404).end();e.responses=e.responses||{};e.responses[req.body.name]=req.body.status;save();res.json(e)});
app.post("/api/announcements",(req,res)=>{let a={id:Date.now(),title:req.body.title,text:req.body.text,createdAt:new Date().toISOString()};db.announcements.unshift(a);save();pushAll({title:"📢 MDP WIESIÓŁKA",body:a.title});res.json(a)});
app.delete("/api/announcements/:id",(req,res)=>{db.announcements=db.announcements.filter(a=>a.id!=req.params.id);save();res.json({ok:true})});
app.post("/api/push/subscribe",(req,res)=>{if(!db.subscriptions.some(s=>s.endpoint===req.body.endpoint))db.subscriptions.push(req.body);save();res.json({ok:true})});
app.get("/api/push/public-key",(req,res)=>res.json({key:pub||""}));
setInterval(async()=>{const now=Date.now();for(const e of db.events){const diff=new Date(e.date).getTime()-now;if(diff>0&&diff<61*60*1000&&!e.reminderSent){e.reminderSent=true;await pushAll({title:"🔥 Zbiórka za mniej niż godzinę",body:e.title,url:"/"});save()} }},60*1000);
app.listen(process.env.PORT||3000,()=>console.log("MDP WIESIÓŁKA działa na porcie "+(process.env.PORT||3000)));
