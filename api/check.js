'use strict';

const DEF=['account-store-eight.vercel.app','.vercel.app','.replit.dev','.replit.app','.repl.co','localhost','0.0.0.0','127.0.0.1'];

function list(){
 const e=(process.env.ALLOWED_DOMAINS||'')
 .split(',').map(s=>s.trim()).filter(Boolean);
 return e.length?e:DEF;
}

function host(req){
 const h=(req&&req.headers&&(req.headers['x-forwarded-host']||req.headers.host))||'';
 let x=String(h).split(',')[0].split(':')[0].toLowerCase();
 if(x)return x;
 const o=(req&&req.headers&&(req.headers.origin||req.headers.referer))||'';
 try{return new URL(o).hostname.toLowerCase()}catch(e){}
 return '';
}

function allow(h){
 const l=list();
 if(!l.length||l.includes('*'))return 1;
 if(!h)return 0;
 return l.some(d=>{
  d=String(d).toLowerCase();
  return d[0]=='.'?(h===d.slice(1)||h.endsWith(d)):h===d;
 });
}

function check(req){
 const h=host(req);
 const ok=allow(h);
 if(!ok)return{ok:0,error:'domain_not_allowed',host:h};
 return{ok:1,domain:{host:h,allowed:1}};
}

module.exports={
 check,
 checkIntegrity:()=>({ok:true}),
 isHostAllowed:allow,
 getRequestHost:host,
 getAllowList:list,
 clearCache:()=>{}
};
