#!/usr/bin/env node
// (Relocated) Basic API endpoint smoke tests.
const http = require('http');
const tests=[{path:'/api/health',desc:'Health'},{path:'/api/services',desc:'Services'}];
function req(t){return new Promise((res)=>{const r=http.request({host:'localhost',port:8000,path:t.path,method:'GET'},resp=>{let d='';resp.on('data',c=>d+=c);resp.on('end',()=>res({code:resp.statusCode,body:d,desc:t.desc,path:t.path}));});r.on('error',e=>res({error:e.message,path:t.path}));r.end();});}
(async()=>{for(const t of tests){const r=await req(t); console.log(r);} })();
