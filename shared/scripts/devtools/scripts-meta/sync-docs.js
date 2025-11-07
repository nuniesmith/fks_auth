#!/usr/bin/env node
// (Relocated) Sync HTML docs from src/docs -> src/web/react/public/docs
const fs = require('fs');
const path = require('path');
const repoRoot = path.resolve(__dirname, '..', '..');
const srcDir = path.join(repoRoot, 'src', 'docs');
const destDir = path.join(repoRoot, 'src', 'web', 'react', 'public', 'docs');
function ensureDir(p){ if(!fs.existsSync(p)) fs.mkdirSync(p,{recursive:true}); }
function copyHtmlFiles(from,to){ ensureDir(to); if(!fs.existsSync(from)) return; const entries=fs.readdirSync(from,{withFileTypes:true}); for(const e of entries){ const s=path.join(from,e.name); const d=path.join(to,e.name); if(e.isDirectory()) copyHtmlFiles(s,d); else if(e.isFile() && e.name.endsWith('.html')) fs.copyFileSync(s,d);} }
copyHtmlFiles(srcDir,destDir); process.stdout.write('[docs] sync complete.\n');
