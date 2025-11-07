#!/usr/bin/env node
/**
 * Sync HTML docs from src/docs -> src/web/react/public/docs
 * Keeps runtime-served docs up to date.
 */
const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const srcDir = path.join(repoRoot, 'src', 'docs');
const destDir = path.join(repoRoot, 'src', 'web', 'react', 'public', 'docs');

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function copyHtmlFiles(from, to) {
  ensureDir(to);
  if (!fs.existsSync(from)) return;
  const entries = fs.readdirSync(from, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(from, entry.name);
    const destPath = path.join(to, entry.name);
    if (entry.isDirectory()) {
      copyHtmlFiles(srcPath, destPath);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.html')) {
      // Skip copying the architecture-diagram.html if it's a small pointer file
      const stat = fs.statSync(srcPath);
      if (entry.name === 'architecture-diagram.html' && stat.size < 512) {
        process.stdout.write(`[docs] skipped pointer ${path.relative(repoRoot, srcPath)}\n`);
      } else {
        fs.copyFileSync(srcPath, destPath);
        process.stdout.write(`[docs] copied ${path.relative(repoRoot, srcPath)} -> ${path.relative(repoRoot, destPath)}\n`);
      }
    }
  }
}

copyHtmlFiles(srcDir, destDir);
process.stdout.write('[docs] sync complete.\n');
