'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const apiHandler = require('./api/index.js');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = '0.0.0.0';
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.txt':  'text/plain; charset=utf-8',
  '.map':  'application/json; charset=utf-8',
};

function safeJoin(root, urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const resolved = path.normalize(path.join(root, decoded));
  if (!resolved.startsWith(root)) return null;
  return resolved;
}

function sendFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const type = MIME[ext] || 'application/octet-stream';
  res.statusCode = 200;
  res.setHeader('Content-Type', type);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  fs.createReadStream(filePath).on('error', () => {
    res.statusCode = 500;
    res.end('Server error');
  }).pipe(res);
}

function send404(res) {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('Not Found');
}

const server = http.createServer((req, res) => {
  try {
    const urlPath = (req.url || '/').split('?')[0];

    if (urlPath === '/api' || urlPath.startsWith('/api/')) {
      return apiHandler(req, res);
    }

    let target = urlPath === '/' ? '/index.html' : urlPath;
    let filePath = safeJoin(ROOT, target);
    if (!filePath) return send404(res);

    fs.stat(filePath, (err, stat) => {
      if (err || !stat) return send404(res);
      if (stat.isDirectory()) {
        const idx = path.join(filePath, 'index.html');
        return fs.stat(idx, (e2, s2) => {
          if (e2 || !s2 || !s2.isFile()) return send404(res);
          sendFile(res, idx);
        });
      }
      if (stat.isFile()) return sendFile(res, filePath);
      return send404(res);
    });
  } catch (e) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Server error: ' + (e && e.message || e));
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.warn(`Port ${PORT} in use — retrying in 2 s…`);
    setTimeout(() => {
      server.close();
      server.listen(PORT, HOST);
    }, 2000);
  } else {
    throw err;
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Private Vault server listening on http://${HOST}:${PORT}`);
  console.log(`  - Static files served from: ${ROOT}`);
  console.log(`  - API routes: /api/config, /api/watchdog, /api/health`);
});

// Also listen on 8081 so the Replit preview proxy (port 80 → 8081) works
if (PORT !== 8081) {
  const http = require('http');
  const previewServer = http.createServer(server.listeners('request')[0]);
  previewServer.listen(8081, HOST, () => {
    console.log(`  - Preview proxy also listening on http://${HOST}:8081`);
  });
  previewServer.on('error', () => {}); // silently ignore if 8081 already in use
}
