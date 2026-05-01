const https = require('https');
const querystring = require('querystring');

export default function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const params = querystring.parse(body);
            const link = params.link;

            if (!link) {
                return res.status(400).json({ error: 'No link provided' });
            }

            // Proxy logic
            const postData = querystring.stringify({ link });
            const options = {
                hostname: 'giaiphapmkt0d.com',
                path: '/proxy.php',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Origin': 'https://giaiphapmkt0d.com',
                    'Referer': 'https://giaiphapmkt0d.com/tim-uid.html'
                }
            };

            const proxyReq = https.request(options, (proxyRes) => {
                let data = '';
                proxyRes.on('data', chunk => data += chunk);
                proxyRes.on('end', () => {
                    try {
                        res.status(200).json(JSON.parse(data));
                    } catch (e) {
                        res.status(500).json({ error: 'Invalid response from upstream' });
                    }
                });
            });

            proxyReq.on('error', (err) => {
                res.status(500).json({ error: err.message });
            });

            proxyReq.write(postData);
            proxyReq.end();
        });
    } else {
        res.status(405).json({ error: 'Method not allowed' });
    }
}
