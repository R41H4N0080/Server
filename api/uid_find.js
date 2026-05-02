const https = require('https');
const querystring = require('querystring');

// আপনার সিক্রেট কী এখানে সেট করুন অথবা Vercel Environment Variable এ রাখুন
const VALID_API_KEY = process.env.PRIVATE_API_KEY || "my_secret_key_123";

export default function handler(req, res) {
    // ১. CORS সেটিংস (যাতে অন্য ওয়েবসাইট থেকে রিকোয়েস্ট আসতে পারে)
    res.setHeader('Access-Control-Allow-Origin', '*'); 
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');

    // Preflight রিকোয়েস্ট হ্যান্ডেল করা
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // ২. Private Key যাচাই করা
    const clientApiKey = req.headers['x-api-key'];

    if (!clientApiKey || clientApiKey !== VALID_API_KEY) {
        return res.status(403).json({ 
            success: false, 
            error: 'Unauthorized: Invalid Private Key' 
        });
    }

    // ৩. বডি থেকে ডেটা সংগ্রহ করা
    let bodyData = '';
    req.on('data', chunk => { bodyData += chunk; });
    req.on('end', () => {
        const params = querystring.parse(bodyData);
        const fbLink = params.link || req.body?.link;

        if (!fbLink) {
            return res.status(400).json({ success: false, error: 'No link provided' });
        }

        // ৪. প্রক্সি লজিক শুরু
        executeProxy(fbLink, res);
    });
}

function executeProxy(fbLink, res) {
    const postData = querystring.stringify({ link: fbLink });
    
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
        },
        timeout: 20000
    };

    const proxyReq = https.request(options, (proxyRes) => {
        let data = '';
        proxyRes.on('data', chunk => { data += chunk; });
        proxyRes.on('end', () => {
            try {
                const jsonData = JSON.parse(data);
                res.status(200).json({
                    success: true,
                    data: jsonData
                });
            } catch (e) {
                res.status(500).json({ 
                    success: false, 
                    error: 'Failed to parse data from upstream'
                });
            }
        });
    });

    proxyReq.on('error', (err) => {
        res.status(500).json({ success: false, error: err.message });
    });

    proxyReq.write(postData);
    proxyReq.end();
}
