const https = require('https');
const querystring = require('querystring');

// এখানে আপনার পছন্দমতো একটি সিক্রেট কি (Secret Key) দিন
const MY_PRIVATE_KEY = "shanto_secret_123"; 

export default function handler(req, res) {
    // CORS Headers (যাতে অন্য ওয়েবসাইট থেকে আপনার এপিআই কল করা যায়)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // OPTIONS রিকোয়েস্ট হ্যান্ডেল করা (Preflight)
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const params = querystring.parse(body);
                const link = params.link;
                const apiKey = params.api_key; // ইউজার থেকে আসা কি

                // ১. কি (Key) চেক করা
                if (!apiKey || apiKey !== MY_PRIVATE_KEY) {
                    return res.status(401).json({ 
                        success: false, 
                        error: 'Unauthorized: Invalid API Key' 
                    });
                }

                // ২. লিঙ্ক আছে কিনা চেক করা
                if (!link) {
                    return res.status(400).json({ 
                        success: false, 
                        error: 'No link provided' 
                    });
                }

                // ৩. এক্সটার্নাল এপিআই থেকে ডেটা আনা
                const postData = querystring.stringify({ link });
                const options = {
                    hostname: 'giaiphapmkt0d.com',
                    path: '/proxy.php',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(postData),
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    }
                };

                const proxyReq = https.request(options, (proxyRes) => {
                    let data = '';
                    proxyRes.on('data', chunk => data += chunk);
                    proxyRes.on('end', () => {
                        try {
                            const result = JSON.parse(data);
                            res.status(200).json({
                                success: true,
                                data: result
                            });
                        } catch (e) {
                            res.status(500).json({ success: false, error: 'Invalid response from source' });
                        }
                    });
                });

                proxyReq.on('error', (err) => {
                    res.status(500).json({ success: false, error: err.message });
                });

                proxyReq.write(postData);
                proxyReq.end();

            } catch (error) {
                res.status(500).json({ success: false, error: 'Internal Server Error' });
            }
        });
    } else {
        res.status(405).json({ success: false, error: 'Method not allowed' });
    }
}
