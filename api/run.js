const axios = require('axios');
const express = require('express');
const app = express();

// Enable JSON body parsing
app.use(express.json());

// ---------------- Configuration ----------------
const PORT = process.env.PORT || 3000;

// Secret key for cron security (optional)
const CRON_SECRET = 'my_cron_secret';

// Your SMM API key
const SMM_API_KEY = 'edb640e4fc417a4dbac597f568e3f411';

// SMM API base URL
const SMM_API_URL = 'https://smmgreen.com/api/v2/order';

// Orders configuration: link, service id, quantity
const orders = [
  {
    service: '123',                       // SMM service id
    link: 'https://instagram.com/user1',
    quantity: 100
  },
  {
    service: '124',
    link: 'https://instagram.com/post1',
    quantity: 50
  }
];
// ------------------------------------------------

// API route for cron-job trigger
app.all('/auto-order', async (req, res) => {
  // Check secret header for security
  const secret = req.headers['x-cron-secret'];
  if (secret !== CRON_SECRET) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const results = [];
    for (const order of orders) {
      const response = await axios.post(SMM_API_URL, {
        key: SMM_API_KEY,
        ...order
      });
      results.push({ order, response: response.data });
    }

    res.status(200).json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Auto-order API running at http://localhost:${PORT}/auto-order`);
});
