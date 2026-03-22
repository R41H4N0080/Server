import axios from 'axios';

export default async function handler(req, res) {
  const CRON_SECRET = process.env.CRON_SECRET || 'my_cron_secret';

  // Cron secret verify
  if (req.headers['x-cron-secret'] !== CRON_SECRET) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }

  // Only allow POST request
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  const orders = [
    { service: '123', link: 'https://instagram.com/user1', quantity: 100 },
    { service: '124', link: 'https://instagram.com/post1', quantity: 50 }
  ];

  try {
    const results = [];

    // Use Promise.all for concurrent requests
    await Promise.all(
      orders.map(async (order) => {
        const response = await axios.post(
          'https://smmgreen.com/api/v2/order',
          {
            key: process.env.SMMGREEN_KEY || 'edb640e4fc417a4dbac597f568e3f411',
            ...order
          },
          {
            headers: {
              'Content-Type': 'application/json'
            },
            timeout: 10000 // 10 sec timeout
          }
        );
        results.push({ order, response: response.data });
      })
    );

    res.status(200).json({ success: true, results });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ success: false, error: err.message });
  }
}
