import axios from 'axios';

export default async function handler(req, res) {
  const CRON_SECRET = 'my_cron_secret';
  if (req.headers['x-cron-secret'] !== CRON_SECRET) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }

  const orders = [
    { service: '123', link: 'https://instagram.com/user1', quantity: 100 },
    { service: '124', link: 'https://instagram.com/post1', quantity: 50 }
  ];

  try {
    const results = [];
    for (const order of orders) {
      const response = await axios.post('https://smmgreen.com/api/v2/order', {
        key: 'edb640e4fc417a4dbac597f568e3f411',
        ...order
      });
      results.push({ order, response: response.data });
    }

    res.status(200).json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
