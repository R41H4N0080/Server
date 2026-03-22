import axios from 'axios';

export default async function handler(req, res) {
  // শুধুমাত্র POST request অনুমোদিত
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  const orders = [
    { service: '123', link: 'https://instagram.com/user1', quantity: 100 },
    { service: '124', link: 'https://instagram.com/post1', quantity: 50 }
  ];

  const results = [];

  for (const order of orders) {
    try {
      const response = await axios.post(
        'https://smmgreen.com/api/v2/order',
        {
          key: 'edb640e4fc417a4dbac597f568e3f411', // সরাসরি API key
          ...order
        },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000
        }
      );

      results.push({ order, response: response.data });
    } catch (err) {
      // কোনো order fail হলে তাকে catch করা হবে
      results.push({
        order,
        error: err.response?.data || err.message || 'Unknown error'
      });
    }
  }

  // সবশেষে ফলাফল return করা হবে
  res.status(200).json({ success: true, results });
}
