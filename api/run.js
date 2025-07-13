export default async function handler(req, res) {
  try {
    const response = await fetch('https://statusdata.22web.org/auto1.php?run_all=1', {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (VercelBot)'
      }
    });

    const text = await response.text();

    if (response.ok) {
      res.status(200).send("✅ API Call Success\n\nResponse:\n" + text);
    } else {
      res.status(500).send("❌ API Call Failed\n\nResponse:\n" + text);
    }
  } catch (error) {
    res.status(500).send("❌ API Call Error\n" + error.toString());
  }
}
