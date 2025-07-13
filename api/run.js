export default async function handler(req, res) {
  try {
    const response = await fetch('https://statusdata.22web.org/auto3.php?run_all=true&token=mysecurekey123', {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
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
