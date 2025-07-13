// api/run.js

export default async function handler(req, res) {
  const targetUrl = "https://statusdata.22web.org/auto1.php?run_all=1";

  try {
    const response = await fetch(targetUrl);
    const result = await response.text();

    res.status(200).send("✅ API Call Success\n\n" + result);
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
}
