import fetch from "node-fetch";

export default async function handler(req, res) {
  try {
    const response = await fetch("https://official-joke-api.appspot.com/random_joke");
    const data = await response.json();

    res.status(200).json({
      success: true,
      joke: data
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
