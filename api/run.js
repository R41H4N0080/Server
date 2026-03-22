export default function handler(req, res) {
  if (req.method === "GET") {
    // Simple test response
    res.status(200).json({
      success: true,
      message: "API test successful!",
      timestamp: new Date().toISOString()
    });
  } else {
    res.status(405).json({ success: false, message: "Method not allowed" });
  }
}
