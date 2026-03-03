export default async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!process.env.OPENAI_API_KEY) {
    return res.status(500).json({ error: "Missing OPENAI_API_KEY. Please add it to Vercel environment variables." });
  }

  const message = req.body?.message;
  if (!message) {
    return res.status(400).json({ error: "Missing 'message' field in request body" });
  }

  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are a cybersecurity AI specialized in Cortex XDR, QRadar SIEM, and Sigma rule conversion." },
          { role: "user", content: message }
        ],
        temperature: 0.2
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: data.error?.message || "OpenAI API request failed",
        details: data.error
      });
    }

    return res.status(200).json(data);

  } catch (error) {
    return res.status(500).json({ error: "Server error", details: error.message });
  }
}
