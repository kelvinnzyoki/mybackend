const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

// In-memory store (you can use Vercel KV instead for production)
const codes = new Map();

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  console.log("📧 /send-code called");
  console.log("Request body:", req.body);

  const { email } = req.body;

  if (!email || !isValidEmail(email)) {
    console.log("❌ Invalid email:", email);
    return res.status(400).json({ message: "Valid email required" });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    console.log("📨 Sending email to:", email);

    const result = await resend.emails.send({
      from: "noreply@cctamcc.site",
      to: email,
      subject: "Your Verification Code",
      html: `
        <h2>Verification Code</h2>
        <p>Your verification code is: <strong style="font-size: 24px;">${code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      `
    });

    console.log("✅ Email sent:", result);

    // Store code with timestamp
    codes.set(email, {
      code: code,
      timestamp: Date.now()
    });

    res.status(200).json({ success: true, message: "Code sent" });

  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ 
      message: "Failed to send code",
      error: err.message
    });
  }
};
