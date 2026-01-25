const { getPool } = require('./_lib/db');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const pool = getPool();
    await pool.query('SELECT 1');
    res.status(200).json({ 
      status: "healthy", 
      database: "connected",
      resend: !!process.env.RESEND_API_KEY
    });
  } catch (err) {
    res.status(500).json({ 
      status: "unhealthy", 
      error: err.message 
    });
  }
};
