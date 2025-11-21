// server.js — Gmail-only OTP server with detailed SMTP error reporting
// REQUIRED ENV (Render):
// OTP_API_KEY, SMTP_USER, SMTP_PASS, SMTP_HOST (smtp.gmail.com), SMTP_PORT (587), OTP_TTL_MINUTES (optional)

const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization']
}));

const PORT = process.env.PORT || 10000;
const OTP_FILE = process.env.OTP_FILE || 'otps.json';
const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || '10', 10) * 60 * 1000;

if (!process.env.OTP_API_KEY) {
  console.error('❌ OTP_API_KEY missing — set it in Render environment variables');
  process.exit(1);
}

if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
  console.error('❌ SMTP_USER or SMTP_PASS missing — set Gmail App Password and user');
  process.exit(1);
}

// Helper: OTP persistence (simple file store)
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function readOTPs() {
  try {
    if (!fs.existsSync(OTP_FILE)) return {};
    return JSON.parse(fs.readFileSync(OTP_FILE, 'utf8') || '{}');
  } catch (e) {
    console.error('readOTPs', e);
    return {};
  }
}
function saveOTP(uid, otp) {
  const s = readOTPs();
  s[uid] = { otp, expires: Date.now() + OTP_TTL };
  fs.writeFileSync(OTP_FILE, JSON.stringify(s, null, 2));
}
function verifyOTP(uid, code) {
  const s = readOTPs();
  const r = s[uid];
  if (!r) return false;
  if (Date.now() > r.expires) return false;
  return r.otp === code;
}

// API key middleware
function requireApiKey(req, res, next) {
  const key = req.get('x-api-key');
  if (!key || key !== process.env.OTP_API_KEY) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

// Create transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  // increase greeting timeout for flaky networks
  greetingTimeout: 15000
});

// Verify transport on startup and log result
transporter.verify().then(() => {
  console.log('✅ SMTP verified (Gmail). Ready to send emails.');
}).catch((err) => {
  // Crash early — logs will show reason (wrong app password, network, port blocked)
  console.error('❌ SMTP verification failed on startup:', err && (err.message || err.toString()));
  // do not exit — keep server running but log failure; requests will return informative error
});

// Routes
app.get('/', (req, res) => res.send('✅ OTP server (Gmail) running'));

app.post('/send-otp', requireApiKey, async (req, res) => {
  console.log('▶ /send-otp called; body keys:', Object.keys(req.body || {}));
  const { uid, email } = req.body || {};
  if (!uid || !email) {
    return res.status(400).json({ success: false, message: 'Missing uid or email' });
  }

  const otp = generateOTP();
  try {
    saveOTP(uid, otp);
  } catch (e) {
    console.error('Failed saving OTP:', e && e.message);
    // proceed to attempt send even if saving failed
  }

  const mailOptions = {
    from: `"ProBrush" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Your ProBrush verification code',
    html: `<div style="font-family:Arial;padding:18px;text-align:center">
            <h2>ProBrush — verification</h2>
            <p style="font-size:28px;letter-spacing:6px;font-weight:bold;margin:12px 0">${otp}</p>
            <p>Expires in ${process.env.OTP_TTL_MINUTES || 10} minutes.</p>
           </div>`
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ SMTP send success; messageId=', info && info.messageId);
    return res.json({ success: true, message: 'OTP sent' });
  } catch (err) {
    // Detailed logging for Render logs (do NOT log secrets)
    console.error('❌ SMTP send failed:', err && (err.message || err.toString()));
    if (err && err.response) {
      console.error('SMTP response:', {
        code: err.response.code || err.response.status,
        text: err.response && err.response.text
      });
    }

    // RESPOND with helpful non-secret error to the client to aid debugging
    return res.status(500).json({
      success: false,
      message: 'Failed to send OTP email',
      error: err && (err.message || String(err)),
    });
  }
});

// Optional: verify-otp endpoint your app can call
app.post('/verify-otp', requireApiKey, (req, res) => {
  const { uid, otp } = req.body || {};
  if (!uid || !otp) {
    return res.status(400).json({ success: false, message: 'Missing uid or otp' });
  }

  const ok = verifyOTP(uid, otp);
  if (!ok) {
    return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
  }

  return res.json({ success: true, message: 'OTP verified' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 OTP server listening on port ${PORT}`);
});
