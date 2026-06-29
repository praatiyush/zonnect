require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const mongoose  = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────────────
// BREVO — sends the 4-digit OTP to the customer's email
// Get a free API key at https://app.brevo.com
// (Settings → SMTP & API → API Keys → Generate a new API key)
// Put it in your .env as BREVO_API_KEY=xkeysib-xxxxxxxx
// Sender email must be verified in Brevo (Settings → Senders)
// ─────────────────────────────────────────────────────
const BREVO_API_KEY  = process.env.BREVO_API_KEY;
const SENDER_EMAIL    = process.env.SENDER_EMAIL;   // e.g. zonnectforyou@gmail.com (must be verified in Brevo)
const SENDER_NAME     = process.env.SENDER_NAME || 'Zonnect';
const OTP_EXPIRY_MS   = 5 * 60 * 1000; // 5 minutes

async function sendOtpEmail(toEmail, otp) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': BREVO_API_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      sender: { name: SENDER_NAME, email: SENDER_EMAIL },
      to: [{ email: toEmail }],
      subject: `Your Zonnect login code: ${otp}`,
      htmlContent: `
        <div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px;">
          <h2 style="color:#1A3C5E;">Zonnect</h2>
          <p>Your one-time login code is:</p>
          <div style="font-size:32px;font-weight:800;letter-spacing:6px;color:#1A3C5E;margin:16px 0;">${otp}</div>
          <p style="color:#64748B;font-size:13px;">This code expires in 5 minutes. If you didn't request this, you can ignore this email.</p>
        </div>`,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Brevo error ${res.status}: ${body}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────
// MONGODB
// ─────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log('✓ MongoDB connected'))
  .catch(err=>console.error('✗ MongoDB error:',err));

// One record per customer — created/looked-up by email
const UserSchema = new mongoose.Schema({
  email:        { type: String, unique: true, required: true },
  name:         String,
  phone:        String, // filled in once, right after first successful login
  createdAt:    { type: Date, default: Date.now },
});
const User = mongoose.model('User', UserSchema);

// OTPs are short-lived, so a separate collection with a TTL index is cleaner
// than bolting onto User — Mongo auto-deletes expired docs for us.
const OtpSchema = new mongoose.Schema({
  email:      { type: String, required: true },
  code:       { type: String, required: true },
  attempts:   { type: Number, default: 0 },
  expiresAt:  { type: Date, required: true },
});
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Otp = mongoose.model('Otp', OtpSchema);

const OrderSchema = new mongoose.Schema({
  orderId:      String,
  email:        String,
  phone:        String,   // contact number, shown to owner for WhatsApp
  customerName: String,
  city:         String,
  address:      String,
  pincode:      String,
  service:      String,
  serviceId:    String,
  hours:        Number,
  estCost:      Number,
  details:      String,
  status:       { type:String, default:'New' },
  agentNote:    { type:String, default:'' },

  needsShipping:      { type: Boolean, default: false },
  shippingFreeByHours:{ type: Boolean, default: false },
  weightKg:           { type: Number, default: null },
  shippingCharge:     { type: Number, default: 0 },

  createdAt:    { type:Date,   default:Date.now },
});
const Order = mongoose.model('Order', OrderSchema);

// ─────────────────────────────────────────────────────
// OWNER CREDENTIALS — stored in Replit Secrets (.env)
// ─────────────────────────────────────────────────────
const OWNER_EMAIL = process.env.OWNER_EMAIL;
const OWNER_PIN   = process.env.OWNER_PIN;
const OWNER_TOKEN = process.env.OWNER_TOKEN;

function genOtp() {
  return String(Math.floor(1000 + Math.random() * 9000)); // 4 digits
}

// ─────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────

// 1. SEND OTP — generates a 4-digit code, stores it (5 min expiry), emails it
app.post('/api/send-otp', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  const code = genOtp();
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

  try {
    // Replace any previous unused OTP for this email
    await Otp.deleteMany({ email });
    await Otp.create({ email, code, expiresAt });
    await sendOtpEmail(email, code);
    res.json({ success: true });
  } catch (err) {
    console.error('send-otp error:', err.message);
    res.status(500).json({ error: 'Could not send OTP email. Try again.' });
  }
});

// 2. VERIFY OTP — checks the code, then creates/looks up the user
app.post('/api/verify-otp', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const code  = (req.body.otp || '').trim();
  if (!email || !code) return res.status(400).json({ error: 'Email and OTP required' });

  try {
    const record = await Otp.findOne({ email });
    if (!record) {
      return res.status(401).json({ error: 'OTP expired or not requested. Send a new one.' });
    }
    if (record.attempts >= 5) {
      await Otp.deleteMany({ email });
      return res.status(429).json({ error: 'Too many wrong attempts. Request a new OTP.' });
    }
    if (record.code !== code) {
      record.attempts += 1;
      await record.save();
      return res.status(401).json({ error: 'Wrong OTP. Try again.' });
    }

    // Correct — consume the OTP so it can't be reused
    await Otp.deleteMany({ email });

    // Owner email — tell frontend to show PIN modal instead of logging in directly
    if (email === (OWNER_EMAIL || '').toLowerCase()) {
      return res.json({ success: true, isOwner: true, email });
    }

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, name: email.split('@')[0] });
    }

    res.json({
      success: true,
      isOwner: false,
      email: user.email,
      name: user.name,
      phone: user.phone || '',
    });
  } catch (err) {
    console.error('verify-otp error:', err.message);
    res.status(500).json({ error: 'Could not verify OTP. Try again.' });
  }
});

// 3. SAVE PHONE NUMBER — collected once, right after first login
app.post('/api/save-phone', async (req, res) => {
  const { email, phone } = req.body;
  if (!email || !phone || phone.length !== 10) {
    return res.status(400).json({ error: 'Valid email and 10-digit phone required' });
  }
  try {
    const user = await User.findOneAndUpdate(
      { email },
      { $set: { phone } },
      { new: true, upsert: true }
    );
    res.json({ success: true, phone: user.phone });
  } catch (err) {
    res.status(500).json({ error: 'Could not save phone number' });
  }
});

// 4. OWNER LOGIN — verifies PIN on the server
app.post('/api/owner-login', (req, res) => {
  const { email, pin } = req.body;
  if ((email || '').toLowerCase() !== (OWNER_EMAIL || '').toLowerCase() || pin !== OWNER_PIN) {
    return res.status(401).json({ success: false, error: 'Wrong credentials' });
  }
  res.json({ success: true, token: OWNER_TOKEN });
});

// 5. GET ORDERS
app.get('/api/orders', async (req, res) => {
  try {
    const { email, owner } = req.query;

    if (owner === 'true') {
      const token = req.headers['x-owner-token'];
      if (!token || token !== OWNER_TOKEN) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      const orders = await Order.find().sort({ createdAt: -1 });
      return res.json({ success: true, orders });
    }

    if (!email) return res.status(400).json({ error: 'Email required' });
    const orders = await Order.find({ email }).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// 6. SAVE ORDER
app.post('/api/orders', async (req, res) => {
  try {
    const order = new Order(req.body);
    await order.save();
    res.json({ success: true, order });
  } catch (err) {
    res.status(500).json({ error: 'Could not save order' });
  }
});

// 7. UPDATE ORDER (status, agent note, weight/shipping)
app.patch('/api/orders/:id', async (req, res) => {
  const token = req.headers['x-owner-token'] || req.body._token;
  if (!token || token !== OWNER_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const updated = await Order.findOneAndUpdate(
      { $or: [{ orderId: req.params.id }, { _id: req.params.id.match(/^[0-9a-f]{24}$/) ? req.params.id : null }] },
      { $set: req.body },
      { new: true }
    );
    res.json({ success: true, order: updated });
  } catch (err) {
    res.status(500).json({ error: 'Could not update order' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Zonnect backend running on port ${PORT}`));
