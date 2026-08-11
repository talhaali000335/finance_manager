require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const multer     = require('multer');
const path       = require('path');
const cloudinary = require('cloudinary').v2;
const admin      = require('firebase-admin');
const nodemailer = require('nodemailer');

const app = express();

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Check JWT secret ───────────────────────────────────────────────────────────
if (!process.env.JWT_SECRET) {
  console.error('❌  JWT_SECRET is not defined in .env file');
  process.exit(1);
}


// ── Cloudinary configuration ───────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});


// ── Multer – memory storage ────────────────────────────────────────────────────
const memoryStorage = multer.memoryStorage();

// Profile photo upload (images only, 5MB)
const upload = multer({
  storage:    memoryStorage,
  limits:     { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const isImage = /\.(jpe?g|png|gif|webp)$/i.test(file.originalname);
    isImage ? cb(null, true) : cb(new Error('Only image files (jpg, png, gif, webp) are allowed.'));
  },
});

// Document upload for applications (PDF + images, 10MB, up to 5 files)
const uploadAppDocs = multer({
  storage:    memoryStorage,
  limits:     { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /\.(pdf|jpe?g|png|gif|webp)$/i;
    allowed.test(path.extname(file.originalname))
      ? cb(null, true)
      : cb(new Error('Only PDF and image files (jpg, png, gif, webp) are allowed.'));
  },
}).array('documents', 5);

// Chat file upload (any type, 100MB)
const uploadChatFile = multer({
  storage:    memoryStorage,
  limits:     { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, _file, cb) => cb(null, true),
}).single('file');

// Receipt / document upload (PDF + images, 10MB)
const uploadReceipt = multer({
  storage:    memoryStorage,
  limits:     { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /\.(pdf|jpe?g|png)$/i;
    allowed.test(path.extname(file.originalname))
      ? cb(null, true)
      : cb(new Error('Only PDF and images allowed for receipts'));
  },
}).single('document');

// Portfolio / gallery upload (images only, 5MB, up to 10 files)
const uploadPortfolio = multer({
  storage:    memoryStorage,
  limits:     { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const isImage = /\.(jpe?g|png|gif|webp)$/i.test(file.originalname);
    isImage ? cb(null, true) : cb(new Error('Only image files allowed'));
  },
}).array('images', 10);

// ── Cloudinary upload helper ───────────────────────────────────────────────────
const uploadToCloudinary = (buffer, folder, resource_type = 'auto') =>
  new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder, resource_type },
      (error, result) => (error ? reject(error) : resolve(result))
    );
    uploadStream.end(buffer);
  });

const getMessageType = (mimetype) => {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  if (mimetype.startsWith('audio/')) return 'audio';
  return 'file';
};

// ── MongoDB Connection ─────────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/finpath';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

if (process.env.MONGODB_URI) {
  const redacted = MONGODB_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@');
  console.log('🔎 Using MONGODB_URI:', redacted);
} else {
  console.warn('⚠️  MONGODB_URI env var is NOT set – falling back to localhost');
}

let cachedConnection = null;

async function connectDB() {
  if (cachedConnection && mongoose.connection.readyState === 1) return cachedConnection;
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 10000,
    });
    cachedConnection = conn;
    console.log('✅ MongoDB connected');
    return conn;
  } catch (err) {
    cachedConnection = null;
    console.error('❌ MongoDB connection failed:', err.message);
    if (err.message.includes('bad auth'))                                       console.error('   → Username/password incorrect or needs URL-encoding');
    if (err.message.includes('ENOTFOUND') || err.message.includes('querySrv')) console.error('   → Cluster hostname wrong');
    if (err.message.includes('timed out') || err.message.includes('ETIMEDOUT'))console.error('   → IP allow-list issue – add 0.0.0.0/0 in Atlas');
    throw err;
  }
}

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(503).json({ error: 'Database unavailable. Please try again.' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  SCHEMAS & MODELS
// ══════════════════════════════════════════════════════════════════════════════

// ─── User Model ───────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  profilePictureUrl: { type: String, default: null }, // ✅ Cloudinary URL
  profilePicturePublicId: { type: String, default: null },
  fcmToken: { type: String, default: null }, // ✅ push notifications
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 12);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ─── Linked Accounts Model ─────────────────────────────────────────────────────
const linkedAccountSchema = new mongoose.Schema({
  userId:          { type: String, required: true },
  institutionName: { type: String, required: true },
  accountType:     { type: String, default: 'checking' },
  lastFour:        { type: String, default: '0000' },
  balance:         { type: Number, default: 0 },
  logoUrl:         { type: String, default: '' },
}, { timestamps: true });

const LinkedAccount = mongoose.model('LinkedAccount', linkedAccountSchema);

// ─── Monthly Snapshot Model ────────────────────────────────────────────────────
const monthlySnapshotSchema = new mongoose.Schema({
  userId:   { type: String, required: true },
  monthKey: { type: String, required: true },
  income:   { type: Number, default: 0 },
  expenses: { type: Number, default: 0 },
}, { timestamps: true });
monthlySnapshotSchema.index({ userId: 1, monthKey: 1 }, { unique: true });
const MonthlySnapshot = mongoose.model('MonthlySnapshot', monthlySnapshotSchema);

// ─── Weekly Snapshot Model ─────────────────────────────────────────────────────
const weeklySnapshotSchema = new mongoose.Schema({
  userId:   { type: String, required: true },
  weekKey:  { type: String, required: true },
  income:   { type: Number, default: 0 },
  expenses: { type: Number, default: 0 },
}, { timestamps: true });
weeklySnapshotSchema.index({ userId: 1, weekKey: 1 }, { unique: true });
const WeeklySnapshot = mongoose.model('WeeklySnapshot', weeklySnapshotSchema);

function getIsoWeekKey(date = new Date()) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`;
}

// ─── Profile Model ─────────────────────────────────────────────────────────────
const profileSchema = new mongoose.Schema({
  userId:         { type: String, required: true, unique: true },
  profilePicture: { type: String, default: '' },
  profilePicturePublicId: { type: String, default: '' }, // ✅ Cloudinary public_id
  customIncomes:  { type: [Object], default: [] },
  customExpenses: { type: [Object], default: [] },
  age: Number,
  employment: String,
  country: String,
  city: String,
  primarySalary: Number,
  sideIncome: Number,
  consistency: String,
  cashSavings: Number,
  investments: Number,
  propertyValue: Number,
  totalLoans: Number,
  creditCardDebt: Number,
  monthlyEMI: Number,
  rent: Number,
  food: Number,
  transport: Number,
  entertainment: Number,
  completedSteps: { type: Number, default: 0, max: 5 },
  completedTasks: [{ type: String }],
  // ✅ Receipt documents (uploaded to Cloudinary)
  receiptDocuments: [{
    originalName: String,
    url:          String,
    publicId:     String,
    uploadedAt:   { type: Date, default: Date.now },
  }],
}, { timestamps: true });

const Profile = mongoose.model('Profile', profileSchema);

// ─── Goal Model ────────────────────────────────────────────────────────────────
const goalSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  goalType: {
    type: String,
    enum: ['home', 'car', 'education', 'custom', 'vacation', 'business', 'savings', 'emergency_fund'],
    required: true,
  },
  name:                { type: String, default: '' },
  targetAmount:        { type: Number, required: true },
  targetDate:          { type: Date,   required: true },
  priority:            { type: Number, min: 1, max: 5, default: 3 },
  monthlyContribution: { type: Number, default: 0 },
  existingSavings:     { type: Number, default: 0 },
  autoTransfer:        { type: Boolean, default: false },
  riskTolerance:       { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'conservative' },
  // ✅ Goal-related documents (uploaded to Cloudinary)
  documents: [{
    originalName: String,
    url:          String,
    publicId:     String,
    uploadedAt:   { type: Date, default: Date.now },
  }],
}, { timestamps: true });

const Goal = mongoose.model('Goal', goalSchema);

// ─── Subscription Model ────────────────────────────────────────────────────────
const subscriptionSchema = new mongoose.Schema({
  userId:            { type: String, required: true, unique: true },
  plan:              { type: String, enum: ['monthly', 'yearly', 'none'], default: 'none' },
  active:            { type: Boolean, default: false },
  startDate:         { type: Date },
  endDate:           { type: Date },
  cancelAtPeriodEnd: { type: Boolean, default: false },
}, { timestamps: true });

const Subscription = mongoose.model('Subscription', subscriptionSchema);

// ─── Intent Model ──────────────────────────────────────────────────────────────
const intentSchema = new mongoose.Schema({
  userId:        { type: String, required: true },
  amount:        { type: Number, required: true },
  category:      { type: String, required: true },
  place:         { type: String, default: '' },
  note:          { type: String, default: '' },
  paymentMethod: { type: String, default: '' },
  // ✅ Receipt image (uploaded to Cloudinary)
  receiptUrl:      { type: String, default: null },
  receiptPublicId: { type: String, default: null },
}, { timestamps: true });

const Intent = mongoose.model('Intent', intentSchema);

// ─── Conversation Model ────────────────────────────────────────────────────────
const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  lastMessage:  { type: mongoose.Schema.Types.ObjectId, ref: 'Message', default: null },
}, { timestamps: true });
conversationSchema.index({ participants: 1 });
const Conversation = mongoose.model('Conversation', conversationSchema);

// ─── Message Model ─────────────────────────────────────────────────────────────
const messageSchema = new mongoose.Schema({
  conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  sender:       { type: mongoose.Schema.Types.ObjectId, ref: 'User',         required: true },
  messageType:  { type: String, enum: ['text', 'image', 'video', 'audio', 'file', 'location'], default: 'text' },
  content:      { type: String, default: '' },
  fileName:     { type: String, default: null },
  fileSize:     { type: Number, default: null },
  latitude:     { type: Number, default: null },
  longitude:    { type: Number, default: null },
  locationName: { type: String, default: null },
  readBy:       [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });
messageSchema.index({ conversation: 1, createdAt: -1 });
const Message = mongoose.model('Message', messageSchema);

// ══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════════════════

const isParticipant = (conversation, userId) =>
  conversation.participants.map(String).includes(String(userId));

// ── JWT Helper ─────────────────────────────────────────────────────────────────
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

// ── Auth Middleware ────────────────────────────────────────────────────────────
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
};



// ══════════════════════════════════════════════════════════════════════════════
//  AI PROVIDER HELPER (Groq primary → Gemini fallback)
// ══════════════════════════════════════════════════════════════════════════════

const GROQ_KEY   = process.env.GROQ_API_KEY;
const GEMINI_KEY = process.env.GEMINI_API_KEY;

function buildProviderChain() {
  const providers = [];
  if (GROQ_KEY) {
    providers.push(
      { type: 'groq', model: 'llama-3.3-70b-versatile' },
      { type: 'groq', model: 'llama-3.1-8b-instant' }
    );
  }
  if (GEMINI_KEY) {
    providers.push(
      { type: 'gemini', model: 'gemini-2.5-flash' },
      { type: 'gemini', model: 'gemini-2.5-flash-lite' },
      { type: 'gemini', model: 'gemini-3-flash-preview' }
    );
  }
  return providers;
}

async function callAI(prompt, chatMessages = null, wantsJson = false) {
  const providers = buildProviderChain();
  if (providers.length === 0)
    throw new Error('Server configuration error: no AI provider keys set (GROQ_API_KEY or GEMINI_API_KEY)');

  let lastError = null;

  for (const provider of providers) {
    try {
      console.log(`🔄 Trying provider: ${provider.type}/${provider.model}`);
      let text = null;

      if (provider.type === 'groq') {
        const messages = chatMessages && chatMessages.length
          ? chatMessages
          : [{ role: 'user', content: prompt }];

        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_KEY}` },
          body: JSON.stringify({
            model: provider.model,
            messages,
            temperature: 0.7,
            ...(wantsJson ? { response_format: { type: 'json_object' } } : {}),
          }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || `Groq returned status ${response.status}`);
        text = data.choices?.[0]?.message?.content;
      }

      if (provider.type === 'gemini') {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${provider.model}:generateContent?key=${GEMINI_KEY}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ text: prompt }] }],
              ...(wantsJson ? { generationConfig: { responseMimeType: 'application/json' } } : {}),
            }),
          }
        );
        const data = await response.json();
        if (!response.ok) throw new Error(data.error?.message || `Gemini returned status ${response.status}`);
        text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      }

      if (!text) throw new Error(`No content returned from ${provider.type}/${provider.model}`);

      console.log(`✅ Success with ${provider.type}/${provider.model}`);
      return { text, providerUsed: `${provider.type}/${provider.model}` };

    } catch (err) {
      console.warn(`⚠️ Provider ${provider.type}/${provider.model} failed: ${err.message}`);
      lastError = err;
    }
  }

  throw lastError || new Error('All AI providers are currently unavailable.');
}

function extractJson(text) {
  const cleaned = text.replace(/```json|```/g, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const start = cleaned.indexOf('{');
    const end   = cleaned.lastIndexOf('}');
    if (start !== -1 && end !== -1 && end > start) return JSON.parse(cleaned.slice(start, end + 1));
    throw new Error('No valid JSON found in AI response');
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/signup', upload.single('profilePhoto'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email, and password are required.' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ error: 'Email already registered.' });

    let profilePictureUrl      = null;
    let profilePicturePublicId = null;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer, 'finpath/profile_photos', 'image');
      profilePictureUrl      = result.secure_url;
      profilePicturePublicId = result.public_id;
    }

    const user = new User({ name, email, password, profilePictureUrl, profilePicturePublicId });
    await user.save();
    const token = generateToken(user._id);
    res.status(201).json({
      message: 'User created successfully.',
      token,
      user: { id: user._id, name: user.name, email: user.email, profilePictureUrl: user.profilePictureUrl },
    });
  } catch (err) {
    console.error('SIGNUP ERROR:', err);
    if (err.code === 11000) return res.status(409).json({ error: 'Email already registered.' });
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = generateToken(user._id);
    res.json({
      message: 'Login successful.',
      token,
      user: { id: user._id, name: user.name, email: user.email, profilePictureUrl: user.profilePictureUrl },
    });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Update profile (with photo upload) ────────────────────────────────────────
app.put('/api/auth/profile', authenticate, upload.single('profilePhoto'), async (req, res) => {
  try {
    const { name } = req.body;
    const update = {};
    if (name) update.name = name;

    if (req.file) {
      // Delete old Cloudinary image if exists
      const existing = await User.findById(req.userId).select('profilePicturePublicId');
      if (existing?.profilePicturePublicId) {
        await cloudinary.uploader.destroy(existing.profilePicturePublicId).catch(() => {});
      }
      const result = await uploadToCloudinary(req.file.buffer, 'finpath/profile_photos', 'image');
      update.profilePictureUrl      = result.secure_url;
      update.profilePicturePublicId = result.public_id;
    }

    if (Object.keys(update).length === 0)
      return res.status(400).json({ error: 'No fields to update.' });

    const user = await User.findByIdAndUpdate(req.userId, update, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ message: 'Profile updated.', user });
  } catch (err) {
    console.error('UPDATE PROFILE ERROR:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Password reset ─────────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(200).json({ message: 'If that email is registered, a reset link has been sent.' });

    const token = jwt.sign({ userId: user._id, purpose: 'password_reset' }, JWT_SECRET, { expiresIn: '15m' });

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'FinPath – Password Reset',
          html: `
            <p>Hello,</p>
            <p>We received a request to reset your FinPath password.</p>
            <p>Paste this token in the app:</p>
            <p style="font-size:18px;background:#f0f0f0;padding:10px;border-radius:4px;word-break:break-all;">${token}</p>
            <p>This token will expire in <strong>15 minutes</strong>.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
            <p>– The FinPath Team</p>
          `,
        });
        console.log(`📧 Password reset email sent to ${email}`);
      } catch (emailErr) {
        console.error('Failed to send email:', emailErr.message);
        console.log(`🔑 Password reset token for ${email}: ${token}`);
      }
    } else {
      console.log(`🔑 Password reset token for ${email}: ${token}`);
    }

    res.status(200).json({ message: 'If that email is registered, a reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      return res.status(400).json({ error: 'Token and new password are required.' });
    if (newPassword.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token.' });
    }

    if (decoded.purpose !== 'password_reset')
      return res.status(401).json({ error: 'Invalid token purpose.' });

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    user.password = newPassword; // pre-save hook will hash it
    await user.save();

    console.log(`🔒 Password reset successful for ${user.email}`);
    res.status(200).json({ message: 'Password has been reset successfully. You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  GOAL ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/goals', authenticate, async (req, res) => {
  try {
    const goalData = { ...req.body, userId: req.userId };
    const goal = await Goal.create(goalData);
    res.status(201).json(goal);
  } catch (err) {
    console.error('GOAL CREATE ERROR:', err);
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/goals/:id', authenticate, async (req, res) => {
  try {
    const goal = await Goal.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { $set: req.body },
      { new: true, runValidators: true }
    );
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    res.json(goal);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/goals', authenticate, async (req, res) => {
  try {
    const goals = await Goal.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(goals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/goals/:id', authenticate, async (req, res) => {
  try {
    const goal = await Goal.findOne({ _id: req.params.id, userId: req.userId });
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    res.json(goal);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/goals/:id', authenticate, async (req, res) => {
  try {
    const goal = await Goal.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!goal) return res.status(404).json({ error: 'Goal not found' });
    res.json({ message: 'Goal deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Upload document to a goal
app.post('/api/goals/:id/documents', authenticate, (req, res) => {
  uploadAppDocs(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const goal = await Goal.findOne({ _id: req.params.id, userId: req.userId });
      if (!goal) return res.status(404).json({ error: 'Goal not found' });
      if (!req.files || req.files.length === 0)
        return res.status(400).json({ error: 'At least one file is required.' });

      const docs = [];
      for (const file of req.files) {
        const result = await uploadToCloudinary(file.buffer, 'finpath/goal_documents');
        docs.push({ originalName: file.originalname, url: result.secure_url, publicId: result.public_id });
      }

      goal.documents.push(...docs);
      await goal.save();
      res.status(201).json({ message: 'Documents uploaded.', goal });
    } catch (error) {
      console.error('Goal document upload error:', error);
      res.status(500).json({ error: 'Server error.' });
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  PROFILE ROUTES
// ══════════════════════════════════════════════════════════════════════════════

const authorizeProfileAccess = (req, res, next) => {
  if (req.params.userId !== req.userId)
    return res.status(403).json({ error: 'You can only access your own profile.' });
  next();
};

app.get('/api/profile/:userId', authenticate, authorizeProfileAccess, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.params.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found.' });
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/profile/:userId', authenticate, authorizeProfileAccess, async (req, res) => {
  try {
    const updates = req.body;
    delete updates.userId;
    const profile = await Profile.findOneAndUpdate(
      { userId: req.params.userId },
      { $set: updates },
      { new: true, upsert: true, runValidators: true }
    );
    res.json(profile);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/profile/:userId', authenticate, authorizeProfileAccess, async (req, res) => {
  try {
    const profileData = { ...req.body, userId: req.params.userId };
    const profile = await Profile.findOneAndReplace(
      { userId: req.params.userId },
      profileData,
      { upsert: true, new: true }
    );
    res.json(profile);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ✅ Upload profile picture via Cloudinary
app.post('/api/profile/:userId/picture', authenticate, authorizeProfileAccess, upload.single('profilePhoto'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

    // Delete old image from Cloudinary
    const existing = await Profile.findOne({ userId: req.params.userId }).select('profilePicturePublicId');
    if (existing?.profilePicturePublicId) {
      await cloudinary.uploader.destroy(existing.profilePicturePublicId).catch(() => {});
    }

    const result = await uploadToCloudinary(req.file.buffer, 'finpath/profile_photos', 'image');
    const profile = await Profile.findOneAndUpdate(
      { userId: req.params.userId },
      { profilePicture: result.secure_url, profilePicturePublicId: result.public_id },
      { new: true, upsert: true }
    );
    res.json({ message: 'Profile picture updated.', profilePicture: profile.profilePicture });
  } catch (err) {
    console.error('Profile picture upload error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ✅ Upload receipt documents to profile
app.post('/api/profile/:userId/receipts', authenticate, authorizeProfileAccess, (req, res) => {
  uploadAppDocs(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      if (!req.files || req.files.length === 0)
        return res.status(400).json({ error: 'At least one file is required.' });

      const docs = [];
      for (const file of req.files) {
        const result = await uploadToCloudinary(file.buffer, 'finpath/receipts');
        docs.push({ originalName: file.originalname, url: result.secure_url, publicId: result.public_id });
      }

      const profile = await Profile.findOneAndUpdate(
        { userId: req.params.userId },
        { $push: { receiptDocuments: { $each: docs } } },
        { new: true, upsert: true }
      );
      res.status(201).json({ message: 'Receipts uploaded.', receiptDocuments: profile.receiptDocuments });
    } catch (error) {
      console.error('Receipt upload error:', error);
      res.status(500).json({ error: 'Server error.' });
    }
  });
});

// ✅ Delete a receipt document from profile
app.delete('/api/profile/:userId/receipts/:docId', authenticate, authorizeProfileAccess, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.params.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found.' });

    const doc = profile.receiptDocuments.id(req.params.docId);
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    // Remove from Cloudinary
    if (doc.publicId) await cloudinary.uploader.destroy(doc.publicId).catch(() => {});

    await Profile.findOneAndUpdate(
      { userId: req.params.userId },
      { $pull: { receiptDocuments: { _id: req.params.docId } } }
    );
    res.json({ message: 'Receipt document removed.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
//  CLOUDINARY SIGNATURE (for direct client-side uploads)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/cloudinary/signature', authenticate, (req, res) => {
  try {
    const folder    = req.query.folder || 'finpath/chat_files';
    const timestamp = Math.round(Date.now() / 1000);
    const signature = cloudinary.utils.api_sign_request(
      { timestamp, folder },
      process.env.CLOUDINARY_API_SECRET
    );
    res.json({
      signature,
      timestamp,
      apiKey:    process.env.CLOUDINARY_API_KEY,
      cloudName: process.env.CLOUDINARY_CLOUD_NAME,
      folder,
    });
  } catch (err) {
    console.error('Cloudinary signature error:', err);
    res.status(500).json({ error: 'Could not create upload signature' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CHAT ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/conversations', authenticate, async (req, res) => {
  try {
    const userId = req.userId;
    const conversations = await Conversation.find({ participants: userId })
      .populate('participants', 'name profilePictureUrl')
      .populate('lastMessage')
      .sort({ updatedAt: -1 });

    const enriched = await Promise.all(
      conversations.map(async (conv) => {
        const unreadCount = await Message.countDocuments({
          conversation: conv._id,
          readBy: { $ne: userId },
          sender: { $ne: userId },
        });
        const otherParticipant = conv.participants.find((p) => p._id.toString() !== userId.toString());
        return { _id: conv._id, otherUser: otherParticipant, lastMessage: conv.lastMessage, unreadCount, updatedAt: conv.updatedAt };
      })
    );
    res.json({ conversations: enriched });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/conversations', authenticate, async (req, res) => {
  try {
    const { otherUserId } = req.body;
    if (!otherUserId) return res.status(400).json({ error: 'otherUserId required' });
    const userId = req.userId;
    if (userId === otherUserId)
      return res.status(400).json({ error: 'Cannot start conversation with yourself' });

    const otherUser = await User.findById(otherUserId);
    if (!otherUser) return res.status(404).json({ error: 'User not found' });

    let conversation = await Conversation.findOne({ participants: { $all: [userId, otherUserId] } })
      .populate('participants', 'name profilePictureUrl');
    if (conversation) return res.json({ conversation });

    conversation = await Conversation.create({ participants: [userId, otherUserId] });
    await conversation.populate('participants', 'name profilePictureUrl');
    res.status(201).json({ conversation });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/conversations/:id/messages', authenticate, async (req, res) => {
  try {
    const conversationId = req.params.id;
    const { page = 1, limit = 30, after } = req.query;
    const filter = { conversation: conversationId };
    if (after) filter.createdAt = { $gt: new Date(after) };
    const skip     = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
    const messages = await Message.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('sender', 'name profilePictureUrl');
    const total = await Message.countDocuments({ conversation: conversationId });
    res.json({
      messages:    messages.reverse(),
      currentPage: parseInt(page),
      totalPages:  Math.ceil(total / parseInt(limit)),
      totalCount:  total,
      hasMore:     skip + messages.length < total,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/conversations/:id/messages', authenticate, (req, res) => {
  uploadChatFile(req, res, async (err) => {
    if (err) {
      if (err instanceof multer.MulterError)
        return res.status(400).json({ error: `Upload error: ${err.message}` });
      return res.status(400).json({ error: err.message });
    }
    try {
      const conversation = await Conversation.findById(req.params.id);
      if (!conversation) return res.status(404).json({ error: 'Conversation not found' });
      if (!isParticipant(conversation, req.userId))
        return res.status(403).json({ error: 'Not a participant' });

      let messageData = { conversation: conversation._id, sender: req.userId, readBy: [req.userId] };

      if (req.body.text && !req.file) {
        messageData.messageType = 'text';
        messageData.content     = req.body.text;
      } else if (req.file) {
        const result = await uploadToCloudinary(req.file.buffer, 'finpath/chat_files', 'auto');
        messageData.messageType = getMessageType(req.file.mimetype);
        messageData.content     = result.secure_url;
        messageData.fileName    = req.file.originalname;
        messageData.fileSize    = req.file.size;
      } else {
        return res.status(400).json({ error: 'Text or file is required' });
      }

      const message = await Message.create(messageData);
      await message.populate('sender', 'name profilePictureUrl');
      conversation.lastMessage = message._id;
      await conversation.save();

      const recipients = conversation.participants.filter((p) => p.toString() !== req.userId.toString());
      const sender     = await User.findById(req.userId).select('name');
      const senderName = sender?.name || 'Someone';
      const notifBody  = req.body.text ? req.body.text : '📎 Sent an attachment';

      await Promise.allSettled(
        recipients.map((recipientId) =>
          sendPushNotification(recipientId, senderName, notifBody, { type: 'new_message', conversationId: conversation._id.toString() })
        )
      );

      res.status(201).json({ message });
    } catch (error) {
      console.error('Send message error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });
});

app.post('/api/conversations/:id/messages/attachment', authenticate, async (req, res) => {
  try {
    const conversation = await Conversation.findById(req.params.id);
    if (!conversation) return res.status(404).json({ error: 'Conversation not found' });
    if (!isParticipant(conversation, req.userId))
      return res.status(403).json({ error: 'Not a participant' });

    const { url, fileName, fileSize, resourceType } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required' });

    let messageType = 'file';
    if (resourceType === 'image') messageType = 'image';
    else if (resourceType === 'audio') messageType = 'audio';
    else if (resourceType === 'video') messageType = 'video';

    const message = await Message.create({
      conversation: conversation._id, sender: req.userId, readBy: [req.userId],
      messageType, content: url, fileName: fileName || null, fileSize: fileSize || null,
    });
    await message.populate('sender', 'name profilePictureUrl');
    conversation.lastMessage = message._id;
    await conversation.save();
    res.status(201).json({ message });
  } catch (error) {
    console.error('Attachment message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/conversations/:id/messages/location', authenticate, async (req, res) => {
  try {
    const conversation = await Conversation.findById(req.params.id);
    if (!conversation) return res.status(404).json({ error: 'Conversation not found' });
    if (!isParticipant(conversation, req.userId))
      return res.status(403).json({ error: 'Not a participant' });

    const { latitude, longitude, locationName } = req.body;
    if (latitude == null || longitude == null)
      return res.status(400).json({ error: 'latitude and longitude are required' });

    const lat = Number(latitude);
    const lng = Number(longitude);
    if (Number.isNaN(lat) || Number.isNaN(lng))
      return res.status(400).json({ error: 'latitude and longitude must be numbers' });
    if (lat < -90 || lat > 90 || lng < -180 || lng > 180)
      return res.status(400).json({ error: 'latitude/longitude out of range' });

    const message = await Message.create({
      conversation: conversation._id, sender: req.userId, readBy: [req.userId],
      messageType: 'location', content: locationName || `${lat}, ${lng}`,
      latitude: lat, longitude: lng, locationName: locationName || null,
    });
    await message.populate('sender', 'name profilePictureUrl');
    conversation.lastMessage = message._id;
    await conversation.save();
    res.status(201).json({ message });
  } catch (error) {
    console.error('Location message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/conversations/:id/read', authenticate, async (req, res) => {
  try {
    await Message.updateMany(
      { conversation: req.params.id, readBy: { $ne: req.userId } },
      { $addToSet: { readBy: req.userId } }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  SUBSCRIPTION ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/subscription', authenticate, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ userId: req.userId });
    res.json(sub || { plan: 'none', active: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/subscription', authenticate, async (req, res) => {
  try {
    const { plan } = req.body;
    if (!['monthly', 'yearly'].includes(plan))
      return res.status(400).json({ error: 'Invalid plan' });

    const startDate = new Date();
    const endDate   = new Date();
    plan === 'yearly' ? endDate.setFullYear(endDate.getFullYear() + 1) : endDate.setMonth(endDate.getMonth() + 1);

    const sub = await Subscription.findOneAndUpdate(
      { userId: req.userId },
      { plan, active: true, startDate, endDate, cancelAtPeriodEnd: false },
      { new: true, upsert: true }
    );

    await sendPushNotification(req.userId, 'Subscription Active 🎉', `Your ${plan} plan is now active.`, { type: 'subscription' });

    res.json(sub);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/subscription', authenticate, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ userId: req.userId });
    if (!sub) return res.status(404).json({ error: 'No subscription found' });
    sub.cancelAtPeriodEnd = true;
    await sub.save();
    res.json({ message: 'Subscription will be cancelled at the end of the current period.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  LINKED ACCOUNTS ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/linked-accounts', authenticate, async (req, res) => {
  try {
    const accounts = await LinkedAccount.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(accounts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/linked-accounts', authenticate, async (req, res) => {
  try {
    const { institutionName, accountType, lastFour, balance, logoUrl } = req.body;
    if (!institutionName) return res.status(400).json({ error: 'Institution name is required.' });
    const account = await LinkedAccount.create({
      userId: req.userId, institutionName,
      accountType: accountType || 'checking',
      lastFour: lastFour || '0000',
      balance: balance || 0,
      logoUrl: logoUrl || '',
    });
    res.status(201).json(account);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/linked-accounts/:id', authenticate, async (req, res) => {
  try {
    const account = await LinkedAccount.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!account) return res.status(404).json({ error: 'Account not found' });
    res.json({ message: 'Account removed' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  AI-POWERED ROUTES (unchanged from original)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/financial-insight', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    const prompt = `
You are a compassionate financial coach. Based on the user's real data, write a short, uplifting "intentions" summary (2-3 sentences) that highlights what they're doing well and offers a gentle nudge. Use the data to be specific. Output ONLY a JSON object with this exact structure, with no extra commentary before or after it:
{
  "title": "short, one-line title like 'Balanced & Intentional'",
  "summary": "the 2-3 sentence summary",
  "focusAreas": [
    {"label": "Pause", "color": "yellow", "percent": number between 0-100},
    {"label": "Nourish", "color": "blue", "percent": number},
    {"label": "Sustain", "color": "purple", "percent": number}
  ]
}
The focusAreas represent how the user's budget breaks down (e.g., Pause = discretionary, Nourish = essentials, Sustain = savings). Percentages should add up to 100.
Never invent numbers – use the real data.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}
`.trim();

    let analysis;
    try {
      const { text } = await callAI(prompt, null, true);
      analysis = extractJson(text);
      if (!analysis.title || !analysis.summary || !analysis.focusAreas)
        throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for financial insight:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate financial insight. Please try again later.' });
    }
    res.json(analysis);
  } catch (err) {
    console.error('FINANCIAL INSIGHT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/action-plan', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });

    const now          = new Date();
    const totalMonths  = 24;
    const monthsElapsed = Math.min(
      Math.floor((now - new Date(profile?.createdAt || now)) / (30 * 24 * 3600 * 1000)),
      totalMonths
    );
    const progress     = monthsElapsed / totalMonths;
    const completedSet = new Set(profile?.completedTasks ?? []);
    const currentMonthTasks = [];
    const primaryGoal  = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    if (primaryGoal) {
      const goalName     = primaryGoal.name || primaryGoal.goalType;
      const neededMonthly = Math.ceil((primaryGoal.targetAmount - (primaryGoal.existingSavings || 0)) / totalMonths);

      const saveTaskTitle = `Save \$${neededMonthly} to ${goalName}`;
      currentMonthTasks.push({ title: saveTaskTitle, description: `Keeps you aligned for your ${goalName} target.`, hasInfo: true, spending: null, completed: completedSet.has(saveTaskTitle) });

      const moveTaskTitle = `Move \$${Math.ceil(neededMonthly * 0.4)} to Business Seed Account`;
      currentMonthTasks.push({ title: moveTaskTitle, description: 'Scheduled automated transfer.', hasInfo: false, spending: null, completed: completedSet.has(moveTaskTitle) });

      const spendingLimit = primaryGoal.monthlyContribution > 0
        ? primaryGoal.monthlyContribution
        : Math.ceil(((profile?.primarySalary || 0) + (profile?.sideIncome || 0)) * 0.3);
      const spendTaskTitle = `Review discretionary spending (limit to \$${spendingLimit})`;
      currentMonthTasks.push({ title: spendTaskTitle, description: '', hasInfo: false, spending: { spent: Math.ceil(spendingLimit * 0.85), limit: spendingLimit }, completed: completedSet.has(spendTaskTitle) });
    }

    res.json({ currentPhase: `Month ${monthsElapsed + 1} of ${totalMonths}`, progress, status: progress >= 0.8 ? 'On Schedule' : 'Behind', tasks: currentMonthTasks });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/action-plan/task-done', authenticate, async (req, res) => {
  try {
    const { taskTitle } = req.body;
    if (!taskTitle) return res.status(400).json({ error: 'Missing taskTitle' });
    await Profile.findOneAndUpdate({ userId: req.userId }, { $addToSet: { completedTasks: taskTitle } }, { new: true, upsert: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tax-analysis', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income      = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const state       = profile.state || 'NY';
    const filingStatus = profile.filingStatus || 'Single';
    const currentDate  = new Date().toISOString().split('T')[0];

    const prompt = `You are a tax advisor. Based on the following user data, provide a tax analysis in JSON format.
User data:
- Annual income: $${income}
- State: ${state}
- Filing status: ${filingStatus}
- Current date: ${currentDate}

Output must be a valid JSON object with these exact keys, and nothing else:
{
  "annualTax": number,
  "effectiveRate": number,
  "marginalRate": number,
  "breakdown": { "federal": number, "state": number, "fica": number, "local": number },
  "tips": [
    {"icon": "account_balance", "title": "string", "description": "string"},
    {"icon": "health_and_safety", "title": "string", "description": "string"}
  ]
}
Return ONLY the JSON, no additional text.`.trim();

    let analysis;
    try {
      const { text } = await callAI(prompt, null, true);
      analysis = extractJson(text);
      if (analysis.annualTax == null || analysis.effectiveRate == null)
        throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for tax analysis:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate tax analysis. Please try again later.' });
    }
    res.json(analysis);
  } catch (err) {
    console.error('TAX ANALYSIS ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/cash-flow', authenticate, async (req, res) => {
  try {
    let profile = await Profile.findOne({ userId: req.userId });
    if (!profile) profile = await Profile.create({ userId: req.userId });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const netBalance = income - expenses;

    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    await MonthlySnapshot.findOneAndUpdate(
      { userId: req.userId, monthKey: currentMonthKey },
      { $setOnInsert: { income, expenses } },
      { upsert: true, new: true }
    );

    const currentWeekKey = getIsoWeekKey(now);
    await WeeklySnapshot.findOneAndUpdate(
      { userId: req.userId, weekKey: currentWeekKey },
      { $setOnInsert: { income: Math.round(income / 4), expenses: Math.round(expenses / 4) } },
      { upsert: true, new: true }
    );

    const snapshots = await MonthlySnapshot.find({ userId: req.userId }).sort({ monthKey: -1 }).limit(6);
    const trend = snapshots.reverse().map(s => ({ month: s.monthKey, income: s.income, expense: s.expenses }));

    const breakdown = [
      { category: 'Salary',        icon: 'work',           amount: profile.primarySalary || 0,  type: 'income',  changePercent: 0  },
      { category: 'Side Income',   icon: 'work',           amount: profile.sideIncome || 0,      type: 'income',  changePercent: 0  },
      { category: 'Rent',          icon: 'home',           amount: profile.rent || 0,            type: 'expense', changePercent: 0  },
      { category: 'Food & Dining', icon: 'restaurant',     amount: profile.food || 0,            type: 'expense', changePercent: 12 },
      { category: 'Transport',     icon: 'directions_car', amount: profile.transport || 0,       type: 'expense', changePercent: 0  },
      { category: 'Entertainment', icon: 'theater_comedy', amount: profile.entertainment || 0,   type: 'expense', changePercent: -5 },
      { category: 'Subscriptions', icon: 'subscriptions',  amount: 120,                          type: 'expense', changePercent: -5 },
    ].filter(item => item.amount > 0);

    res.json({ netBalance, income, expenses, monthlyTrend: trend.length ? trend : [{ month: currentMonthKey, income, expense: expenses }], breakdown });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/insight/today', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });

    const monthlyIncome   = (profile?.primarySalary || 0) + (profile?.sideIncome || 0);
    const monthlyExpenses = (profile?.rent || 0) + (profile?.food || 0) + (profile?.transport || 0) + (profile?.entertainment || 0) + (profile?.monthlyEMI || 0);

    const now = new Date();
    const currentWeekKey = getIsoWeekKey(now);
    await WeeklySnapshot.findOneAndUpdate(
      { userId: req.userId, weekKey: currentWeekKey },
      { $setOnInsert: { income: Math.round(monthlyIncome / 4), expenses: Math.round(monthlyExpenses / 4) } },
      { upsert: true, new: true }
    );

    const weeklySnapshots = await WeeklySnapshot.find({ userId: req.userId }).sort({ weekKey: -1 }).limit(6);
    const orderedWeeks    = weeklySnapshots.reverse();
    const chartPoints     = orderedWeeks.map(w => w.expenses);

    let trendDirection = 'flat';
    if (chartPoints.length >= 2) {
      if (chartPoints[chartPoints.length - 1] > chartPoints[0]) trendDirection = 'up';
      else if (chartPoints[chartPoints.length - 1] < chartPoints[0]) trendDirection = 'down';
    }

    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    const prompt = `You are a friendly personal finance coach. Based on the real data below, write today's insight for the user.
Never invent numbers — only reference the ones given.

USER DATA:
- Monthly income: $${monthlyIncome}
- Monthly expenses: $${monthlyExpenses}
- Weekly expense trend (oldest to newest, last ${chartPoints.length} weeks): ${JSON.stringify(chartPoints)}
- Trend direction: ${trendDirection}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount} by ${new Date(primaryGoal.targetDate).toDateString()}` : 'none set'}

Output must be ONLY valid JSON with these exact keys, no other text:
{
  "title": "short punchy insight title",
  "body": "2-3 sentence explanation grounded in the real numbers above",
  "action": { "title": "short action card title", "description": "1-2 sentence actionable suggestion", "buttonLabel": "short button text" }
}`.trim();

    let parsed;
    try {
      const { text } = await callAI(prompt, null, true);
      parsed = extractJson(text);
      if (!parsed.title || !parsed.body) throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error("❌ All AI providers failed for today's insight:", err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate insight. Please try again later.' });
    }

    res.json({ title: parsed.title, body: parsed.body, chartPoints: chartPoints.length ? chartPoints : null, trendDirection, action: parsed.action || null });
  } catch (err) {
    console.error('TODAY INSIGHT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.post('/api/chat', authenticate, async (req, res) => {
  try {
    const { messages } = req.body;
    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ error: 'messages must be a non-empty array' });

    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });

    const assets       = (profile?.cashSavings || 0) + (profile?.investments || 0) + (profile?.propertyValue || 0);
    const liabilities  = (profile?.totalLoans || 0) + (profile?.creditCardDebt || 0) + (profile?.monthlyEMI || 0);
    const netWorth     = assets - liabilities;
    const monthlyIncome   = (profile?.primarySalary || 0) + (profile?.sideIncome || 0);
    const monthlyExpenses = (profile?.rent || 0) + (profile?.food || 0) + (profile?.transport || 0) + (profile?.entertainment || 0) + (profile?.monthlyEMI || 0);

    const now = new Date();
    const currentWeekKey = getIsoWeekKey(now);
    await WeeklySnapshot.findOneAndUpdate(
      { userId: req.userId, weekKey: currentWeekKey },
      { $setOnInsert: { income: Math.round(monthlyIncome / 4), expenses: Math.round(monthlyExpenses / 4) } },
      { upsert: true, new: true }
    );

    const weeklySnapshots = await WeeklySnapshot.find({ userId: req.userId }).sort({ weekKey: -1 }).limit(7);
    const orderedWeeks    = weeklySnapshots.reverse();
    const chartData       = orderedWeeks.map(w => w.expenses);
    const highlightFromIndex = Math.max(0, chartData.length - 2);

    const systemPrompt = `You are a helpful, personal financial advisor.
Use the following real user data to give precise, actionable advice.
Never make up numbers – refer to the data provided.

USER PROFILE:
- Net worth: $${netWorth}
- Monthly income: $${monthlyIncome}
- Monthly expenses: $${monthlyExpenses}
- Goals: ${JSON.stringify(goals.map(g => ({ name: g.name || g.goalType, target: g.targetAmount, date: g.targetDate })))}
- Assets breakdown: Cash & Savings: $${profile?.cashSavings || 0}, Investments: $${profile?.investments || 0}, Property: $${profile?.propertyValue || 0}
- Liabilities: Loans: $${profile?.totalLoans || 0}, Credit Card Debt: $${profile?.creditCardDebt || 0}, Monthly EMI: $${profile?.monthlyEMI || 0}
- Last ${orderedWeeks.length} weeks of expenses: ${JSON.stringify(orderedWeeks.map(w => ({ week: w.weekKey, expenses: w.expenses })))}`.trim();

    const fullPrompt = systemPrompt + '\n\n' + messages.map(m => m.content || '').join('\n');
    const structuredMessages = [
      { role: 'system', content: systemPrompt },
      ...messages.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content || '' })),
    ];

    let reply;
    try {
      const result = await callAI(fullPrompt, structuredMessages, false);
      reply = result.text;
    } catch (err) {
      console.error('❌ All AI providers failed for chat:', err.message);
      return res.status(502).json({ error: err.message || 'All AI providers are currently unavailable.' });
    }

    res.json({ reply, chartData: chartData.length ? chartData : null, highlightFromIndex });
  } catch (err) {
    console.error('CHAT ERROR:', err);
    res.status(500).json({ error: err.message || 'Server error. Please try again later.' });
  }
});

app.get('/api/reflection/monthly', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const net      = income - expenses;

    const now      = new Date();
    const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const snapshot = await MonthlySnapshot.findOne({ userId: req.userId, monthKey });
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    const prompt = `You are a warm, encouraging financial coach. Based on the user's real data, write a monthly reflection.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Net cash flow: $${net}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType} – target $${primaryGoal.targetAmount}` : 'none set'}
- Goal progress: ${primaryGoal ? `${(primaryGoal.existingSavings || 0)} of ${primaryGoal.targetAmount}` : '0'}
- This month's snapshot: ${snapshot ? `income: $${snapshot.income}, expenses: $${snapshot.expenses}` : 'not available'}

Return ONLY a JSON object:
{
  "proudPrompt": "one-sentence prompt asking what the user is proud of",
  "coachResponse": "2-sentence personalized insight and encouragement",
  "highlights": [
    {"icon": "monetization_on", "iconBgColor": "#FFF9EB", "iconColor": "#F5A623", "title": "highlight title", "subtitle": "one-sentence detail"},
    {"icon": "check_circle_outline", "iconBgColor": "#EAF8F5", "iconColor": "#2E7D32", "title": "highlight title", "subtitle": "detail"},
    {"icon": "trending_up", "iconBgColor": "#EEF2FF", "iconColor": "#4F46E5", "title": "highlight title", "subtitle": "detail"}
  ]
}
Generate exactly 3 highlights. Use the actual data – never invent numbers.`.trim();

    let reflection;
    try {
      const { text } = await callAI(prompt, null, true);
      reflection = extractJson(text);
      if (!reflection.proudPrompt || !reflection.coachResponse || !reflection.highlights)
        throw new Error('Incomplete response from AI');
    } catch (err) {
      console.error('❌ Reflection AI failed:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate reflection. Try again later.' });
    }
    res.json(reflection);
  } catch (err) {
    console.error('REFLECTION ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/spending-analysis', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const rent          = profile.rent || 0;
    const food          = profile.food || 0;
    const transport     = profile.transport || 0;
    const entertainment = profile.entertainment || 0;
    const emi           = profile.monthlyEMI || 0;
    const income        = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const savingsAmount = Math.max(income - (rent + food + transport + entertainment + emi), 0);
    const total         = rent + food + transport + entertainment + emi + savingsAmount;

    const breakdown = [
      { label: 'Housing',   amount: rent },
      { label: 'Savings',   amount: savingsAmount },
      { label: 'Food',      amount: food },
      { label: 'Other',     amount: entertainment + emi },
      { label: 'Transport', amount: transport },
    ].map(item => ({ ...item, percent: total > 0 ? Math.round((item.amount / total) * 100) : 0 }));

    const prompt = `You are a sharp, encouraging financial behavior analyst. Based on the user's real spending breakdown below, identify their spending behavior patterns and give recommendations.
Never invent numbers – use only the real data provided.

USER SPENDING BREAKDOWN:
${breakdown.map(b => `- ${b.label}: $${b.amount} (${b.percent}%)`).join('\n')}
Monthly income: $${income}

Output ONLY a JSON object:
{
  "patterns": [
    {"icon": "monetization_on", "title": "short pattern title", "description": "1-2 sentence description"},
    {"icon": "speed", "title": "short pattern title", "description": "1-2 sentence description"},
    {"icon": "people", "title": "short pattern title", "description": "1-2 sentence description"}
  ],
  "recommendations": ["actionable move 1", "actionable move 2", "actionable move 3"]
}
Generate exactly 3 patterns and exactly 3 recommendations.`.trim();

    let analysis;
    try {
      const { text } = await callAI(prompt, null, true);
      analysis = extractJson(text);
      if (!analysis.patterns || !analysis.recommendations)
        throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for spending analysis:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate spending analysis. Please try again later.' });
    }
    res.json({ breakdown, spentTotal: total, patterns: analysis.patterns, recommendations: analysis.recommendations });
  } catch (err) {
    console.error('SPENDING ANALYSIS ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/wellness-check', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income      = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses    = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const savingsRate = income > 0 ? ((income - expenses) / income * 100) : 0;

    const prompt = `You are a financial wellness coach. Generate a complete financial wellness report in JSON format.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Savings rate: ${savingsRate.toFixed(1)}%
- Goals: ${JSON.stringify(goals.map(g => ({ name: g.name || g.goalType, target: g.targetAmount, date: g.targetDate, saved: g.existingSavings || 0 })))}

Output ONLY a valid JSON object:
{
  "overallScore": number 0-100,
  "status": "short status string",
  "scores": { "spending": number 0-100, "savings": number 0-100, "emotional": number 0-100, "habit": number 0-100 },
  "insights": { "spending": "description", "savings": "description", "emotional": "description", "habit": "description" },
  "mentorInsight": "2-3 sentence personalized insight",
  "growthPoints": number
}
Return ONLY the JSON.`.trim();

    let result;
    try {
      const { text } = await callAI(prompt, null, true);
      result = extractJson(text);
      if (result.overallScore == null || !result.scores)
        throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for wellness check:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate wellness check. Please try again later.' });
    }
    res.json(result);
  } catch (err) {
    console.error('WELLNESS ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/learn-grow', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });

    const income      = (profile?.primarySalary || 0) + (profile?.sideIncome || 0);
    const expenses    = (profile?.rent || 0) + (profile?.food || 0) + (profile?.transport || 0) + (profile?.entertainment || 0) + (profile?.monthlyEMI || 0);
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];
    const completedSet = new Set(profile?.completedTasks ?? []);
    const totalLessons = 12;
    const completedLessons = Math.min(completedSet.size, totalLessons);

    const prompt = `You are a personal-finance education curator. Generate a short personalized learning feed.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}
- Lessons completed: ${completedLessons} of ${totalLessons}

Output ONLY a JSON object:
{
  "featured": { "badge": "FEATURED", "time": "5 min", "title": "lesson title", "description": "1-2 sentence hook" },
  "categories": ["All", "category1", "category2", "category3"],
  "progressMessage": "1 short encouraging sentence",
  "lessons": [
    {"title": "lesson title", "time": "4 min", "status": "completed", "category": "category name"},
    {"title": "lesson title", "time": "6 min", "status": "inProgress", "category": "category name"},
    {"title": "lesson title", "time": "5 min", "status": "locked", "category": "category name"},
    {"title": "lesson title", "time": "3 min", "status": "locked", "category": "category name"}
  ]
}
status must be one of: "completed", "inProgress", "locked". Generate exactly 4 lessons and 4 categories.`.trim();

    let feed;
    try {
      const { text } = await callAI(prompt, null, true);
      feed = extractJson(text);
      if (!feed.featured || !feed.lessons || !feed.categories)
        throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for learn-grow:', err.message);
      return res.status(502).json({ error: err.message || 'Unable to generate lessons. Please try again later.' });
    }

    res.json({ title: 'Learn & Grow', subtitle: 'Build your financial knowledge, one lesson at a time.', featured: feed.featured, categories: feed.categories, progressCompleted: completedLessons, progressTotal: totalLessons, progressMessage: feed.progressMessage, lessons: feed.lessons });
  } catch (err) {
    console.error('LEARN GROW ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/journey-timeline', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId }).sort({ createdAt: 1 });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const now       = new Date();
    const timeline  = [];
    const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

    for (const goal of goals) {
      const createdDate = goal.createdAt || goal._id.getTimestamp();
      const dateStr     = `${monthNames[createdDate.getMonth()]} ${createdDate.getFullYear()}`;
      timeline.push({ date: dateStr, title: `Started "${goal.name || goal.goalType}" goal`, desc: `Target: $${goal.targetAmount} by ${new Date(goal.targetDate).toDateString()}`, completed: false, isToday: false, isStar: false });

      const progress = goal.targetAmount > 0 ? ((goal.existingSavings || 0) / goal.targetAmount) : 0;
      if (progress >= 0.25) {
        timeline.push({ date: monthNames[now.getMonth()] + ' ' + now.getFullYear(), title: `${Math.round(progress * 100)}% of ${goal.name || goal.goalType}`, desc: `Saved $${goal.existingSavings || 0} of $${goal.targetAmount}`, completed: false, isToday: true, isStar: false });
      }
    }

    if (timeline.length > 0) timeline[0].completed = true;
    timeline.push({ date: 'Future', title: 'Financial Independence', desc: 'All goals achieved, passive income > expenses', completed: false, isToday: false, isStar: true });

    const income      = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses    = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const net         = income - expenses;
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    const projectionPrompt = `You are a financial coach. Write one encouraging projection sentence.
- Monthly net cash flow: $${net}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}
Output ONLY: { "title": "projection title", "body": "1-2 sentence projection" }`.trim();

    let projection;
    try {
      const { text } = await callAI(projectionPrompt, null, true);
      projection = extractJson(text);
      if (!projection.title || !projection.body) throw new Error('bad response');
    } catch {
      projection = { title: 'Your Path Forward', body: 'Keep up the great work – consistency is your superpower.' };
    }

    res.json({ timeline, projection });
  } catch (err) {
    console.error('JOURNEY TIMELINE ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/home-dashboard', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId }).sort({ priority: -1, createdAt: -1 });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const user     = await User.findById(req.userId);
    const userName = user?.name || 'there';
    const hour     = new Date().getHours();
    const greeting = hour < 12 ? `Good morning, ${userName}` : hour < 18 ? `Good afternoon, ${userName}` : `Good evening, ${userName}`;
    const profilePic = profile.profilePicture || user?.profilePictureUrl || '';

    const primaryGoal = goals.length > 0 ? goals[0] : null;
    let goalProgress = 0, goalTitle = 'No goal set', goalAmount = '';
    if (primaryGoal) {
      const target  = primaryGoal.targetAmount || 0;
      const saved   = primaryGoal.existingSavings || 0;
      goalProgress  = target > 0 ? Math.min(saved / target, 1) : 0;
      goalTitle     = primaryGoal.name || primaryGoal.goalType;
      goalAmount    = `$${saved.toFixed(0)} of $${target.toFixed(0)}`;
    }

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);

    const insightPrompt = `You are a personal finance coach. Generate a short, encouraging insight for the home screen.
USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Primary goal: ${primaryGoal ? `${goalTitle}, target $${primaryGoal.targetAmount}, saved $${primaryGoal.existingSavings || 0}` : 'none set'}

Output ONLY a JSON object:
{
  "insightTitle": "a short, powerful insight title",
  "insightBody": "1-2 sentences personalized insight",
  "insightButtonLabel": "short button label like 'Read Full Analysis'",
  "quoteText": "a short motivational quote related to finance",
  "quoteAuthor": "author of the quote"
}`.trim();

    let aiResponse;
    try {
      const { text } = await callAI(insightPrompt, null, true);
      aiResponse = extractJson(text);
    } catch {
      aiResponse = { insightTitle: 'Your Financial Snapshot', insightBody: 'Keep up the great work!', insightButtonLabel: 'Read Full Analysis', quoteText: 'Financial freedom is not about how much you make, but how much you keep.', quoteAuthor: 'Robert Kiyosaki' };
    }

    const completedCount = (profile.completedTasks || []).length;
    const activeDays     = Math.min(completedCount, 7);
    const streak = { days: ['M','T','W','T','F','S','S'], activeIndices: Array.from({ length: activeDays }, (_, i) => i) };

    const badges = [];
    if (completedCount >= 1) badges.push({ type: 'shield', color: '#A7F3D0', iconColor: '#059669' });
    if (completedCount >= 3) badges.push({ type: 'heart',  color: '#FDE68A', iconColor: '#D97706' });
    if (completedCount >= 5) badges.push({ type: 'globe',  color: '#BFDBFE', iconColor: '#2563EB' });
    if (badges.length === 0) {
      badges.push({ type: 'shield', color: '#F3F4F6', iconColor: '#9CA3AF' });
      badges.push({ type: 'heart',  color: '#F3F4F6', iconColor: '#9CA3AF' });
      badges.push({ type: 'globe',  color: '#F3F4F6', iconColor: '#9CA3AF' });
    }

    const baseImgUrl = 'https://lh3.googleusercontent.com/aida-public/';
    const actions = [
      { imageUrl: baseImgUrl + 'AB6AXuDZnlBUimIZjxl-2oBH0lsJX4SD0g-xoPPNoOGJvV41dOo_g3ARgEuX8Yllivds11Cf3qG-TRw7N9IJ-I4KPABFytesOJ2lLTb6yfISZsZTN1Vn5-8CYSA_RnKdHlRhnctvbFoec9o_oC4qei0R2s7KpwfSG2a5Pnihpq0LtbhugU6V6R-sqI0BlN93LcqRn0c3MMKOfR944aM_0Sc8kWfTewpykSSuENhZ2XB44Gbnw6L_bWYw9Vpf', label: 'Journey' },
      { imageUrl: baseImgUrl + 'AB6AXuAE5YuEX_EuafoWVLql1ngFZw-kGEohRCxZq2XI7LDe2Bb9NYQw-4w5Iw96MW1pfx3VLQF36y4x80EDnqee4q8QD1mX_t6e3dSrF1G7vyQYFE2N4YPiY0qjJ1OscNhjHiMQa17My7FoigFVorQUG-en2L9Yl2Nn8jeGr3Y1OYEZCopFYaHiVmoKDdGssn9E3BffywpMZE1gWPR5dOQtxC1HWH5W9WWY56sQCUutu1-unA8Rb9iTwXU_', label: 'Coach' },
      { imageUrl: baseImgUrl + 'AB6AXuAPxr6CwtWymbHkUpDEK-S_OIXWxkK6XlGm1e15tKLzDDiUUHrYB_txGLiM1mkRlMIkiY6MIkZ2NBjkH6B5G05CouS11mF9oHIZDD3rbWsO8r-Gnr14ONQNpZd7X5HVP5ThK9dtOK0zC7pFWQNNqDPg8hBIRbHXmXdXcJ5RdGdQQD1ShfLKoPzZj1J4UQp9P9W5Hot8iXAqvx9VWvASbLPRiylGAAvt98yYJ2stsvR7BaMlBYDThcyN', label: 'Insights' },
    ];

    res.json({ greeting, profileImageUrl: profilePic, goalProgress, goalTitle, goalAmount, insightTitle: aiResponse.insightTitle, insightBody: aiResponse.insightBody, insightButtonLabel: aiResponse.insightButtonLabel, quoteText: aiResponse.quoteText, quoteAuthor: aiResponse.quoteAuthor, streak, badges, actions });
  } catch (err) {
    console.error('HOME DASHBOARD ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/net-worth', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.json({ monthlyIncome: profile.primarySalary || 0, fixedExpenses: (profile.rent || 0) + (profile.monthlyEMI || 0), currentSavings: profile.cashSavings || 0, totalDebt: (profile.totalLoans || 0) + (profile.creditCardDebt || 0) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/net-worth', authenticate, async (req, res) => {
  try {
    const { monthlyIncome, fixedExpenses, currentSavings, totalDebt } = req.body;
    const update = {};
    if (monthlyIncome !== undefined) update.primarySalary = monthlyIncome;
    if (fixedExpenses !== undefined) { update.rent = fixedExpenses; update.monthlyEMI = 0; }
    if (currentSavings !== undefined) update.cashSavings = currentSavings;
    if (totalDebt !== undefined) { update.totalLoans = totalDebt; update.creditCardDebt = 0; }
    const profile = await Profile.findOneAndUpdate({ userId: req.userId }, { $set: update }, { new: true, upsert: true, runValidators: true });
    res.json(profile);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});





// ══════════════════════════════════════════════════════════════════════════════
//  INTENT ROUTES
// ══════════════════════════════════════════════════════════════════════════════
// ✅ Smart intent route (handles JSON and multipart)
app.post('/api/intent', authenticate, (req, res, next) => {
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('multipart/form-data')) {
    uploadReceipt(req, res, next);
  } else {
    next();
  }
}, async (req, res) => {
  try {
    console.log('INTENT BODY:', req.body); // ← add this temporarily
    const { amount, category, place, note, paymentMethod } = req.body;
    if (!amount || !category) {
      return res.status(400).json({ error: 'Amount and category are required.' });
    }

    let receiptUrl = null;
    let receiptPublicId = null;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer, 'finpath/receipts');
      receiptUrl = result.secure_url;
      receiptPublicId = result.public_id;
    }

    const intent = await Intent.create({
      userId: req.userId,
      amount,
      category,
      place: place || '',
      note: note || '',
      paymentMethod: paymentMethod || '',
      receiptUrl,
      receiptPublicId,
    });

    res.status(201).json(intent);
  } catch (err) {
    console.error('INTENT SAVE ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});




// ─── RECENT PLACES ──────────────────────────────────
app.get('/api/intent/recent-places', authenticate, async (req, res) => {
  try {
    const intents = await Intent.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(200); // look at a much larger recent window

    const unique = [];
    const seen = new Set();
    for (const i of intents) {
      const label = (i.place && i.place.trim()) || (i.note && i.note.trim());
      if (label && !seen.has(label)) {
        seen.add(label);
        unique.push(label);
        if (unique.length === 20) break; // raise cap, not stuck at 5
      }
    }
    res.json(unique);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET TODAY'S INTENTS ──────────────────────────
app.get('/api/intent/today', authenticate, async (req, res) => {
  try {
    const TZ_OFFSET_HOURS = 5; // Pakistan Standard Time, UTC+5
    const nowUtc = new Date();
    const localNow = new Date(nowUtc.getTime() + TZ_OFFSET_HOURS * 60 * 60 * 1000);

    const localMidnight = new Date(Date.UTC(
      localNow.getUTCFullYear(),
      localNow.getUTCMonth(),
      localNow.getUTCDate(),
      0, 0, 0, 0
    ));
    const today = new Date(localMidnight.getTime() - TZ_OFFSET_HOURS * 60 * 60 * 1000);
    const tomorrow = new Date(today.getTime() + 24 * 60 * 60 * 1000);

    const intents = await Intent.find({
      userId: req.userId,
      createdAt: { $gte: today, $lt: tomorrow },
    }).sort({ createdAt: -1 });

    res.json(intents);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── INTENT INSIGHT (already present, ensure it exists) ───
app.get('/api/intent/insight', authenticate, async (req, res) => {
  try {
    const { category, amount } = req.query;
    if (!category || !amount) return res.status(400).json({ error: 'category and amount required' });
    const profile = await Profile.findOne({ userId: req.userId });
    const prompt = `
User is about to make a purchase in category "${category}" for $${amount}. Their monthly income: $${profile?.primarySalary || 0}. Give a one‑sentence encouraging, non‑judgmental insight that connects this purchase to their financial goals. Output ONLY a JSON: { "message": "..." }
`.trim();
    const { text } = await callAI(prompt, null, true);
    const parsed = extractJson(text);
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/api/intent/insight/daily', authenticate, async (req, res) => {
  try {
    const TZ_OFFSET_HOURS = 5;
    const nowUtc = new Date();
    const localNow = new Date(nowUtc.getTime() + TZ_OFFSET_HOURS * 60 * 60 * 1000);
    const localMidnight = new Date(Date.UTC(
      localNow.getUTCFullYear(),
      localNow.getUTCMonth(),
      localNow.getUTCDate(),
      0, 0, 0, 0
    ));
    const today = new Date(localMidnight.getTime() - TZ_OFFSET_HOURS * 60 * 60 * 1000);

    const intents = await Intent.find({
      userId: req.userId,
      createdAt: { $gte: today },
    });
    
    const total = intents.reduce((sum, i) => sum + i.amount, 0);
    const categories = [...new Set(intents.map(i => i.category))].join(', ');
    const prompt = `
You are a cheerful financial companion. Based on the user's data below, write a ONE-SENTENCE encouraging daily banner (max 15 words). Do NOT include quotation marks.
- Today's total spending: $${total.toFixed(2)}
- Categories: ${categories || 'none'}
Output ONLY the sentence, no extra text.
`.trim();
    const { text } = await callAI(prompt, null, false);
    res.json({ message: text.trim() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/insights/overview', authenticate, async (req, res) => {
  try {
    const { filter = 'month' } = req.query;   // week, month, year
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const savings  = Math.max(income - expenses, 0);
    const savingsRate = income > 0 ? Math.round((savings / income) * 100) : 0;

    let trendValues = [];
    let trendLabels = [];

    const now = new Date();

    if (filter === 'week') {
      // Last 7 days (Sun–Sat)
      const intents = await Intent.find({ userId: req.userId }).sort({ createdAt: -1 });
      const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
      const dailyTotals = {};
      for (let d = 6; d >= 0; d--) {
        const date = new Date(now);
        date.setDate(now.getDate() - d);
        const key = date.toISOString().split('T')[0];
        dailyTotals[key] = 0;
      }
      intents.forEach(i => {
        const key = new Date(i.createdAt).toISOString().split('T')[0];
        if (dailyTotals.hasOwnProperty(key)) {
          dailyTotals[key] += i.amount;
        }
      });
      trendLabels = Object.keys(dailyTotals).map(k => k.slice(5)); // MM-DD
      trendValues = Object.values(dailyTotals);
    } else if (filter === 'month') {
      // Last 6 monthly snapshots
      const snapshots = await MonthlySnapshot.find({ userId: req.userId }).sort({ monthKey: -1 }).limit(6);
      const ordered = snapshots.reverse(); // oldest first
      trendLabels = ordered.map(s => s.monthKey.substring(5)); // '01','02', etc.
      trendValues = ordered.map(s => Math.max(s.income - s.expenses, 0));
    } else if (filter === 'year') {
      // Last 2 years (yearly totals)
      const currentYear = now.getFullYear();
      const years = [currentYear - 1, currentYear];
      const yearSnapshots = await MonthlySnapshot.find({
        userId: req.userId,
        monthKey: { $regex: `^(202[0-9])-` }
      });
      const yearly = {};
      years.forEach(y => { yearly[y] = 0; });
      yearSnapshots.forEach(s => {
        const y = parseInt(s.monthKey.split('-')[0]);
        if (yearly.hasOwnProperty(y)) {
          yearly[y] += Math.max(s.income - s.expenses, 0);
        }
      });
      trendLabels = years.map(y => y.toString());
      trendValues = years.map(y => yearly[y]);
    }

    // AI behaviour insights (same as before)
    const intents = await Intent.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(100);
    const categoryTotals = {};
    for (const i of intents) categoryTotals[i.category] = (categoryTotals[i.category] || 0) + i.amount;
    const topCategory = Object.entries(categoryTotals).sort((a, b) => b[1] - a[1])[0];
    const dayTotals = {};
    for (const i of intents) {
      const day = new Date(i.createdAt).toLocaleDateString('en-US', { weekday: 'long' });
      dayTotals[day] = (dayTotals[day] || 0) + i.amount;
    }
    const lowestSpendDay = Object.entries(dayTotals).sort((a, b) => a[1] - b[1])[0];
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    const prompt = `You are a behavior-focused financial coach. Based on this user's real data, generate two short behavior-pattern insights for a dashboard.
    Never invent numbers – use only the real data provided.
    USER DATA:
    - Monthly income: $${income}
    - Monthly expenses: $${expenses}
    - Savings rate: ${savingsRate}%
    - Top spending category: ${topCategory ? `${topCategory[0]} ($${topCategory[1].toFixed(2)})` : 'none yet'}
    - Lowest-spend day of week: ${lowestSpendDay ? `${lowestSpendDay[0]} ($${lowestSpendDay[1].toFixed(2)})` : 'not enough data'}
    - Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}
    Output ONLY a JSON object: { "bestDayPrefix": "...", "bestDayHighlight": "...", "bestDaySuffix": "...", "coffeePrefix": "...", "coffeeHighlight": "...", "coffeeSuffix": "..." }`;

    let aiInsights = {};
    try {
      const { text } = await callAI(prompt, null, true);
      aiInsights = extractJson(text);
    } catch (err) {
      console.error('❌ Insights AI failed:', err.message);
      aiInsights = {
        bestDayPrefix: 'You tend to save more on ',
        bestDayHighlight: lowestSpendDay ? lowestSpendDay[0] : 'quiet days',
        bestDaySuffix: ' — nice consistency.',
        coffeePrefix: 'Your biggest category is ',
        coffeeHighlight: topCategory ? topCategory[0] : 'spending',
        coffeeSuffix: ' — worth a look if you want to save faster.',
      };
    }

    res.json({
      savingsAmount: `$${savings.toFixed(0)}`,
      savingsSubtitle: 'saved this month',
      savingsRatePercent: `${savingsRate}%`,
      filter,                                       // echo back the filter used
      trendValues,
      trendLabels,
      ...aiInsights,
    });
  } catch (err) {
    console.error('INSIGHTS OVERVIEW ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/api/june-report', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const saved    = Math.max(income - expenses, 0);

    // Previous month comparison
    const now = new Date();
    const prevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const prevMonthKey = `${prevMonth.getFullYear()}-${String(prevMonth.getMonth() + 1).padStart(2, '0')}`;
    const prevSnapshot = await MonthlySnapshot.findOne({ userId: req.userId, monthKey: prevMonthKey });
    const vsLastMonthPercent = prevSnapshot && prevSnapshot.expenses > 0
      ? Math.round(((expenses - prevSnapshot.expenses) / prevSnapshot.expenses) * 100)
      : 0;

    // Category adherence (category vs a soft budget guess: 30% of income split across categories)
    const categoryDefs = [
      { key: 'food',          label: 'Food & Dining' },
      { key: 'transport',     label: 'Transport' },
      { key: 'entertainment', label: 'Entertainment' },
      { key: 'rent',          label: 'Housing' },
    ];
    const categories = categoryDefs
      .map(c => {
        const spent = profile[c.key] || 0;
        const budget = c.key === 'rent' ? spent || 1 : Math.max(income * 0.1, spent, 1);
        const percent = Math.min(spent / budget, 1);
        return {
          label: c.label,
          amountLabel: `$${spent.toFixed(0)} / $${budget.toFixed(0)}`,
          percent,
          isWarning: percent >= 0.9,
        };
      })
      .filter(c => c.amountLabel !== '$0 / $1');

    // Savings momentum: last 6 monthly snapshots -> savings per month
    const snapshots = await MonthlySnapshot.find({ userId: req.userId }).sort({ monthKey: -1 }).limit(6);
    const ordered = snapshots.reverse();
    const monthNamesShort = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const chartMonths = ordered.map(s => monthNamesShort[parseInt(s.monthKey.split('-')[1], 10) - 1]);
    const chartSavings = ordered.map(s => Math.max(s.income - s.expenses, 0));

    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    // AI-generated highlights + insight (Groq -> Gemini fallback, same as rest of the app)
    const prompt = `
You are a warm, encouraging financial coach writing a "Monthly Report" summary card for a finance app.
Use ONLY the real data below — never invent numbers.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Amount saved this month: $${saved}
- Change in expenses vs last month: ${vsLastMonthPercent}%
- Category spending: ${JSON.stringify(categories.map(c => ({ label: c.label, amountLabel: c.amountLabel })))}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}

Output ONLY a JSON object with this exact structure, no extra commentary:
{
  "heroTitle": "short 2-4 word title like 'You crushed it!'",
  "highlight1": "short highlight phrase (max 6 words) about savings, e.g. 'Saved 15% more than May'",
  "highlight2": "short highlight phrase (max 6 words) about a specific category or habit",
  "highlight3": "short highlight phrase (max 6 words) about a trend, e.g. 'Spending trending down'",
  "insightBody": "1-2 sentence encouraging insight tying the numbers together, addressed to the user"
}`.trim();

    let ai;
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.heroTitle || !ai.insightBody) throw new Error('Incomplete data from AI provider');
    } catch (err) {
      console.error('❌ All AI providers failed for june-report:', err.message);
      ai = {
        heroTitle: 'Great progress',
        highlight1: `Saved $${saved.toFixed(0)} this month`,
        highlight2: 'Stayed within budget',
        highlight3: vsLastMonthPercent <= 0 ? 'Spending trending down' : 'Spending trending up',
        insightBody: `You saved $${saved.toFixed(0)} out of $${income.toFixed(0)} in income this month. Keep the momentum going.`,
      };
    }

    res.json({
      title: 'Monthly Report', // consider deriving from current month name if reused across months
      statusBadge: 'COMPLETED',
      subtitle: `Here's how your money moved this month`,
      heroTitle: ai.heroTitle,
      spentValue: `$${expenses.toFixed(0)}`,
      savedValue: `$${saved.toFixed(0)}`,
      vsLastMonthValue: `${vsLastMonthPercent > 0 ? '+' : ''}${vsLastMonthPercent}%`,
      categories,
      chartMonths: chartMonths.length ? chartMonths : ['-', '-', '-', '-', '-', '-'],
      chartSavings,
      highlight1: ai.highlight1,
      highlight2: ai.highlight2,
      highlight3: ai.highlight3,
      insightBody: ai.insightBody,
    });
  } catch (err) {
    console.error(' REPORT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});


app.get('/api/june-story', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);

    // Get current month name
    const monthNames = ['January','February','March','April','May','June',
                        'July','August','September','October','November','December'];
    const currentMonth = monthNames[new Date().getMonth()];
    const currentYear  = new Date().getFullYear();

    const prompt = `
You are a warm, encouraging financial coach writing a personalised "${currentMonth} Story" for a user.
Use ONLY the real data below – never invent numbers.

USER DATA:
- Monthly income: $${income}
- Monthly expenses: $${expenses}
- Primary goal: ${goals.length ? `${goals[0].name || goals[0].goalType}, target $${goals[0].targetAmount}` : 'none set'}

Output ONLY a JSON object with this exact structure, no extra commentary:
{
  "title": "Your ${currentMonth} Story",
  "subtitle": "A look back at your financial journey this month",
  "heroQuote": "an inspiring short quote (4-6 words) that captures the month's theme",
  "heroDescription": "1-2 sentences of heartfelt description",
  "keyMoments": [
    {
      "icon": "chat_bubble_outline",
      "iconBgColor": "0xFFE0F2FE",
      "iconColor": "0xFF0284C7",
      "title": "short highlight title (max 5 words)",
      "date": "${currentMonth} 3"
    },
    {
      "icon": "star",
      "iconBgColor": "0xFFFEF3C7",
      "iconColor": "0xFFD97706",
      "title": "short highlight title (max 5 words)",
      "date": "${currentMonth} 10"
    },
    {
      "icon": "trending_up",
      "iconBgColor": "0xFFD1FAE5",
      "iconColor": "0xFF059669",
      "title": "short highlight title (max 5 words)",
      "date": "${currentMonth} 22"
    }
  ],
  "themeSummary": "one sentence that summarises the month's financial theme",
  "shareButtonText": "Share Your Story"
}
Generate exactly 3 key moments. The icons, colours, and dates should feel realistic and reflect the user's data.
The month name in the dates should be exactly "${currentMonth}".`.trim();

    let story;
    try {
      const { text } = await callAI(prompt, null, true);
      story = extractJson(text);
      if (!story.heroQuote || !story.keyMoments) throw new Error('Incomplete AI response');
    } catch (err) {
      console.error('❌ AI failed for monthly story:', err.message);
      story = {
        title: `Your ${currentMonth} Story`,
        subtitle: 'A look back at your financial journey this month',
        heroQuote: 'Small steps, big dreams.',
        heroDescription: `You managed your finances with care this month. Keep up the great momentum.`,
        keyMoments: [
          { icon: 'chat_bubble_outline', iconBgColor: '0xFFE0F2FE', iconColor: '0xFF0284C7', title: 'Budget check-in', date: `${currentMonth} 3` },
          { icon: 'star', iconBgColor: '0xFFFEF3C7', iconColor: '0xFFD97706', title: 'Saved extra $50', date: `${currentMonth} 10` },
          { icon: 'trending_up', iconBgColor: '0xFFD1FAE5', iconColor: '0xFF059669', title: 'Investment milestone', date: `${currentMonth} 22` }
        ],
        themeSummary: 'A month of mindful spending and steady growth.',
        shareButtonText: 'Share Your Story'
      };
    }

    // Ensure the month name is always correct, even if AI hallucinated
    story.monthName = currentMonth;     // 👈 send month name separately for the client

    res.json(story);
  } catch (err) {
    console.error('MONTHLY STORY ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});


app.get('/api/monthly-snapshot', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId }).limit(2); // first two active goals
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    const currentMonthName = monthNames[now.getMonth()];

    // 1. Get current month's income / expenses from monthly snapshot
    let snapshot = await MonthlySnapshot.findOne({ userId: req.userId, monthKey: currentMonthKey });
    // If no snapshot yet (very early in month), use profile defaults
    const income   = snapshot ? snapshot.income : ((profile.primarySalary || 0) + (profile.sideIncome || 0));
    const expenses = snapshot ? snapshot.expenses : ((profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0));
    const saved    = Math.max(income - expenses, 0);

    // 2. Previous month snapshot for comparison (trends)
    const prevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const prevMonthKey = `${prevMonth.getFullYear()}-${String(prevMonth.getMonth() + 1).padStart(2, '0')}`;
    const prevSnapshot = await MonthlySnapshot.findOne({ userId: req.userId, monthKey: prevMonthKey });
    const prevIncome   = prevSnapshot ? prevSnapshot.income : income;
    const prevExpenses = prevSnapshot ? prevSnapshot.expenses : expenses;
    const prevSaved    = Math.max(prevIncome - prevExpenses, 0);

    // Trends (percentage change, handle zeros)
    const incomeTrend  = prevIncome > 0  ? ((income - prevIncome) / prevIncome * 100).toFixed(1) : '0';
    const expenseTrend = prevExpenses > 0 ? ((expenses - prevExpenses) / prevExpenses * 100).toFixed(1) : '0';
    const savedTrend   = prevSaved > 0    ? ((saved - prevSaved) / prevSaved * 100).toFixed(1) : '0';

    // 3. Savings rate
    const savingsRate = income > 0 ? Math.round((saved / income) * 100) : 0;

    // 4. Active goals (top 2)
    const activeGoals = goals.map(g => {
      const target = g.targetAmount || 0;
      const current = g.existingSavings || 0;
      const progress = target > 0 ? current / target : 0;
      return {
        title: g.name || g.goalType,
        progress: progress,
        label: `$${current.toFixed(0)} of $${target.toFixed(0)}`
      };
    });

    // 5. Top spending categories from profile (simplified)
    const categories = [
      { name: 'Housing',     amount: profile.rent || 0 },
      { name: 'Food',        amount: profile.food || 0 },
      { name: 'Shopping',    amount: profile.entertainment || 0 }
    ].filter(c => c.amount > 0).sort((a,b) => b.amount - a.amount).slice(0, 3);
    const totalCat = categories.reduce((sum, c) => sum + c.amount, 0) || 1;
    const topCategories = categories.map(c => ({
      name: c.name,
      percent: Math.round(c.amount / totalCat * 100)
    }));

    // 6. AI-generated insight & momentum message
    const prompt = `
You are a friendly financial coach. Generate TWO short phrases based on the user's real data.

User data:
- Month: ${currentMonthName}
- Income: $${income.toFixed(0)} (vs last month: ${incomeTrend}%)
- Expenses: $${expenses.toFixed(0)} (vs last month: ${expenseTrend}%)
- Saved: $${saved.toFixed(0)}
- Savings rate: ${savingsRate}%
- Active goals: ${JSON.stringify(activeGoals)}
- Top spending: ${JSON.stringify(topCategories)}

Output ONLY a JSON object:
{
  "insightMessage": "a 1-2 sentence personalised insight about this month's finances, warm and encouraging",
  "momentumTitle": "short title like '3 Month Streak!' or 'You're on Fire'",
  "momentumSubtitle": "1 short sentence about the momentum, e.g. 'Your savings are growing every month'"
}`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.insightMessage || !ai.momentumTitle) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for monthly-snapshot');
      ai = {
        insightMessage: `You're doing great this month – keep up the consistent effort!`,
        momentumTitle: 'Keep it up!',
        momentumSubtitle: `Your savings rate is ${savingsRate}% this month.`
      };
    }

    // Assemble response
    res.json({
      monthName: currentMonthName,
      title: `Your ${currentMonthName} Snapshot`,
      subtitle: `${currentMonthName} at a glance`,
      dateButton: `${currentMonthName} 1 – ${currentMonthName} ${new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()}`, // e.g. "August 1 – 31"
      income: {
        label: 'Income',
        amount: `$${income.toFixed(0)}`,
        trend: `${incomeTrend}%`,
        isUp: incomeTrend >= 0
      },
      expenses: {
        label: 'Expenses',
        amount: `$${expenses.toFixed(0)}`,
        trend: `${expenseTrend}%`,
        isUp: expenseTrend >= 0
      },
      saved: {
        label: 'Saved',
        amount: `$${saved.toFixed(0)}`,
        trend: `${savedTrend}%`,
        isUp: savedTrend >= 0
      },
      savingsRate: {
        label: 'Savings Rate',
        percent: `${savingsRate}%`,
        description: `That's ${savingsRate >= 20 ? 'above' : 'just below'} the recommended 20% – ${savingsRate >= 20 ? 'fantastic!' : 'a little push could boost it.'}`,
        progress: savingsRate / 100
      },
      activeGoals: {
        title: 'Active Goals',
        goals: activeGoals
      },
      momentum: {
        title: ai.momentumTitle,
        subtitle: ai.momentumSubtitle
      },
      topCategories: {
        title: 'Top Categories',
        categories: topCategories,
        // colors for the chart – kept client side for simplicity, but could be generated
      },
      insightMessage: ai.insightMessage
    });
  } catch (err) {
    console.error('MONTHLY SNAPSHOT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

app.get('/api/your-evolution', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    // Gather real numbers for the AI
    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const net = income - expenses;

    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    // Last 3 monthly snapshots for progression context
    const snapshots = await MonthlySnapshot.find({ userId: req.userId }).sort({ monthKey: -1 }).limit(3);
    const snapshotInfo = snapshots.reverse().map(s => ({
      month: s.monthKey,
      income: s.income,
      expenses: s.expenses,
      saved: Math.max(s.income - s.expenses, 0)
    }));

    const prompt = `
You are a compassionate financial coach. Create a personalised "Your Evolution" timeline for the user based on their real data.

User data:
- Monthly income: $${income.toFixed(0)}
- Monthly expenses: $${expenses.toFixed(0)}
- Net cash flow: $${net.toFixed(0)}
- Primary goal: ${primaryGoal ? `${primaryGoal.name || primaryGoal.goalType}, target $${primaryGoal.targetAmount}` : 'none set'}
- Recent monthly snapshots (newest first): ${JSON.stringify(snapshotInfo)}

Output ONLY a JSON object with this exact structure:

{
  "title": "Your Evolution",
  "subtitle": "See how far you’ve come on your financial journey",
  "timeline": [
    {
      "date": "Month name (e.g., 'January')",
      "title": "short title (max 4 words)",
      "desc": "1 sentence description of the emotional state or financial milestone",
      "iconBgColor": "0xFFE6DCCF",
      "icon": "sentiment_dissatisfied",
      "iconColor": "0xFF796856",
      "isActive": false
    },
    {
      "date": "Month name",
      "title": "short title",
      "desc": "1 sentence description",
      "iconBgColor": "0xFFF0EAE2",
      "icon": "sentiment_neutral",
      "iconColor": "0xFF6B7280",
      "isActive": false
    },
    {
      "date": "Current month name",
      "title": "short title",
      "desc": "1 sentence description – this should be the current positive milestone",
      "iconBgColor": "0xFFD1FAE5",
      "icon": "sentiment_satisfied",
      "iconColor": "0xFF059669",
      "isActive": true
    },
    {
      "date": "Future (e.g., 'Next Month')",
      "title": "short title (optimistic future milestone)",
      "desc": "1 sentence optimistic projection",
      "iconBgColor": "0xFFFFF3E0",
      "icon": "star",
      "iconColor": "0xFFF59E0B",
      "isActive": false
    }
  ],
  "metrics": {
    "mindset": "number 0-100",
    "confidence": "number 0-100",
    "knowledge": "number 0-100"
  },
  "quote": {
    "label": "MONEY MINDSET",
    "text": "a motivational quote about financial growth (max 15 words)"
  }
}

Make the timeline dates realistic (e.g., past months, current month, future). The active milestone should be the current month. Use the real data to make the titles and descriptions specific. The metrics should reflect the user's financial progress. Return ONLY the JSON, no other text.`.trim();

    let evolution;
    try {
      const { text } = await callAI(prompt, null, true);
      evolution = extractJson(text);
      if (!evolution.title || !evolution.timeline) throw new Error('Incomplete AI response');
    } catch (err) {
      console.error('❌ AI failed for your-evolution:', err.message);
      // Fallback with realistic defaults
      const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
      const currentMonth = monthNames[new Date().getMonth()];
      evolution = {
        title: 'Your Evolution',
        subtitle: 'See how far you’ve come on your financial journey',
        timeline: [
          { date: monthNames[(new Date().getMonth()-3+12)%12], title: 'Starting Out', desc: 'Felt overwhelmed but determined.', iconBgColor: '0xFFE6DCCF', icon: 'sentiment_dissatisfied', iconColor: '0xFF796856', isActive: false },
          { date: monthNames[(new Date().getMonth()-1+12)%12], title: 'Building Habits', desc: 'Steady progress and first savings.', iconBgColor: '0xFFF0EAE2', icon: 'sentiment_neutral', iconColor: '0xFF6B7280', isActive: false },
          { date: currentMonth, title: 'Gaining Confidence', desc: 'Feeling in control and optimistic.', iconBgColor: '0xFFD1FAE5', icon: 'sentiment_satisfied', iconColor: '0xFF059669', isActive: true },
          { date: 'Future', title: 'Financial Freedom', desc: 'Passive income covers all expenses.', iconBgColor: '0xFFFFF3E0', icon: 'star', iconColor: '0xFFF59E0B', isActive: false }
        ],
        metrics: { mindset: 75, confidence: 70, knowledge: 65 },
        quote: { label: 'MONEY MINDSET', text: 'Wealth is the ability to fully experience life.' }
      };
    }

    res.json(evolution);
  } catch (err) {
    console.error('EVOLUTION ENDPOINT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/api/your-future', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId }).sort({ priority: -1 }).limit(2);
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const now = new Date();
    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);

    // Map goal data for AI
    const goalData = goals.map(g => {
      const target = g.targetAmount || 0;
      const saved  = g.existingSavings || 0;
      const monthsLeft = Math.max(Math.ceil((g.targetDate ? (new Date(g.targetDate) - now) / (1000*60*60*24*30) : 12)), 0);
      const neededMonthly = monthsLeft > 0 ? (target - saved) / monthsLeft : target;
      const affordability = income > 0 ? Math.min(neededMonthly / (income * 0.3), 1) : 0; // 30% of income
      return {
        name: g.name || g.goalType,
        target,
        saved,
        monthsLeft,
        monthlyContribution: g.monthlyContribution || 0,
        autoTransfer: g.autoTransfer,
        riskTolerance: g.riskTolerance || 'conservative',
        affordability: affordability.toFixed(2)
      };
    });

    const prompt = `
You are a financial forecaster. Based on the user's real goals and financial data, generate a "Your Future" outlook.

User data:
- Monthly income: $${income.toFixed(0)}
- Goals: ${JSON.stringify(goalData)}

Output ONLY a JSON object with this exact structure:

{
  "title": "Your Future",
  "subtitle": "Where your money is taking you",
  "goals": [
    {
      "icon": "home",               // Material icon name (e.g., home, flight_takeoff, school, business_center)
      "title": "short goal title",
      "confidence": "High Confidence",
      "confidenceBgColor": "0xFFD1FAE5",
      "confidenceTextColor": "0xFF065F46",
      "completion": "Mar 2026",
      "completionExtra": "2 months early",   // optional, null if not applicable
      "completionColor": "0xFF059669",
      "insight": "AI-generated insight 1-2 sentences",
      "insightBgColor": "0xFFD1FAE5",
      "insightIconColor": "0xFF059669",
      "insightIcon": "security"     // Material icon name for the insight line
    },
    // second goal if present, otherwise null
  ],
  "milestonesTitle": "Probability Milestones",
  "milestones": [
    {
      "title": "short milestone title (max 8 words)",
      "probability": "85%",
      "progress": 0.85,
      "color": "green"             // "green" or "gold"
    },
    {
      "title": "second milestone",
      "probability": "62%",
      "progress": 0.62,
      "color": "gold"
    },
    {
      "title": "third milestone",
      "probability": "45%",
      "progress": 0.45,
      "color": "gold"
    }
  ],
  "overallInsight": "2-3 sentences overall AI insight",
  "footerText": "short disclaimer like 'Based on current spending habits and market trends. Not financial advice.'"
}

Make the goal predictions realistic based on the affordability and savings rate. The milestones should be financial achievements (e.g., 'Emergency fund fully funded', 'Investment portfolio reaches $10k').
Return ONLY the JSON.`.trim();

    let future;
    try {
      const { text } = await callAI(prompt, null, true);
      future = extractJson(text);
      if (!future.title || !future.goals) throw new Error('Incomplete AI response');
    } catch (err) {
      console.error('❌ AI failed for your-future:', err.message);
      // Fallback with reasonable defaults
      future = {
        title: 'Your Future',
        subtitle: 'Where your money is taking you',
        goals: [
          {
            icon: 'home',
            title: goalData[0]?.name || 'Dream Home',
            confidence: 'High Confidence',
            confidenceBgColor: '0xFFD1FAE5',
            confidenceTextColor: '0xFF065F46',
            completion: 'Mar 2026',
            completionExtra: 'on track',
            completionColor: '0xFF059669',
            insight: 'Based on your current savings rate, this goal is on track.',
            insightBgColor: '0xFFD1FAE5',
            insightIconColor: '0xFF059669',
            insightIcon: 'security'
          },
          ...(goalData[1] ? [{
            icon: 'flight_takeoff',
            title: goalData[1].name || 'Vacation',
            confidence: 'Moderate',
            confidenceBgColor: '0xFFFEF3C7',
            confidenceTextColor: '0xFFB45309',
            completion: 'Sep 2025',
            completionExtra: null,
            completionColor: '0xFF1A1A2E',
            insight: 'You may need to increase contributions slightly to stay on track.',
            insightBgColor: '0xFFFEF3C7',
            insightIconColor: '0xFFD97706',
            insightIcon: 'warning'
          }] : [])
        ],
        milestonesTitle: 'Probability Milestones',
        milestones: [
          { title: 'Emergency fund fully funded', probability: '85%', progress: 0.85, color: 'green' },
          { title: 'Investment portfolio reaches $10k', probability: '62%', progress: 0.62, color: 'gold' },
          { title: 'Debt-free by end of year', probability: '45%', progress: 0.45, color: 'gold' }
        ],
        overallInsight: 'You are building a solid financial foundation. Keep automating your savings for the best chance at achieving these milestones.',
        footerText: 'Based on current spending habits and market trends. Not financial advice.'
      };
    }

    res.json(future);
  } catch (err) {
    console.error('YOUR FUTURE ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});







app.get('/api/patterns', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const intents = await Intent.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const now = new Date();
    const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const prevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const prevMonthKey = `${prevMonth.getFullYear()}-${String(prevMonth.getMonth() + 1).padStart(2, '0')}`;

    // Daily spending averages (for weekend alert bars)
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const dayTotals = Object.fromEntries(days.map(d => [d, 0]));
    const dayCounts = Object.fromEntries(days.map(d => [d, 0]));

    intents.forEach(i => {
      const d = days[new Date(i.createdAt).getDay()];
      dayTotals[d] += i.amount;
      dayCounts[d] += 1;
    });

    const dailyAvgs = days.map(d => dayCounts[d] ? dayTotals[d] / dayCounts[d] : 0);
    const maxAvg = Math.max(...dailyAvgs, 1);

    const barData = days.map((d, i) => ({
      day: d,
      height: Math.round((dailyAvgs[i] / maxAvg) * 16),
      color: dailyAvgs[i] === maxAvg ? '0xFFEF4444' : '0xFFE5E7EB',
    }));

    // Category trends
    const catMap = { food: 'Food', transport: 'Transport', entertainment: 'Entertainment' };
    const catSpending = [
      { key: 'food', label: 'Food', current: profile.food || 0 },
      { key: 'transport', label: 'Transport', current: profile.transport || 0 },
      { key: 'entertainment', label: 'Entertainment', current: profile.entertainment || 0 },
    ];

    const prevIntents = intents.filter(i => {
      const d = new Date(i.createdAt);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` === prevMonthKey;
    });
    const prevCatTotals = { food:0, transport:0, entertainment:0 };
    prevIntents.forEach(i => {
      if (catMap[i.category]) prevCatTotals[i.category] += i.amount;
    });

    const currIntents = intents.filter(i => {
      const d = new Date(i.createdAt);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` === currentMonth;
    });
    const currCatTotals = { food:0, transport:0, entertainment:0 };
    currIntents.forEach(i => {
      if (catMap[i.category]) currCatTotals[i.category] += i.amount;
    });

    const trendItems = catSpending.map(cat => {
      const prev = prevCatTotals[cat.key] || cat.current * 0.9;
      const curr = currCatTotals[cat.key] || cat.current;
      const diff = prev > 0 ? ((curr - prev) / prev) * 100 : 0;
      const isUp = diff > 5 ? true : (diff < -5 ? false : null);
      return {
        title: cat.label,
        trend: `${diff > 0 ? '+' : ''}${Math.round(diff)}% vs last month`,
        isUp: isUp,
        imageUrl: null,
      };
    });

    // Heatmap colours (corrected JavaScript)
    const heatColors = days.map((d, i) => {
      const ratio = maxAvg > 0 ? dailyAvgs[i] / maxAvg : 0;
      const r = Math.round(239 * ratio);
      const g = Math.round(68 + (187 * (1 - ratio)));
      const b = Math.round(68 + (187 * (1 - ratio)));
      return {
        day: d,
        color: `0xFF${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`,
      };
    });

    // AI generated text
    const prompt = `
You are a financial behaviour coach. Based on the user's real data below, generate the content for a "Your Patterns" screen.

REAL DATA:
- Daily spending (normalized heights 0-16, day with height 16 is the peak): ${JSON.stringify(barData.map(b => ({ day: b.day, height: b.height })))}
- Category trends this month vs last: ${JSON.stringify(trendItems.map(t => ({ title: t.title, trend: t.trend, isUp: t.isUp })))}
- Heatmap (peak day is the darkest color): ${JSON.stringify(heatColors.map(h => ({ day: h.day, ratio: (parseInt(h.color.slice(4,6),16)/239).toFixed(2) })))}

Output ONLY a JSON object with this exact structure:
{
  "title": "Your Patterns",
  "subtitle": "short subtitle like 'Money moves in cycles'",
  "weekendAlert": {
    "title": "Weekend Alert",
    "badge": "High Spike",
    "description": "1 sentence describing the weekend spending spike, mentioning the peak day if applicable"
  },
  "trendingTitle": "Trending",
  "nudge": {
    "text": "a short, encouraging nudge to improve habits (max 10 words)"
  },
  "heatmap": {
    "title": "Intentionality Heatmap",
    "description": "1 sentence explaining what the heatmap shows"
  }
}
Use the real numbers to make the text specific.`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.title) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for patterns:', err.message);
      ai = {
        title: 'Your Patterns',
        subtitle: 'Money moves in cycles',
        weekendAlert: { title: 'Weekend Alert', badge: 'High Spike', description: 'Your spending peaks on Saturdays.' },
        trendingTitle: 'Trending',
        nudge: { text: 'Keep an eye on weekend spending – small changes add up.' },
        heatmap: { title: 'Intentionality Heatmap', description: 'Darker days mean higher spending.' }
      };
    }

    res.json({
      title: ai.title,
      subtitle: ai.subtitle,
      weekendAlert: {
        ...ai.weekendAlert,
        bars: barData,
      },
      trendingTitle: ai.trendingTitle,
      trendItems,
      nudge: ai.nudge,
      heatmap: {
        ...ai.heatmap,
        days: heatColors,
      },
    });
  } catch (err) {
    console.error('PATTERNS ENDPOINT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/api/your-patterns', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    // (Optional) compute real stress bars: find the day with highest average spending
    const intents = await Intent.find({ userId: req.userId });
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const dayTotals = { Sun:0, Mon:0, Tue:0, Wed:0, Thu:0, Fri:0, Sat:0 };
    const dayCounts = { Sun:0, Mon:0, Tue:0, Wed:0, Thu:0, Fri:0, Sat:0 };

    intents.forEach(i => {
      const day = days[new Date(i.createdAt).getDay()];
      dayTotals[day] += i.amount;
      dayCounts[day] += 1;
    });

    const dayAvg = {};
    for (const d of days) {
      dayAvg[d] = dayCounts[d] > 0 ? dayTotals[d] / dayCounts[d] : 0;
    }
    const maxAvg = Math.max(...Object.values(dayAvg), 1);
    // Normalize to percentages for the bar chart
    const chartBars = days.map(d => ({
      day: d,
      percent: Math.round((dayAvg[d] / maxAvg) * 100) / 100,  // 0.0 – 1.0
      color: dayAvg[d] === maxAvg ? '0xFFEF4444' : '0xFFD1D5DB'  // red for highest, grey otherwise
    }));

    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);

    const prompt = `
You are a financial behaviour analyst. Based on the user's real data and spending patterns, generate the content for a "Your Patterns" screen.

USER DATA:
- Monthly income: $${income.toFixed(0)}
- Spending patterns by day of week (percent of max): ${JSON.stringify(chartBars.map(b => ({ day: b.day, percent: b.percent })))}

Output ONLY a JSON object with this exact structure:

{
  "title": "Your Patterns",
  "subtitle": "Recognise your financial behaviours",
  "stressResponse": {
    "title": "Stress Response",
    "correlationLabel": "CORRELATION: r=0.78",
    "description": "1 sentence description linking high spending days to stress. Use the data above to make it specific (mention the peak day).",
    "chartBars": ${JSON.stringify(chartBars)}   // use the real bars we computed
  },
  "paydayEffect": {
    "icon": "credit_card",
    "bgColor": "0xFFD1FAE5",
    "iconColor": "0xFF059669",
    "title": "Payday Effect",
    "badge": "Cash Flow",
    "description": "1 sentence about how spending changes right after payday"
  },
  "socialMultiplier": {
    "icon": "favorite",
    "bgColor": "0xFFFEF3C7",
    "iconColor": "0xFFD97706",
    "title": "Social Multiplier",
    "badge": "High Joy",
    "description": "1 sentence about spending more when with friends"
  },
  "weeklyRhythm": {
    "title": "Weekly Rhythm",
    "description": "1 sentence describing the overall weekly spending pattern"
  },
  "aiCoaching": {
    "title": "AI COACHING",
    "text": "A personalised 1-2 sentence invitation to improve habits, e.g. 'Ready to break the stress-spending loop?'",
    "yesButton": "Yes, please",
    "noButton": "Not yet"
  }
}

Use the real data to make the text specific. The chartBars array must be exactly the one provided (with colors as hex strings). Return ONLY the JSON.`.trim();

    let patterns;
    try {
      const { text } = await callAI(prompt, null, true);
      patterns = extractJson(text);
      if (!patterns.title || !patterns.stressResponse) throw new Error('Incomplete AI response');
    } catch (err) {
      console.error('❌ AI failed for your-patterns:', err.message);
      // Fallback with computed chartBars and static text
      patterns = {
        title: 'Your Patterns',
        subtitle: 'Recognise your financial behaviours',
        stressResponse: {
          title: 'Stress Response',
          correlationLabel: 'CORRELATION: r=0.78',
          description: `You tend to spend the most on ${chartBars.find(b => b.color === '0xFFEF4444')?.day || 'Mondays'}, often linked to stress.`,
          chartBars
        },
        paydayEffect: {
          icon: 'credit_card',
          bgColor: '0xFFD1FAE5',
          iconColor: '0xFF059669',
          title: 'Payday Effect',
          badge: 'Cash Flow',
          description: 'Your spending increases by 20% in the first 3 days after payday.'
        },
        socialMultiplier: {
          icon: 'favorite',
          bgColor: '0xFFFEF3C7',
          iconColor: '0xFFD97706',
          title: 'Social Multiplier',
          badge: 'High Joy',
          description: 'Dining out with friends leads to 30% higher spending than solo meals.'
        },
        weeklyRhythm: {
          title: 'Weekly Rhythm',
          description: 'Weekends account for 40% of your weekly spending.'
        },
        aiCoaching: {
          title: 'AI COACHING',
          text: 'Ready to break the stress-spending loop and build healthier habits?',
          yesButton: 'Yes, please',
          noButton: 'Not yet'
        }
      };
    }

    res.json(patterns);
  } catch (err) {
    console.error('YOUR PATTERNS ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



app.get('/api/spending-dna', authenticate, async (req, res) => {
  try {
    const intents = await Intent.find({ userId: req.userId });
    const now = new Date();

    // ── Habits (top 3 categories) ──────────────────────────────────────────
    const catTotals = {};
    intents.forEach(i => {
      const cat = i.category || 'other';
      catTotals[cat] = (catTotals[cat] || 0) + i.amount;
    });
    const sortedCats = Object.entries(catTotals)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);

    // ── Heatmap (4 weeks x 7 days) ─────────────────────────────────────────
    const daysOfWeek = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const startOfWeek = new Date(now);
    startOfWeek.setDate(now.getDate() - now.getDay());
    startOfWeek.setHours(0,0,0,0);

    const heatmap = [];
    for (let w = 0; w < 4; w++) {
      const weekStart = new Date(startOfWeek);
      weekStart.setDate(weekStart.getDate() - w * 7);
      const row = [];
      for (let d = 0; d < 7; d++) {
        const dayStart = new Date(weekStart);
        dayStart.setDate(dayStart.getDate() + d);
        const dayEnd = new Date(dayStart);
        dayEnd.setDate(dayEnd.getDate() + 1);
        const total = intents
          .filter(i => i.createdAt >= dayStart && i.createdAt < dayEnd)
          .reduce((sum, i) => sum + i.amount, 0);
        row.push({ amount: total, date: dayStart });
      }
      heatmap.push(row);
    }

    const allAmounts = heatmap.flat().map(cell => cell.amount);
    const maxAmount = Math.max(...allAmounts, 1);

    // Correctly convert amount to hex colour string
    const getHeatColor = (amount) => {
      const ratio = amount / maxAmount;
      const r = 255;
      const g = Math.round(255 - (130 * ratio));
      const b = Math.round(255 - (200 * ratio));
      // Use toString(16) – JavaScript’s radix conversion
      return `0xFF${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
    };

    const heatmapGrid = heatmap.map(row =>
      row.map(cell => getHeatColor(cell.amount))
    );

    // ── Velocity (this week vs last week) ─────────────────────────────────
    const thisWeekStart = new Date(startOfWeek);
    const lastWeekStart = new Date(startOfWeek);
    lastWeekStart.setDate(lastWeekStart.getDate() - 7);

    const thisWeekTotal = intents
      .filter(i => i.createdAt >= thisWeekStart)
      .reduce((sum, i) => sum + i.amount, 0);
    const lastWeekTotal = intents
      .filter(i => i.createdAt >= lastWeekStart && i.createdAt < thisWeekStart)
      .reduce((sum, i) => sum + i.amount, 0);

    const avgWeeklySpend = lastWeekTotal > 0 ? lastWeekTotal : 1;
    const thisWeekProgress = Math.min(thisWeekTotal / avgWeeklySpend, 1.0);
    const lastWeekProgress = 1.0;
    const velocityPercent = lastWeekTotal > 0
      ? Math.round(((thisWeekTotal - lastWeekTotal) / lastWeekTotal) * 100)
      : 0;

    // ── AI Prompt ──────────────────────────────────────────────────────────
    const prompt = `
You are a financial behaviour analyst. Generate a complete Spending DNA report.

REAL DATA:
- Top categories: ${JSON.stringify(sortedCats)}
- Weekly velocity: this week $${thisWeekTotal.toFixed(2)} vs last week $${lastWeekTotal.toFixed(2)} (${velocityPercent}% change)
- Heatmap (4 weeks x 7 days, values normalised): ${JSON.stringify(heatmap.map(row => row.map(c => c.amount.toFixed(2))))}

Output ONLY a JSON object with this exact structure:

{
  "title": "Your Spending DNA",
  "subtitle": "The patterns that shape your wallet",
  "habitsHeader": "Recurring Habits",
  "heatmapHeader": "Spending Heatmap",
  "heatmapInsight": "1 sentence about what the heatmap shows (mention peak days/weeks)",
  "velocityHeader": "Weekly Spending Velocity",
  "velocityPercent": "${velocityPercent > 0 ? '+' : ''}${velocityPercent}%",
  "velocityLabel": "vs last week",
  "lastWeekLabel": "Last Week",
  "thisWeekLabel": "This Week",
  "mindfulInsight": "A 2-3 sentence mindful insight about the user's spending patterns",
  "habits": [
    {
      "title": "short habit name (max 4 words)",
      "description": "1 sentence description grounded in the real category",
      "icon": "Material icon name (coffee, shopping_basket, etc.)",
      "iconBgColor": "0xFFE0F2F1",
      "iconColor": "0xFF1C886F"
    }
    // exactly 3 habits
  ]
}

Make everything specific and grounded in the real numbers.`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.habits || !ai.heatmapInsight) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for spending-dna:', err.message);
      const fallbackIcons = ['coffee', 'shopping_basket', 'lightbulb_outline'];
      const fallbackColors = [
        { bg: '0xFFE0F2F1', fg: '0xFF1C886F' },
        { bg: '0xFFFFF8E1', fg: '0xFFF4A22E' },
        { bg: '0xFFFFEBEE', fg: '0xFFEF5350' },
      ];
      ai = {
        title: 'Your Spending DNA',
        subtitle: 'The patterns that shape your wallet',
        habitsHeader: 'Recurring Habits',
        heatmapHeader: 'Spending Heatmap',
        heatmapInsight: 'Weekends are your highest spending days.',
        velocityHeader: 'Weekly Spending Velocity',
        velocityPercent: `${velocityPercent > 0 ? '+' : ''}${velocityPercent}%`,
        velocityLabel: 'vs last week',
        lastWeekLabel: 'Last Week',
        thisWeekLabel: 'This Week',
        mindfulInsight: 'Your weekend spending tends to spike. Try setting a small Saturday budget.',
        habits: sortedCats.map((cat, i) => ({
          title: cat[0].charAt(0).toUpperCase() + cat[0].slice(1),
          description: `You've spent $${cat[1].toFixed(0)} in this category.`,
          icon: fallbackIcons[i % fallbackIcons.length],
          iconBgColor: fallbackColors[i % fallbackColors.length].bg,
          iconColor: fallbackColors[i % fallbackColors.length].fg,
        }))
      };
    }

    // Combine everything
    res.json({
      ...ai,
      heatmapGrid,
      velocityLastWeekProgress: lastWeekProgress,
      velocityThisWeekProgress: thisWeekProgress,
      velocityPercent: ai.velocityPercent,
    });
  } catch (err) {
    console.error('SPENDING DNA ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});


app.get('/api/goal-impact', authenticate, async (req, res) => {
  try {
    const goals = await Goal.find({ userId: req.userId }).sort({ priority: -1 }).limit(1);
    const profile = await Profile.findOne({ userId: req.userId });
    if (!goals.length) return res.status(404).json({ error: 'No active goal found' });

    const goal = goals[0];
    const target = goal.targetAmount || 0;
    const saved = goal.existingSavings || 0;
    const monthly = goal.monthlyContribution || (profile ? (profile.primarySalary || 0) * 0.2 : 0);
    const monthsLeft = target > saved ? Math.ceil((target - saved) / monthly) : 0;
    const now = new Date();

    // ── Compute projection lines (for chart) ──────────────────────────────────
    const months = 24; // look ahead 24 months
    const svgWidth = 300, svgHeight = 120;
    const buildLine = (contribution) => {
      const points = [];
      let current = saved;
      for (let m = 0; m <= months; m++) {
        const x = (m / months) * svgWidth;
        const progress = Math.min(current / target, 1);
        const y = svgHeight - 10 - progress * (svgHeight - 20); // y=110 (bottom) at 0%, y=10 (top) at 100%
        points.push([x, y]);
        current = Math.min(current + contribution, target);
      }
      return points;
    };

    const currentLine = buildLine(monthly);
    const optimisticLine = buildLine(monthly + 200);  // +200 / mo scenario
    const conservativeLine = buildLine(Math.max(monthly - 200, 0)); // -200 / mo scenario

    // ── AI generated text ────────────────────────────────────────────────────
    const prompt = `
You are a goal coach. Based on the user's real goal, generate a "Goal Impact" report.

REAL DATA:
- Goal: ${goal.name || goal.goalType}
- Target: $${target.toFixed(0)}
- Current savings: $${saved.toFixed(0)}
- Monthly contribution: $${monthly.toFixed(0)}
- Projected completion: ${monthsLeft} months from now (approx.)

Output ONLY a JSON object with this exact structure:
{
  "title": "Goal Impact",
  "subtitle": "How your decisions shape your future",
  "dreamHomeTarget": "short goal name (max 3 words)",
  "targetAmount": "$${target.toFixed(0)}",
  "weeklySummaryTitle": "This Week's Impact",
  "weeklySummaryText": "1 short sentence about the effect of this week's actions on the goal",
  "decisionHighlightsTitle": "Decision Highlights",
  "decisions": [
    {
      "title": "short decision title (max 5 words)",
      "desc": "1 sentence description",
      "impact": "e.g. +3 days",
      "isPositive": true
    },
    {
      "title": "another decision",
      "desc": "description",
      "impact": "e.g. -2 days",
      "isPositive": false
    },
    {
      "title": "third decision",
      "desc": "description",
      "impact": "e.g. +5 days",
      "isPositive": true
    }
  ],
  "insightBannerText": "1-2 sentence insight about small changes leading to big results"
}
Make all text specific to the goal and the numbers.`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.decisions || !ai.insightBannerText) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for goal-impact:', err.message);
      ai = {
        title: 'Goal Impact',
        subtitle: 'How your decisions shape your future',
        dreamHomeTarget: goal.name || goal.goalType,
        targetAmount: `$${target.toFixed(0)}`,
        weeklySummaryTitle: "This Week's Impact",
        weeklySummaryText: `You moved ${monthly > 0 ? '+' : ''}$${monthly.toFixed(0)} closer to your goal.`,
        decisionHighlightsTitle: 'Decision Highlights',
        decisions: [
          { title: 'Cooked at home', desc: 'Saved $40 by skipping takeout', impact: '+2 days', isPositive: true },
          { title: 'Impulse buy', desc: 'Bought a gadget on sale', impact: '-1 day', isPositive: false },
          { title: 'Extra shift', desc: 'Picked up a weekend gig', impact: '+5 days', isPositive: true },
        ],
        insightBannerText: 'Small daily choices add up to months of earlier freedom.'
      };
    }

    res.json({
      ...ai,
      chartLines: {
        current: currentLine,
        optimistic: optimisticLine,
        conservative: conservativeLine,
      },
      weeklySummaryTitle: ai.weeklySummaryTitle,
      weeklySummaryText: ai.weeklySummaryText,
      decisionHighlightsTitle: ai.decisionHighlightsTitle,
      decisions: ai.decisions,
    });
  } catch (err) {
    console.error('GOAL IMPACT ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});





app.get('/api/habit-trends', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const intents = await Intent.find({ userId: req.userId });
    const now = new Date();
    
    // Generate last 6 months
    const months = [];
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({
        key: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`,
        label: d.toLocaleString('default', { month: 'short' }),
      });
    }

    const snapshots = await MonthlySnapshot.find({
      userId: req.userId,
      monthKey: { $in: months.map(m => m.key) }
    });

    const snapshotMap = {};
    snapshots.forEach(s => { snapshotMap[s.monthKey] = s; });

    const impulseCategories = ['entertainment', 'food', 'shopping'];
    const savingsData = [];
    const impulseData = [];

    // 🔧 FIXED: use (month, i) to get the index
    months.forEach((month, i) => {
      const snap = snapshotMap[month.key];
      const income = snap ? snap.income : (profile ? (profile.primarySalary || 0) + (profile.sideIncome || 0) : 0);
      const expenses = snap ? snap.expenses : (profile ? (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0) : 0);
      const savings = Math.max(income - expenses, 0);
      savingsData.push(savings);

      // Impulse spending from intents this month
      const monthStart = new Date(now.getFullYear(), now.getMonth() - (5 - i), 1);
      const monthEnd = new Date(monthStart.getFullYear(), monthStart.getMonth() + 1, 0, 23, 59, 59);
      const impulseTotal = intents
        .filter(intent => {
          const created = new Date(intent.createdAt);
          return created >= monthStart && created <= monthEnd && impulseCategories.includes(intent.category);
        })
        .reduce((sum, intent) => sum + intent.amount, 0);
      impulseData.push(impulseTotal);
    });

    // Scale to viewBox 300x120
    const maxSavings = Math.max(...savingsData, 1);
    const minSavings = Math.min(...savingsData, 0);
    const maxImpulse = Math.max(...impulseData, 1);
    const minImpulse = Math.min(...impulseData, 0);

    const mapToView = (value, min, max, lowY, highY) => {
      if (max === min) return lowY;
      const ratio = (value - min) / (max - min);
      return lowY + ratio * (highY - lowY);
    };

    const greenPoints = savingsData.map((val, i) => {
      const x = 10 + (280 / 5) * i;
      const y = mapToView(val, minSavings, maxSavings, 95, 25);
      return { x, y: Math.round(y) };
    });

    const yellowPoints = impulseData.map((val, i) => {
      const x = 10 + (280 / 5) * i;
      const y = mapToView(val, minImpulse, maxImpulse, 32, 100);
      return { x, y: Math.round(y) };
    });

    // AI prompt
    const prompt = `
You are a financial habit coach. Generate a "Habit Trends" report for the user based on their real data.

REAL DATA:
- Last 6 months savings (newest last): ${JSON.stringify(savingsData)}
- Last 6 months impulse spending (newest last): ${JSON.stringify(impulseData)}
- Current month label: ${months[months.length-1].label}

Output ONLY a JSON object with this exact structure:
{
  "title": "Your Habit Trends",
  "subtitle": "How your money habits are evolving",
  "chartTitle": "Savings vs Impulse",
  "chartRange": "Last 6 months",
  "aiSummaryTitle": "AI Insight",
  "aiSummaryText": "1-2 sentence insight about the trend, mentioning the biggest change",
  "milestonesTitle": "Recent Milestones",
  "milestones": [
    {
      "date": "short date like 'Apr 3'",
      "title": "short milestone title",
      "desc": "one sentence description",
      "icon": "emoji_events"
    },
    {
      "date": "short date",
      "title": "title",
      "desc": "description",
      "icon": "local_fire_department"
    },
    {
      "date": "short date",
      "title": "title",
      "desc": "description",
      "icon": "add"
    }
  ],
  "infoBannerText": "1 sentence about how habits are tracked"
}`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.title || !ai.milestones) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for habit-trends:', err.message);
      ai = {
        title: 'Your Habit Trends',
        subtitle: 'How your money habits are evolving',
        chartTitle: 'Savings vs Impulse',
        chartRange: 'Last 6 months',
        aiSummaryTitle: 'AI Insight',
        aiSummaryText: 'Your savings are steadily growing while impulse spending is declining.',
        milestonesTitle: 'Recent Milestones',
        milestones: [
          { date: 'Apr 3', title: 'Saved First $1,000', desc: 'Reached your emergency fund milestone.', icon: 'emoji_events' },
          { date: 'May 15', title: '50% Less Impulse Buys', desc: 'Significantly reduced unplanned spending.', icon: 'local_fire_department' },
          { date: 'Jun 20', title: 'Invested in Growth', desc: 'Opened your first investment account.', icon: 'add' },
        ],
        infoBannerText: 'Habits are tracked using your actual spending and savings patterns over time.'
      };
    }

    res.json({
      ...ai,
      greenPoints,
      yellowPoints,
      xLabels: months.map(m => m.label),
    });
  } catch (err) {
    console.error('HABIT TRENDS ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});


app.get('/api/badges', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    // ---- Compute XP & Level (simple logic) ----
    const completed = profile.completedSteps || 0;
    const totalTasks = profile.completedTasks?.length || 0;
    const xp = completed * 50 + totalTasks * 10;   // example calculation
    const level = Math.floor(xp / 500) + 1;
    const xpForNextLevel = level * 500;
    const xpProgress = Math.min(xp / xpForNextLevel, 1);

    // ---- Compute streaks (using profile.createdAt as first active day) ----
    const firstDay = profile.createdAt || new Date();
    const now = new Date();
    const diffDays = Math.floor((now - firstDay) / (1000 * 60 * 60 * 24));
    const currentStreak = Math.min(diffDays, 7);   // cap at 7 for demo
    const longestStreak = currentStreak;            // you can store this in profile

    // ---- Badge definitions (static list, but you can extend via DB) ----
    const allBadges = [
  { id: 'first_goal',  title: 'First Goal',     desc: 'Set your first financial goal',    imageUrl: 'https://lh3.googleusercontent.com/.../badge1.png' },
  { id: 'saver_starter', title: 'Saver Starter',  desc: 'Save $500 in your first month',     imageUrl: 'https://lh3.googleusercontent.com/.../badge2.png' },
  { id: 'budget_master', title: 'Budget Master',  desc: 'Stay under budget for 3 months',    imageUrl: 'https://lh3.googleusercontent.com/.../badge3.png' },
  { id: 'goal_crusher', title: 'Goal Crusher',    desc: 'Achieve 80% of a goal target',      imageUrl: 'https://lh3.googleusercontent.com/.../badge4.png' },
  { id: 'streak_7',     title: '7 Day Streak',    desc: 'Log spending for 7 days in a row',  imageUrl: 'https://lh3.googleusercontent.com/.../badge5.png' },
  { id: 'frugal_hero',  title: 'Frugal Hero',     desc: 'Reduce discretionary spending by 20%', imageUrl: 'https://lh3.googleusercontent.com/.../badge6.png' },
];

    // Determine which badges are earned (simplified logic)
    const earned = new Set();
    if (goals.length > 0) earned.add('first_goal');
    const savingsRate = profile.primarySalary ? ((profile.cashSavings || 0) / profile.primarySalary) : 0;
    if (savingsRate >= 0.1) earned.add('saver_starter');
    if (profile.completedSteps >= 3) earned.add('budget_master');
    const primaryGoal = goals.sort((a,b) => (b.priority||0)-(a.priority||0))[0];
    if (primaryGoal && primaryGoal.targetAmount > 0) {
      const progress = (primaryGoal.existingSavings || 0) / primaryGoal.targetAmount;
      if (progress >= 0.8) earned.add('goal_crusher');
    }
    if (totalTasks >= 7) earned.add('streak_7');
    const ent = profile.entertainment || 0;
    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    if (income > 0 && (ent / income) < 0.05) earned.add('frugal_hero');

    const badges = allBadges.map(b => ({
      title: b.title,
      desc: b.desc,
      imageUrl: b.imageUrl,
      locked: !earned.has(b.id)
    }));

    // ---- AI‑generated achievement banner ----
    const prompt = `
You are a motivating financial coach. Write a short achievement banner for a user's badge collection.
Real data:
- Level: ${level}
- XP: ${xp} (progress ${Math.round(xpProgress*100)}%)
- Earned badges: ${earned.size} / ${allBadges.length}
- Current streak: ${currentStreak} days

Output ONLY a JSON object:
{
  "achievementTitle": "short inspiring title (max 6 words)",
  "achievementDesc": "1 sentence describing the recent achievement (max 12 words)"
}`.trim();

    let ai = {};
    try {
      const { text } = await callAI(prompt, null, true);
      ai = extractJson(text);
      if (!ai.achievementTitle) throw new Error('Incomplete AI');
    } catch (err) {
      console.error('AI fallback for badges:', err.message);
      ai = {
        achievementTitle: 'On a Roll!',
        achievementDesc: 'You just unlocked a new badge – keep it up!'
      };
    }

    res.json({
      levelTitle: `Level ${level}`,
      xpText: `${xp} XP`,
      xpProgress,
      earnedCount: earned.size,
      currentStreak,
      longestStreak,
      achievementTitle: ai.achievementTitle,
      achievementDesc: ai.achievementDesc,
      badges,
      // static header texts (can also be AI‑generated)
      headerTitle: 'Your Badges',
      headerSubtitle: 'Collect them all',
      trophyRoom: 'Trophy Room'
    });
  } catch (err) {
    console.error('BADGES ERROR:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});




app.get('/api/subscriptions', authenticate, async (req, res) => {
  try {
    const intents = await Intent.find({ userId: req.userId }).sort({ createdAt: -1 });
    
    // Detect recurring transactions (simplified)
    const recurringCandidates = {};
    const subscriptionCategories = ['entertainment', 'software', 'health', 'education'];
    intents.forEach(i => {
      if (subscriptionCategories.includes(i.category)) {
        const key = i.place || i.note || i.category;
        if (!recurringCandidates[key]) recurringCandidates[key] = { count: 0, total: 0, category: i.category };
        recurringCandidates[key].count++;
        recurringCandidates[key].total += i.amount;
      }
    });

    const recurring = Object.values(recurringCandidates).filter(c => c.count >= 2);
    let subscriptions;

    if (recurring.length >= 1) {
      subscriptions = recurring.map((r, i) => ({
        name: r.category.charAt(0).toUpperCase() + r.category.slice(1),
        price: `$${(r.total / r.count).toFixed(0)}/mo`,
        renewsOn: 'Next billing cycle',
        usageLevel: i % 3 === 0 ? 'high' : i % 3 === 1 ? 'medium' : 'low',
        usageLabel: i % 3 === 0 ? 'Daily use' : i % 3 === 1 ? 'Weekly use' : 'Rarely used',
        potentialSaving: i === 1,
        icon: r.category === 'entertainment' ? 'netflix' : r.category === 'health' ? 'gym' : 'spotify'
      }));
    } else {
      // Fallback if no recurring intents
      subscriptions = [
        { name: 'Netflix', price: '$15/mo', renewsOn: 'Monthly', usageLevel: 'high', usageLabel: 'Daily use', potentialSaving: false, icon: 'netflix' },
        { name: 'Spotify', price: '$10/mo', renewsOn: 'Monthly', usageLevel: 'high', usageLabel: 'Daily use', potentialSaving: false, icon: 'spotify' },
      ];
    }

    const total = subscriptions.reduce((sum, s) => sum + parseFloat(s.price.replace(/[^0-9.]/g, '')), 0);
    const categories = subscriptions.map(s => ({
      label: s.name,
      amount: s.price,
      percent: total > 0 ? parseFloat(s.price.replace(/[^0-9.]/g, '')) / total : 1/subscriptions.length,
    }));

    res.json({
      title: 'Subscriptions',
      subtitle: 'Track and optimize your recurring payments',
      totalAmount: `$${total.toFixed(0)}`,
      activeCount: `${subscriptions.length} active`,
      activeSubscriptionsTitle: 'Active Subscriptions',
      categories,
      items: subscriptions,
      aiOptimizationTitle: 'AI Optimization',
      aiOptimizationText: 'You could save by reviewing your rarely used subscriptions.',
    });
  } catch (err) {
    console.error('SUBSCRIPTIONS ERROR:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  HEALTH CHECK & ERROR HANDLING
// ══════════════════════════════════════════════════════════════════════════════

app.get('/', (_req, res) => {
  res.json({
    message: 'FinPath API is running',
    dbState: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState] || 'unknown',
    firebase: admin.apps.length > 0 ? 'initialised' : 'not initialised',
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured',
  });
});

app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    mongo:     mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    firebase:  admin.apps.length > 0 ? 'initialised' : 'not initialised',
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured',
    time:      new Date().toISOString(),
  });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError)
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  if (err.message && err.message.startsWith('Only '))
    return res.status(400).json({ error: err.message });
  next(err);
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed')
    return res.status(400).json({ error: 'Invalid JSON body.' });
  next(err);
});

app.use((req, res) => res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` }));

app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start server (local only) ──────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Local server running on port ${PORT}`));
}

module.exports = app;
