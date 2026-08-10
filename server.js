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
    const profile = await Profile.findOne({ userId: req.userId });
    const goals   = await Goal.find({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income   = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const savings  = Math.max(income - expenses, 0);
    const savingsRate = income > 0 ? Math.round((savings / income) * 100) : 0;

    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const snapshots = await MonthlySnapshot.find({ userId: req.userId }).sort({ monthKey: -1 }).limit(6);
    const orderedSnapshots = snapshots.reverse();
    const monthlySavings = orderedSnapshots.map(s => Math.max(s.income - s.expenses, 0));

    const intents = await Intent.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(100);
    const categoryTotals = {};
    for (const i of intents) {
      categoryTotals[i.category] = (categoryTotals[i.category] || 0) + i.amount;
    }
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

Output ONLY a JSON object with this exact structure:
{
  "bestDayPrefix": "text before the highlighted day, e.g. 'You save the most on '",
  "bestDayHighlight": "the day name, bold-worthy short phrase",
  "bestDaySuffix": "text after, e.g. ' — keep that pattern going.'",
  "coffeePrefix": "text before the highlighted category insight",
  "coffeeHighlight": "short highlighted phrase about the top category",
  "coffeeSuffix": "text after"
}`.trim();

    let aiInsights;
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
      monthlyTrend: monthlySavings.length ? monthlySavings : [0, 0, 0, 0, 0, 0],
      months: orderedSnapshots.map(s => s.monthKey.split('-')[1]),
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
