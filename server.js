const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/finpath';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ─── Log redacted URI for debugging ────────────────
if (process.env.MONGODB_URI) {
  const redacted = MONGODB_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@');
  console.log('🔎 Using MONGODB_URI:', redacted);
} else {
  console.warn('⚠️  MONGODB_URI env var is NOT set – falling back to localhost');
}

// ─── MongoDB Connection (cached) ──────────────────
let isConnected = false;

async function connectDB() {
  if (isConnected && mongoose.connection.readyState === 1) return;
  try {
    await mongoose.connect(MONGODB_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 10000,
    });
    isConnected = true;
    console.log('✅ MongoDB connected');
  } catch (err) {
    isConnected = false;
    console.error('❌ MongoDB connection failed:', err.message);
    if (err.message.includes('bad auth')) console.error('   → Username/password incorrect or needs URL-encoding');
    if (err.message.includes('ENOTFOUND') || err.message.includes('querySrv')) console.error('   → Cluster hostname wrong');
    if (err.message.includes('timed out') || err.message.includes('ETIMEDOUT')) console.error('   → IP allow-list issue – add 0.0.0.0/0 in Atlas');
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

// ─── User Model ─────────────────────────────────────
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 12);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ─── Profile Model ──────────────────────────────────
const profileSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
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
}, { timestamps: true });

const Profile = mongoose.model('Profile', profileSchema);

// ─── Goal Model ─────────────────────────────────────
const goalSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  goalType: { type: String, enum: ['home', 'car', 'education', 'custom'], required: true },
  name: { type: String, default: '' },
  targetAmount: { type: Number, required: true },
  targetDate: { type: Date, required: true },
  priority: { type: Number, min: 1, max: 5, default: 3 },
  monthlyContribution: { type: Number, default: 0 },
  existingSavings: { type: Number, default: 0 },
  autoTransfer: { type: Boolean, default: false },
  riskTolerance: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'conservative' },
}, { timestamps: true });

const Goal = mongoose.model('Goal', goalSchema);

// ─── JWT Helpers ────────────────────────────────────
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// ─── Auth Middleware (must be defined BEFORE routes) ──
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

// ─── AUTH ROUTES ────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ error: 'Email already registered.' });

    const user = new User({ name, email, password });
    await user.save();
    const token = generateToken(user._id);
    res.status(201).json({
      message: 'User created successfully.',
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error('SIGNUP ERROR:', err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = generateToken(user._id);
    res.json({
      message: 'Login successful.',
      token,
      user: { id: user._id, name: user.name, email: user.email },
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

// ─── GOAL ROUTES ────────────────────────────────────
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

// GET all goals for the authenticated user
app.get('/api/goals', authenticate, async (req, res) => {
  try {
    const goals = await Goal.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(goals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─── PROFILE ROUTES ─────────────────────────────────
const authorizeProfileAccess = (req, res, next) => {
  if (req.params.userId !== req.userId) return res.status(403).json({ error: 'You can only access your own profile.' });
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

// ─── Health check ───────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    message: 'FinPath API is running',
    dbState: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState] || 'unknown',
  });
});

// ─── Export for Vercel ──────────────────────────────
module.exports = app;
