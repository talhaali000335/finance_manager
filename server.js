const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ─── Environment Variables ──────────────────────────
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/finpath';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ─── MongoDB Connection ─────────────────────────────
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ─── User Model (Auth) ──────────────────────────────
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ─── Profile Model (Financial Data) ─────────────────
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

// ─── JWT Helpers ────────────────────────────────────
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// ─── Auth Middleware (Protected Routes) ─────────────
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

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

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

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const token = generateToken(user._id);
    res.json({
      message: 'Login successful.',
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// GET current user (protected)
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PROFILE ROUTES (Protected) ─────────────────────

const authorizeProfileAccess = (req, res, next) => {
  if (req.params.userId !== req.userId) {
    return res.status(403).json({ error: 'You can only access your own profile.' });
  }
  next();
};

// GET profile
app.get('/api/profile/:userId', authenticate, authorizeProfileAccess, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.params.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found.' });
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH profile (partial update)
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

// PUT profile (full replace)
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

// Health check
app.get('/', (req, res) => res.send('FinPath API is running'));

async function startServer() {
  try {
    // Wait until the database is actually connected
    await mongoose.connect(MONGODB_URI);
    console.log('✅ MongoDB connected');

    // Only then start accepting requests
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err);
    process.exit(1); // crash the function so Vercel can report the error
  }
}

startServer();
