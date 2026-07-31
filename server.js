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

// ─── Log a safe version of the URI ──────────────────
if (process.env.MONGODB_URI) {
  const redacted = MONGODB_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@');
  console.log('🔎 Using MONGODB_URI:', redacted);
} else {
  console.warn('⚠️  MONGODB_URI env var is NOT set – falling back to localhost');
}

// ─── MongoDB connection (cached across invocations) ──
let cachedConnection = null;

async function connectDB() {
  if (cachedConnection && mongoose.connection.readyState === 1) {
    return cachedConnection;
  }
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
    if (err.message.includes('bad auth')) console.error('   → Username/password incorrect or needs URL-encoding');
    if (err.message.includes('ENOTFOUND') || err.message.includes('querySrv')) console.error('   → Cluster hostname wrong');
    if (err.message.includes('timed out') || err.message.includes('ETIMEDOUT')) console.error('   → IP allow-list issue – add 0.0.0.0/0 in Atlas');
    throw err;
  }
}

// Gate every request on a live connection
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

// ─── Linked Accounts Model ─────────────────────────
const linkedAccountSchema = new mongoose.Schema({
  userId:          { type: String, required: true },
  institutionName: { type: String, required: true },
  accountType:     { type: String, default: 'checking' },
  lastFour:        { type: String, default: '0000' },
  balance:         { type: Number, default: 0 },
  logoUrl:         { type: String, default: '' },
}, { timestamps: true });

const LinkedAccount = mongoose.model('LinkedAccount', linkedAccountSchema);

// ─── Monthly Snapshot Model ──────────────────────
const monthlySnapshotSchema = new mongoose.Schema({
  userId:    { type: String, required: true },
  monthKey:  { type: String, required: true },
  income:    { type: Number, default: 0 },
  expenses:  { type: Number, default: 0 },
}, { timestamps: true });

monthlySnapshotSchema.index({ userId: 1, monthKey: 1 }, { unique: true });

const MonthlySnapshot = mongoose.model('MonthlySnapshot', monthlySnapshotSchema);

// ─── Profile Model ─────────────────────────────────
const profileSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  profilePicture: { type: String, default: '' },
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
}, { timestamps: true });

const Profile = mongoose.model('Profile', profileSchema);

// ─── Goal Model ─────────────────────────────────────
const goalSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  goalType: {
    type: String,
    enum: ['home', 'car', 'education', 'custom', 'vacation', 'business', 'savings', 'emergency_fund'],
    required: true,
  },
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

// ─── Subscription Model ────────────────────────────
const subscriptionSchema = new mongoose.Schema({
  userId:           { type: String, required: true, unique: true },
  plan:             { type: String, enum: ['monthly', 'yearly', 'none'], default: 'none' },
  active:           { type: Boolean, default: false },
  startDate:        { type: Date },
  endDate:          { type: Date },
  cancelAtPeriodEnd:{ type: Boolean, default: false },
}, { timestamps: true });

const Subscription = mongoose.model('Subscription', subscriptionSchema);

// ─── JWT Helpers ────────────────────────────────────
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// ─── Auth Middleware ─────────────────────────────────
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

// ✅ Signup – now creates a blank profile
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

    // ✅ Auto-create profile for the new user
    await Profile.create({ userId: user._id });

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

// ✅ Login – ensures profile exists
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

    // ✅ Upsert profile – creates if missing, does nothing if already exists
    await Profile.findOneAndUpdate(
      { userId: user._id },
      { $setOnInsert: { userId: user._id } },
      { upsert: true, new: true }
    );

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

// ─── ACTION PLAN ENDPOINT ───────────────────────────
app.get('/api/action-plan', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const goals = await Goal.find({ userId: req.userId });

    const now = new Date();
    const totalMonths = 24;
    const monthsElapsed = Math.min(
      Math.floor((now - new Date(profile?.createdAt || now)) / (30 * 24 * 3600 * 1000)),
      totalMonths
    );
    const progress = monthsElapsed / totalMonths;

    const completedSet = new Set(profile?.completedTasks ?? []);

    const currentMonthTasks = [];
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    if (primaryGoal) {
      const goalName = primaryGoal.name || primaryGoal.goalType;
      const neededMonthly = Math.ceil(
        (primaryGoal.targetAmount - (primaryGoal.existingSavings || 0)) / totalMonths
      );

      const saveTaskTitle = `Save \$${neededMonthly} to ${goalName}`;
      currentMonthTasks.push({
        title: saveTaskTitle,
        description: `Keeps you aligned for your ${goalName} target.`,
        hasInfo: true,
        spending: null,
        completed: completedSet.has(saveTaskTitle),
      });

      const moveTaskTitle = `Move \$${Math.ceil(neededMonthly * 0.4)} to Business Seed Account`;
      currentMonthTasks.push({
        title: moveTaskTitle,
        description: 'Scheduled automated transfer.',
        hasInfo: false,
        spending: null,
        completed: completedSet.has(moveTaskTitle),
      });

      const spendingLimit = primaryGoal.monthlyContribution > 0
        ? primaryGoal.monthlyContribution
        : Math.ceil(((profile?.primarySalary || 0) + (profile?.sideIncome || 0)) * 0.3);
      const spendTaskTitle = `Review discretionary spending (limit to \$${spendingLimit})`;
      currentMonthTasks.push({
        title: spendTaskTitle,
        description: '',
        hasInfo: false,
        spending: {
          spent: Math.ceil(spendingLimit * 0.85),
          limit: spendingLimit,
        },
        completed: completedSet.has(spendTaskTitle),
      });
    }

    res.json({
      currentPhase: `Month ${monthsElapsed + 1} of ${totalMonths}`,
      progress: progress,
      status: progress >= 0.8 ? 'On Schedule' : 'Behind',
      tasks: currentMonthTasks,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── MARK TASK AS DONE ──────────────────────────────
app.post('/api/action-plan/task-done', authenticate, async (req, res) => {
  try {
    const { taskTitle } = req.body;
    if (!taskTitle) return res.status(400).json({ error: 'Missing taskTitle' });

    await Profile.findOneAndUpdate(
      { userId: req.userId },
      { $addToSet: { completedTasks: taskTitle } },
      { new: true, upsert: true }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── TAX ANALYSIS ──────────────────────────────────
app.get('/api/tax-analysis', authenticate, async (req, res) => {
  // … unchanged …
});

// ─── SUBSCRIPTION ROUTES ────────────────────────────
app.get('/api/subscription', authenticate, async (req, res) => {
  // … unchanged …
});

app.post('/api/subscription', authenticate, async (req, res) => {
  // … unchanged …
});

app.delete('/api/subscription', authenticate, async (req, res) => {
  // … unchanged …
});

// ✅ CASH FLOW ENDPOINT – auto‑creates profile if missing
app.get('/api/cash-flow', authenticate, async (req, res) => {
  try {
    let profile = await Profile.findOne({ userId: req.userId });
    if (!profile) {
      profile = await Profile.create({ userId: req.userId });
    }
    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const netBalance = income - expenses;

    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    await MonthlySnapshot.findOneAndUpdate(
      { userId: req.userId, monthKey: currentMonthKey },
      { $setOnInsert: { income, expenses } },
      { upsert: true, new: true }
    );

    const snapshots = await MonthlySnapshot
      .find({ userId: req.userId })
      .sort({ monthKey: -1 })
      .limit(6);

    const trend = snapshots.reverse().map(s => ({
      month: s.monthKey,
      income: s.income,
      expense: s.expenses,
    }));

    const breakdown = [
      { category: 'Salary', icon: 'work', amount: profile.primarySalary || 0, type: 'income', changePercent: 0 },
      { category: 'Side Income', icon: 'work', amount: profile.sideIncome || 0, type: 'income', changePercent: 0 },
      { category: 'Rent', icon: 'home', amount: profile.rent || 0, type: 'expense', changePercent: 0 },
      { category: 'Food & Dining', icon: 'restaurant', amount: profile.food || 0, type: 'expense', changePercent: 12 },
      { category: 'Transport', icon: 'directions_car', amount: profile.transport || 0, type: 'expense', changePercent: 0 },
      { category: 'Entertainment', icon: 'theater_comedy', amount: profile.entertainment || 0, type: 'expense', changePercent: -5 },
      { category: 'Subscriptions', icon: 'subscriptions', amount: 120, type: 'expense', changePercent: -5 },
    ].filter(item => item.amount > 0);

    res.json({
      netBalance,
      income,
      expenses,
      monthlyTrend: trend.length ? trend : [{ month: currentMonthKey, income, expense: expenses }],
      breakdown,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── LINKED ACCOUNTS ROUTES ──────────────────────────
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
      userId: req.userId,
      institutionName,
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

// ─── Health check ───────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    message: 'FinPath API is running',
    dbState: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState] || 'unknown',
  });
});

// ─── Chat route (unchanged) ─────────────────────────
app.post('/api/chat', authenticate, async (req, res) => {
  // … unchanged …
});

// ─── Export for Vercel ──────────────────────────────
module.exports = app;
