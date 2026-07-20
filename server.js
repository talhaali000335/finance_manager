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




// ─── Profile Model (added completedTasks field) ─────

// ─── Monthly Snapshot Model ──────────────────────
const monthlySnapshotSchema = new mongoose.Schema({
  userId:    { type: String, required: true },
  monthKey:  { type: String, required: true },   // e.g. "2026-07"
  income:    { type: Number, default: 0 },
  expenses:  { type: Number, default: 0 },
}, { timestamps: true });

// Ensure one snapshot per user per month
monthlySnapshotSchema.index({ userId: 1, monthKey: 1 }, { unique: true });

const MonthlySnapshot = mongoose.model('MonthlySnapshot', monthlySnapshotSchema);

// ─── Profile Model (added completedTasks field) ─────

const profileSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  profilePicture: { type: String, default: '' },   // <-- new
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
  completedTasks: [{ type: String }],   // <-- NEW field for action plan task tracking
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
  endDate:          { type: Date },            // optional – for yearly, set 1 year ahead
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

// DELETE – Remove a goal
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

// ─── ACTION PLAN ENDPOINT (UPDATED) ─────────────────
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

    // Completed task set for this user
    const completedSet = new Set(profile?.completedTasks ?? []);

    const currentMonthTasks = [];
    const primaryGoal = goals.sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];

    if (primaryGoal) {
      const goalName = primaryGoal.name || primaryGoal.goalType;
      const neededMonthly = Math.ceil(
        (primaryGoal.targetAmount - (primaryGoal.existingSavings || 0)) / totalMonths
      );

      // Task 1
      const saveTaskTitle = `Save \$${neededMonthly} to ${goalName}`;
      currentMonthTasks.push({
        title: saveTaskTitle,
        description: `Keeps you aligned for your ${goalName} target.`,
        hasInfo: true,
        spending: null,
        completed: completedSet.has(saveTaskTitle),
      });

      // Task 2
      const moveTaskTitle = `Move \$${Math.ceil(neededMonthly * 0.4)} to Business Seed Account`;
      currentMonthTasks.push({
        title: moveTaskTitle,
        description: 'Scheduled automated transfer.',
        hasInfo: false,
        spending: null,
        completed: completedSet.has(moveTaskTitle),
      });

      // Task 3
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

// ─── TAX ANALYSIS – AI‑powered (Gemini) ───────────
app.get('/api/tax-analysis', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const state = profile.state || 'NY';            // adjust as needed
    const filingStatus = profile.filingStatus || 'Single';
    const currentDate = new Date().toISOString().split('T')[0];

    const prompt = `
You are a tax advisor. Based on the following user data, provide a tax analysis in JSON format.
User data:
- Annual income: $${income}
- State: ${state}
- Filing status: ${filingStatus}
- Current date: ${currentDate}

Output must be a valid JSON object with these exact keys:
{
  "annualTax": number (estimated total federal + state + FICA + local),
  "effectiveRate": number (as percentage),
  "marginalRate": number (as percentage),
  "breakdown": {
    "federal": number,
    "state": number,
    "fica": number,
    "local": number
  },
  "tips": [
    {"icon": "account_balance", "title": "string", "description": "string"},
    {"icon": "health_and_safety", "title": "string", "description": "string"}
  ]
}
Return ONLY the JSON, no additional text.
`.trim();

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Server configuration error: missing GEMINI_API_KEY' });
    }

     const models = [
       'gemini-2.5-flash',                // stable, free tier
       'gemini-2.5-flash-lite',           // fallback
       'gemini-3-flash-preview',          // preview (if still available)
                 ];

    

    let lastError = null;
    for (const model of models) {
      try {
        console.log(`🔍 Trying Gemini for tax analysis with model: ${model}`);
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ text: prompt }] }]
            })
          }
        );

        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error?.message || `Gemini returned status ${response.status}`);
        }

        const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!rawText) throw new Error('No content returned from Gemini');

        // Extract JSON (sometimes wrapped in ```json blocks)
        const jsonStr = rawText.replace(/```json|```/g, '').trim();
        const analysis = JSON.parse(jsonStr);

        if (analysis.annualTax == null || analysis.effectiveRate == null) {
          throw new Error('Incomplete data from Gemini');
        }

       

        console.log(`✅ Tax analysis generated with model: ${model}`);
        return res.json(analysis);

      } catch (err) {
        console.warn(`⚠️ Model ${model} failed: ${err.message}`);
        lastError = err;
      }
    }

    // All models failed
    console.error('❌ All Gemini models failed for tax analysis');
    throw lastError || new Error('Unable to generate tax analysis. Please try again later.');

  } catch (err) {
    console.error('TAX ANALYSIS ERROR:', err);
    // ✅ Always return valid JSON
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});



// ─── GET current subscription ──────────────────────
app.get('/api/subscription', authenticate, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ userId: req.userId });
    res.json(sub || { plan: 'none', active: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST activate subscription (after Google Pay purchase) ─
app.post('/api/subscription', authenticate, async (req, res) => {
  try {
    const { plan } = req.body;
    if (!['monthly', 'yearly'].includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    const startDate = new Date();
    const endDate = new Date();
    if (plan === 'yearly') {
      endDate.setFullYear(endDate.getFullYear() + 1);
    } else {
      endDate.setMonth(endDate.getMonth() + 1);
    }

    const sub = await Subscription.findOneAndUpdate(
      { userId: req.userId },
      { plan, active: true, startDate, endDate, cancelAtPeriodEnd: false },
      { new: true, upsert: true }
    );
    res.json(sub);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── DELETE cancel subscription ─────────────────────
app.delete('/api/subscription', authenticate, async (req, res) => {
  try {
    const sub = await Subscription.findOne({ userId: req.userId });
    if (!sub) return res.status(404).json({ error: 'No subscription found' });

    sub.cancelAtPeriodEnd = true;
    await sub.save();
    // In real life you would also call Google/Apple API to cancel the subscription

    res.json({ message: 'Subscription will be cancelled at the end of the current period.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─── CASH FLOW ENDPOINT (STABLE TREND, NO RANDOM) ────
app.get('/api/cash-flow', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });

    const income = (profile.primarySalary || 0) + (profile.sideIncome || 0);
    const expenses = (profile.rent || 0) + (profile.food || 0) + (profile.transport || 0) + (profile.entertainment || 0) + (profile.monthlyEMI || 0);
    const netBalance = income - expenses;

    // ─── Current month key (e.g. "2026-07") ───────
    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    // Auto‑save a snapshot for the current month (if not already saved)
    await MonthlySnapshot.findOneAndUpdate(
      { userId: req.userId, monthKey: currentMonthKey },
      { $setOnInsert: { income, expenses } },
      { upsert: true, new: true }
    );

    // ─── Fetch last 6 snapshots ──────────────────
    const snapshots = await MonthlySnapshot
      .find({ userId: req.userId })
      .sort({ monthKey: -1 })         // newest first
      .limit(6);

    // Build trend from snapshots (oldest first)
    const trend = snapshots
      .reverse()
      .map(s => ({
        month: s.monthKey,            // e.g. "2026-07"
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
      monthlyTrend: trend.length ? trend : [
        // fallback: at least the current month
        { month: currentMonthKey, income, expense: expenses }
      ],
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

// ─── Open Router chat ───────────────────────────────────

app.post('/api/chat', authenticate, async (req, res) => {
  try {
    const { messages } = req.body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages must be a non-empty array' });
    }

    // ─── Fetch real user data from DB ─────────────────
    const profile = await Profile.findOne({ userId: req.userId });
    const goals = await Goal.find({ userId: req.userId });

    // Calculate net worth, income, expenses from profile
    const assets = (profile?.cashSavings || 0) + (profile?.investments || 0) + (profile?.propertyValue || 0);
    const liabilities = (profile?.totalLoans || 0) + (profile?.creditCardDebt || 0) + (profile?.monthlyEMI || 0);
    const netWorth = assets - liabilities;

    const monthlyIncome = (profile?.primarySalary || 0) + (profile?.sideIncome || 0);
    const monthlyExpenses = (profile?.rent || 0) + (profile?.food || 0) + (profile?.transport || 0) + (profile?.entertainment || 0) + (profile?.monthlyEMI || 0);

    const systemPrompt = `
You are a helpful, personal financial advisor.
Use the following real user data to give precise, actionable advice.
Never make up numbers – refer to the data provided.

USER PROFILE:
- Net worth: $${netWorth}
- Monthly income: $${monthlyIncome}
- Monthly expenses: $${monthlyExpenses}
- Goals: ${JSON.stringify(goals.map(g => ({ name: g.name || g.goalType, target: g.targetAmount, date: g.targetDate })))}
- Assets breakdown: Cash & Savings: $${profile?.cashSavings || 0}, Investments: $${profile?.investments || 0}, Property: $${profile?.propertyValue || 0}
- Liabilities: Loans: $${profile?.totalLoans || 0}, Credit Card Debt: $${profile?.creditCardDebt || 0}, Monthly EMI: $${profile?.monthlyEMI || 0}

Answer the user's question concisely and helpfully.
`.trim();

    const userMessages = messages.map(m => m.content || '').join('\n');
    const fullPrompt = systemPrompt + '\n\n' + userMessages;

    // ─── Gemini call (unchanged) ───────────────────────
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('❌ Missing GEMINI_API_KEY');
      return res.status(500).json({ error: 'Server configuration error: missing API key' });
    }

    const models = [
      'gemini-2.5-flash',
      'gemini-2.5-flash-lite',
      'gemini-3-flash-preview',
    ];

    let lastError = null;
    for (const model of models) {
      try {
        console.log(`🔄 Trying Gemini model: ${model}`);
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ text: fullPrompt }] }]
            })
          }
        );

        const data = await response.json();
        if (!response.ok) {
          const errorMsg = data.error?.message || `status ${response.status}`;
          console.warn(`⚠️ Model ${model} failed: ${errorMsg}`);
          lastError = new Error(errorMsg);
          continue;
        }

        const reply = data.candidates?.[0]?.content?.parts?.[0]?.text
                      ?? 'I could not generate a response. Please try again.';
        console.log(`✅ Success with model: ${model}`);
        return res.json({ reply });

      } catch (fetchErr) {
        console.warn(`⚠️ Network error with model ${model}: ${fetchErr.message}`);
        lastError = fetchErr;
      }
    }

    console.error('❌ All Gemini models failed');
    throw lastError || new Error('All Gemini models are currently unavailable.');

  } catch (err) {
    console.error('CHAT ERROR:', err);
    res.status(500).json({ error: err.message || 'Server error. Please try again later.' });
  }
});



// ─── Export for Vercel ──────────────────────────────
module.exports = app;
