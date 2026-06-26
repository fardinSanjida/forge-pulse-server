 require('dotenv').config()
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');

const cookieParser = require('cookie-parser');
const app = express()
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}
app.use(cors(corsOptions))
app.use(cookieParser())
app.use('/api/webhook', express.raw({ type: 'application/json' }))
app.use(express.json())
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;
const port = 5000
const uri = process.env.MONGO_DB_URI
const dbName = process.env.MONGO_DB_NAME || 'forge_pulse_db'
const authDbName = process.env.AUTH_DB_NAME || dbName

if (!uri) {
  console.error('Missing MONGO_DB_URI in .env')
  process.exit(1)
}

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
})

const getDb = () => client.db(dbName)
const getAuthDb = () => client.db(authDbName)
const getCollection = (name) => getDb().collection(name)
const getAuthCollection = (name) => getAuthDb().collection(name)

function toObjectId(id) {
  return ObjectId.isValid(id) ? new ObjectId(id) : null
}

function getPagination(query) {
  const page = Math.max(Number.parseInt(query.page, 10) || 1, 1)
  const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 10, 1), 50)
  return {
    page,
    limit,
    skip: (page - 1) * limit,
  }
}

async function createBookingFromStripeSession(session) {
  const metadata = session.metadata || {};
  const userEmail = String(metadata.userEmail || session.customer_details?.email || '').toLowerCase();
  const classId = metadata.classId || '';

  if (!userEmail || !classId) {
    throw new Error('Missing required Stripe metadata for booking');
  }

  const existing = await getCollection('bookings').findOne({ userEmail, classId });
  if (existing) {
    return { already: true, existing };
  }

  const booking = {
    userName: metadata.userName || session.customer_details?.name || '',
    userEmail,
    classId,
    className: metadata.className || '',
    trainerName: metadata.trainerName || '',
    schedule: metadata.schedule || '',
    amount: Number(session.amount_total || 0) / 100,
    transactionId: session.payment_intent || session.id,
    createdAt: new Date(),
  };

  const result = await getCollection('bookings').insertOne(booking);

  if (ObjectId.isValid(classId)) {
    await getCollection('classes').updateOne(
      { _id: new ObjectId(classId) },
      { $inc: { bookingCount: 1 }, $set: { updatedAt: new Date() } },
    );
  }

  return { booking: { ...booking, _id: result.insertedId } };
}

function generateToken(user) {
  const payload = {
    email: user.email,
    role: user.role || 'user',
  };

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('Missing JWT_SECRET in environment');
  }

  return jwt.sign(payload, secret, { expiresIn: '7d' });
}

async function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Re-fetch live role and banned status so admin changes take effect immediately
  // without requiring the user to re-login.
  try {
    const dbUser = await getAuthCollection('user').findOne(
      { email: req.user.email },
      { projection: { role: 1, banned: 1 } },
    )
    if (dbUser) {
      req.user.role = dbUser.role || 'user'
      req.user.banned = dbUser.banned ?? false
    }
  } catch {
    // DB error: fall back to values in the JWT
  }

  return next();
}

function authorizeRole(allowed) {
  const allowedRoles = Array.isArray(allowed) ? allowed : [allowed];
  return (req, res, next) => {
    const role = req.user?.role || 'user';
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    return next();
  };
}

async function checkNotBlocked(req, res, next) {
  const userEmail = req.user?.email;
  if (!userEmail) return next();
  try {
    const user = await getAuthCollection('user').findOne({ email: userEmail });
    if (user?.banned) {
      return res.status(403).json({ error: 'Action restricted by Admin' });
    }
    return next();
  } catch (err) {
    console.error('Failed to check user block status:', err);
    return next();
  }
}

async function ensureIndexes() {
  await Promise.all([
    getAuthCollection('user').createIndex({ email: 1 }),
    getCollection('classes').createIndexes([
      { key: { status: 1 } },
      { key: { category: 1 } },
      { key: { name: 1 } },
    ]),
    getCollection('trainerApplications').createIndexes([
      { key: { userEmail: 1 }, unique: true },
      { key: { status: 1 } },
    ]),
    getCollection('bookings').createIndexes([
      { key: { userEmail: 1, classId: 1 }, unique: true },
      { key: { userEmail: 1 } },
    ]),
    getCollection('favorites').createIndexes([
      { key: { userEmail: 1, classId: 1 }, unique: true },
      { key: { userEmail: 1 } },
    ]),
    getCollection('forumPosts').createIndexes([
      { key: { createdAt: -1 } },
      { key: { authorEmail: 1 } },
    ]),
    getCollection('forumComments').createIndexes([
      { key: { postId: 1, createdAt: -1 } },
      { key: { authorEmail: 1 } },
    ]),
    getCollection('forumVotes').createIndexes([
      { key: { postId: 1, userEmail: 1 }, unique: true },
    ]),
  ])
}

async function updateAuthUserRole(userEmail, role) {
  return getAuthCollection('user').findOneAndUpdate(
    { email: userEmail },
    {
      $set: {
        role,
        updatedAt: new Date(),
      },
    },
    { returnDocument: 'after' },
  )
}

app.get('/', async (req, res) => {
  try {
    await client.db('admin').command({ ping: 1 })
    res.send(`Forge Pulse server is running. MongoDB database "${dbName}" is healthy.`)
  } catch (err) {
    console.error('MongoDB ping failed:', err)
    res.status(500).send('MongoDB connection failed.')
  }
})

// Issue JWT for an existing auth user (requires AUTH_ISSUE_KEY when set)
app.post('/api/auth/issue', async (req, res) => {
  try {
    const { email, issueKey } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (process.env.AUTH_ISSUE_KEY && issueKey !== process.env.AUTH_ISSUE_KEY) {
      return res.status(403).json({ error: 'Invalid issue key' });
    }

    const userEmail = String(email).toLowerCase();
    let user = await getAuthCollection('user').findOne({ email: userEmail });

    if (!user) {
      return res.status(404).json({ error: 'Auth user not found' });
    }

    // Ensure role field is persisted — Better Auth does not set it by default
    if (!user.role) {
      user = await getAuthCollection('user').findOneAndUpdate(
        { email: userEmail },
        { $set: { role: 'user' } },
        { returnDocument: 'after' },
      ) || user
    }

    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error('Failed to issue token:', err);
    res.status(500).json({ error: 'Failed to issue token' });
  }
});

// Issue JWT and set as HttpOnly cookie (for browser login flows)
app.post('/api/auth/issue-cookie', async (req, res) => {
  try {
    const { email, issueKey } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (process.env.AUTH_ISSUE_KEY && issueKey !== process.env.AUTH_ISSUE_KEY) {
      return res.status(403).json({ error: 'Invalid issue key' });
    }

    const userEmail = String(email).toLowerCase();
    let user = await getAuthCollection('user').findOne({ email: userEmail });

    if (!user) {
      return res.status(404).json({ error: 'Auth user not found' });
    }

    // Honour caller's requested role for new users; existing roles are preserved
    if (!user.role) {
      const requested = req.body.role;
      const roleToSet = requested === 'trainer' ? 'trainer' : 'user';
      user = await getAuthCollection('user').findOneAndUpdate(
        { email: userEmail },
        { $set: { role: roleToSet } },
        { returnDocument: 'after' },
      ) || user
    }

    const token = generateToken(user);

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };

    res.cookie('token', token, cookieOptions);
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to issue cookie token:', err);
    res.status(500).json({ error: 'Failed to issue cookie token' });
  }
});

// API: list classes
app.get('/api/classes', async (req, res) => {
  try {
    const { page, limit, skip } = getPagination(req.query)
    const filter = {}

    if (req.query.status) {
      filter.status = req.query.status
    }

    if (req.query.search) {
      filter.name = { $regex: req.query.search, $options: 'i' }
    }

    if (req.query.category) {
      const categories = String(req.query.category)
        .split(',')
        .map((category) => category.trim())
        .filter(Boolean)

      if (categories.length) {
        filter.category = { $in: categories }
      }
    }

    if (req.query.trainerEmail) {
      filter.trainerEmail = String(req.query.trainerEmail).toLowerCase()
    }

    const classesCollection = getCollection('classes')
    const [classes, total] = await Promise.all([
      classesCollection
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      classesCollection.countDocuments(filter),
    ])

    res.json({
      data: classes,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    })
  } catch (err) {
    console.error('Failed to fetch classes:', err)
    res.status(500).json({ error: 'Failed to fetch classes' })
  }
})

app.get('/api/classes/:id', async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid class id' })
    }

    const classItem = await getCollection('classes').findOne({ _id: objectId })

    if (!classItem) {
      return res.status(404).json({ error: 'Class not found' })
    }

    res.json(classItem)
  } catch (err) {
    console.error('Failed to fetch class:', err)
    res.status(500).json({ error: 'Failed to fetch class' })
  }
})

app.post('/api/classes', authenticateJWT, authorizeRole(['trainer','admin']), async (req, res) => {
  try {
    const data = req.body

    if (!data?.name || !data?.category || !data?.price || !data?.description) {
      return res.status(400).json({
        error: 'Class name, category, price, and description are required',
      })
    }

    const now = new Date()
    const classDocument = {
      name: data.name,
      image: data.image || '',
      category: data.category,
      difficulty: data.difficulty || 'Beginner',
      duration: data.duration || '',
      schedule: data.schedule || '',
      price: Number(data.price),
      description: data.description,
      trainerName: data.trainerName || '',
      trainerEmail: data.trainerEmail || '',
      status: 'Pending',
      bookingCount: 0,
      createdAt: now,
      updatedAt: now,
    }

    const result = await getCollection('classes').insertOne(classDocument)
    res.status(201).json({ ...classDocument, _id: result.insertedId })
  } catch (err) {
    console.error('Failed to insert class:', err)
    res.status(500).json({ error: 'Failed to insert class' })
  }
})

app.patch('/api/classes/:id/status', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)
    const allowedStatuses = ['Pending', 'Approved', 'Rejected']

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid class id' })
    }

    if (!allowedStatuses.includes(req.body?.status)) {
      return res.status(400).json({ error: 'Invalid class status' })
    }

    const result = await getCollection('classes').findOneAndUpdate(
      { _id: objectId },
      {
        $set: {
          status: req.body.status,
          rejectionReason: req.body.feedback || '',
          updatedAt: new Date(),
        },
      },
      { returnDocument: 'after' },
    )

    if (!result) {
      return res.status(404).json({ error: 'Class not found' })
    }

    res.json(result)
  } catch (err) {
    console.error('Failed to update class status:', err)
    res.status(500).json({ error: 'Failed to update class status' })
  }
})

app.patch('/api/classes/:id', authenticateJWT, authorizeRole(['trainer', 'admin']), async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid class id' })
    }

    const existingClass = await getCollection('classes').findOne({ _id: objectId })

    if (!existingClass) {
      return res.status(404).json({ error: 'Class not found' })
    }

    if (req.user.role === 'trainer' && existingClass.trainerEmail !== req.user.email) {
      return res.status(403).json({ error: 'You can only update your own classes' })
    }

    const data = req.body
    const updates = { updatedAt: new Date() }

    if (data.name !== undefined) updates.name = data.name
    if (data.image !== undefined) updates.image = data.image
    if (data.category !== undefined) updates.category = data.category
    if (data.difficulty !== undefined) updates.difficulty = data.difficulty
    if (data.duration !== undefined) updates.duration = data.duration
    if (data.schedule !== undefined) updates.schedule = data.schedule
    if (data.price !== undefined) updates.price = Number(data.price)
    if (data.description !== undefined) updates.description = data.description

    const result = await getCollection('classes').findOneAndUpdate(
      { _id: objectId },
      { $set: updates },
      { returnDocument: 'after' },
    )

    res.json(result)
  } catch (err) {
    console.error('Failed to update class:', err)
    res.status(500).json({ error: 'Failed to update class' })
  }
})

app.delete('/api/classes/:id', authenticateJWT, authorizeRole(['trainer', 'admin']), async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid class id' })
    }

    const existingClass = await getCollection('classes').findOne({ _id: objectId })

    if (!existingClass) {
      return res.status(404).json({ error: 'Class not found' })
    }

    if (req.user.role === 'trainer' && existingClass.trainerEmail !== req.user.email) {
      return res.status(403).json({ error: 'You can only delete your own classes' })
    }

    await getCollection('classes').deleteOne({ _id: objectId })
    res.json({ deleted: true })
  } catch (err) {
    console.error('Failed to delete class:', err)
    res.status(500).json({ error: 'Failed to delete class' })
  }
})

app.get('/api/trainer-applications', async (req, res) => {
  try {
    const filter = {}

    if (req.query.status) {
      filter.status = req.query.status
    }

    if (req.query.userEmail) {
      filter.userEmail = String(req.query.userEmail).toLowerCase()
    }

    const applications = await getCollection('trainerApplications')
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray()

    res.json(applications)
  } catch (err) {
    console.error('Failed to fetch trainer applications:', err)
    res.status(500).json({ error: 'Failed to fetch trainer applications' })
  }
})

app.post('/api/trainer-applications', authenticateJWT, checkNotBlocked, async (req, res) => {
  try {
    const data = req.body
    const userEmail = data?.userEmail?.toLowerCase()

    if (!userEmail || !data?.experience || !data?.specialty) {
      return res.status(400).json({
        error: 'User email, experience, and specialty are required',
      })
    }

    const now = new Date()
    const application = {
      userName: data.userName || '',
      userEmail,
      experience: Number(data.experience),
      specialty: data.specialty,
      bio: data.bio || '',
      availableDays: Array.isArray(data.availableDays) ? data.availableDays : [],
      status: 'Pending',
      feedback: '',
      createdAt: now,
      updatedAt: now,
    }

    const result = await getCollection('trainerApplications').findOneAndUpdate(
      { userEmail },
      { $setOnInsert: application },
      { upsert: true, returnDocument: 'after' },
    )

    res.status(result.createdAt?.getTime() === now.getTime() ? 201 : 200).json(result)
  } catch (err) {
    console.error('Failed to save trainer application:', err)
    res.status(500).json({ error: 'Failed to save trainer application' })
  }
})

app.patch('/api/trainer-applications/:id', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)
    const allowedStatuses = ['Pending', 'Approved', 'Rejected']

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid application id' })
    }

    if (!allowedStatuses.includes(req.body?.status)) {
      return res.status(400).json({ error: 'Invalid application status' })
    }

    const existingApplication = await getCollection('trainerApplications').findOne({
      _id: objectId,
    })

    if (!existingApplication) {
      return res.status(404).json({ error: 'Application not found' })
    }

    if (req.body.status === 'Approved') {
      const updatedUser = await updateAuthUserRole(
        existingApplication.userEmail,
        'trainer',
      )

      if (!updatedUser) {
        return res.status(404).json({
          error: 'Application found, but matching auth user was not found',
        })
      }
    }

    if (
      req.body.status === 'Rejected' &&
      existingApplication.status !== 'Approved'
    ) {
      await updateAuthUserRole(existingApplication.userEmail, 'user')
    }

    const result = await getCollection('trainerApplications').findOneAndUpdate(
      { _id: objectId },
      {
        $set: {
          status: req.body.status,
          feedback: req.body.feedback || '',
          updatedAt: new Date(),
        },
      },
      { returnDocument: 'after' },
    )

    if (!result) {
      return res.status(404).json({ error: 'Application not found' })
    }

    res.json(result)
  } catch (err) {
    console.error('Failed to update trainer application:', err)
    res.status(500).json({ error: 'Failed to update trainer application' })
  }
})

app.get('/api/bookings', authenticateJWT, async (req, res) => {
  try {
    const filter = {}

    if (req.query.userEmail) {
      filter.userEmail = String(req.query.userEmail).toLowerCase()
    }

    if (req.query.classId) {
      filter.classId = req.query.classId
    }

    if (req.query.page || req.query.limit) {
      const { page, limit, skip } = getPagination(req.query)
      const bookingsCollection = getCollection('bookings')
      const [bookings, total] = await Promise.all([
        bookingsCollection.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        bookingsCollection.countDocuments(filter),
      ])
      return res.json({
        data: bookings,
        pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
      })
    }

    const bookings = await getCollection('bookings')
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray()

    res.json(bookings)
  } catch (err) {
    console.error('Failed to fetch bookings:', err)
    res.status(500).json({ error: 'Failed to fetch bookings' })
  }
})

app.post('/api/bookings', authenticateJWT, checkNotBlocked, async (req, res) => {
  try {
    const data = req.body
    const userEmail = data?.userEmail?.toLowerCase()

    if (!userEmail || !data?.classId || !data?.transactionId) {
      return res.status(400).json({
        error: 'User email, class id, and transaction id are required',
      })
    }

    const now = new Date()
    const booking = {
      userName: data.userName || '',
      userEmail,
      classId: data.classId,
      className: data.className || '',
      trainerName: data.trainerName || '',
      schedule: data.schedule || '',
      amount: Number(data.amount) || 0,
      transactionId: data.transactionId,
      createdAt: now,
    }

    const result = await getCollection('bookings').insertOne(booking)

    if (ObjectId.isValid(data.classId)) {
      await getCollection('classes').updateOne(
        { _id: new ObjectId(data.classId) },
        { $inc: { bookingCount: 1 }, $set: { updatedAt: now } },
      )
    }

    res.status(201).json({ ...booking, _id: result.insertedId })
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'You have already booked this class' })
    }

    console.error('Failed to save booking:', err)
    res.status(500).json({ error: 'Failed to save booking' })
  }
})

// Create Stripe Checkout Session
app.post('/api/create-checkout-session', authenticateJWT, async (req, res) => {
  if (!stripe) {
    return res.status(500).json({ error: 'Stripe not configured on server' });
  }

  try {
    const { classId, className, amount, trainerName, schedule } = req.body || {};

    if (!classId || !className || !amount) {
      return res.status(400).json({ error: 'classId, className and amount are required' });
    }

    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const successBase = process.env.CLIENT_URL || corsOptions.origin;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: className },
            unit_amount: Math.round(numericAmount * 100),
          },
          quantity: 1,
        },
      ],
      customer_email: req.user?.email,
      metadata: {
        userEmail: req.user?.email || '',
        userName: req.user?.name || '',
        classId: String(classId),
        className: className,
        trainerName: trainerName || '',
        schedule: schedule || '',
      },
      success_url: `${successBase}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${successBase}/payment/cancel?classId=${encodeURIComponent(classId)}`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Failed to create checkout session:', err);
    res.status(500).json({
      error: 'Failed to create checkout session',
      detail: err?.message || String(err),
    });
  }
});

// Complete checkout: verify session and create booking
app.post('/api/complete-checkout', authenticateJWT, async (req, res) => {
  if (!stripe) {
    return res.status(500).json({ error: 'Stripe not configured on server' });
  }

  try {
    const { sessionId } = req.body || {};

    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Checkout session not found' });
    }

    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const result = await createBookingFromStripeSession(session);
    if (result.already) {
      return res.json({ already: true });
    }

    res.status(201).json(result.booking);
  } catch (err) {
    console.error('Failed to complete checkout:', err);
    res.status(500).json({ error: 'Failed to complete checkout' });
  }
});

app.post('/api/webhook', async (req, res) => {
  if (!stripe) {
    return res.status(500).send('Stripe not configured');
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('Missing STRIPE_WEBHOOK_SECRET in environment');
    return res.status(500).send('Webhook secret not configured');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    try {
      if (session.payment_status === 'paid') {
        await createBookingFromStripeSession(session);
      }
    } catch (err) {
      console.error('Failed to create booking from webhook session:', err);
      return res.status(500).send('Webhook processing error');
    }
  }

  res.json({ received: true });
});

app.get('/api/favorites', authenticateJWT, async (req, res) => {
  try {
    const filter = {}

    if (req.query.userEmail) {
      filter.userEmail = String(req.query.userEmail).toLowerCase()
    }

    const favorites = await getCollection('favorites')
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray()

    res.json(favorites)
  } catch (err) {
    console.error('Failed to fetch favorites:', err)
    res.status(500).json({ error: 'Failed to fetch favorites' })
  }
})

app.post('/api/favorites', authenticateJWT, async (req, res) => {
  try {
    const data = req.body
    const userEmail = data?.userEmail?.toLowerCase()

    if (!userEmail || !data?.classId) {
      return res.status(400).json({ error: 'User email and class id are required' })
    }

    const favorite = {
      userEmail,
      classId: data.classId,
      className: data.className || '',
      trainerName: data.trainerName || '',
      price: data.price || '',
      schedule: data.schedule || '',
      createdAt: new Date(),
    }

    const result = await getCollection('favorites').insertOne(favorite)
    res.status(201).json({ ...favorite, _id: result.insertedId })
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Class already saved to favorites' })
    }

    console.error('Failed to save favorite:', err)
    res.status(500).json({ error: 'Failed to save favorite' })
  }
})

app.delete('/api/favorites/:id', authenticateJWT, async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid favorite id' })
    }

    const result = await getCollection('favorites').deleteOne({ _id: objectId })

    if (!result.deletedCount) {
      return res.status(404).json({ error: 'Favorite not found' })
    }

    res.json({ deleted: true })
  } catch (err) {
    console.error('Failed to delete favorite:', err)
    res.status(500).json({ error: 'Failed to delete favorite' })
  }
})

app.get('/api/forum-posts', async (req, res) => {
  try {
    const { page, limit, skip } = getPagination(req.query)
    const filter = {}

    if (req.query.authorEmail) {
      filter.authorEmail = String(req.query.authorEmail).toLowerCase()
    }

    const postsCollection = getCollection('forumPosts')
    const [posts, total] = await Promise.all([
      postsCollection
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      postsCollection.countDocuments(filter),
    ])

    res.json({
      data: posts,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    })
  } catch (err) {
    console.error('Failed to fetch forum posts:', err)
    res.status(500).json({ error: 'Failed to fetch forum posts' })
  }
})

app.get('/api/forum-posts/:id', async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid post id' })
    }

    const post = await getCollection('forumPosts').findOne({ _id: objectId })

    if (!post) {
      return res.status(404).json({ error: 'Post not found' })
    }

    res.json(post)
  } catch (err) {
    console.error('Failed to fetch forum post:', err)
    res.status(500).json({ error: 'Failed to fetch forum post' })
  }
})

app.post('/api/forum-posts', authenticateJWT, authorizeRole(['trainer','admin']), async (req, res) => {
  try {
    const data = req.body

    if (!data?.title || !data?.description || !data?.authorEmail) {
      return res.status(400).json({
        error: 'Title, description, and author email are required',
      })
    }

    const now = new Date()
    const post = {
      title: data.title,
      image: data.image || '',
      description: data.description,
      authorName: data.authorName || '',
      authorEmail: data.authorEmail.toLowerCase(),
      authorRole: data.authorRole || 'trainer',
      likes: 0,
      dislikes: 0,
      commentCount: 0,
      createdAt: now,
      updatedAt: now,
    }

    const result = await getCollection('forumPosts').insertOne(post)
    res.status(201).json({ ...post, _id: result.insertedId })
  } catch (err) {
    console.error('Failed to create forum post:', err)
    res.status(500).json({ error: 'Failed to create forum post' })
  }
})

app.delete('/api/forum-posts/:id', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid post id' })
    }

    const postId = objectId.toString()
    const result = await getCollection('forumPosts').deleteOne({ _id: objectId })

    if (!result.deletedCount) {
      return res.status(404).json({ error: 'Post not found' })
    }

    await Promise.all([
      getCollection('forumComments').deleteMany({ postId }),
      getCollection('forumVotes').deleteMany({ postId }),
    ])
    res.json({ deleted: true })
  } catch (err) {
    console.error('Failed to delete forum post:', err)
    res.status(500).json({ error: 'Failed to delete forum post' })
  }
})

app.get('/api/forum-posts/:id/comments', async (req, res) => {
  try {
    const postId = req.params.id
    const comments = await getCollection('forumComments')
      .find({ postId })
      .sort({ createdAt: -1 })
      .toArray()

    res.json(comments)
  } catch (err) {
    console.error('Failed to fetch comments:', err)
    res.status(500).json({ error: 'Failed to fetch comments' })
  }
})

app.post('/api/forum-posts/:id/comments', authenticateJWT, checkNotBlocked, async (req, res) => {
  try {
    const data = req.body
    const postObjectId = toObjectId(req.params.id)

    if (!postObjectId) {
      return res.status(400).json({ error: 'Invalid post id' })
    }

    if (!data?.text || !data?.authorEmail) {
      return res.status(400).json({ error: 'Comment and author email are required' })
    }

    const comment = {
      postId: req.params.id,
      parentId: data.parentId || null,
      text: data.text,
      authorName: data.authorName || '',
      authorEmail: data.authorEmail.toLowerCase(),
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    const result = await getCollection('forumComments').insertOne(comment)
    await getCollection('forumPosts').updateOne(
      { _id: postObjectId },
      { $inc: { commentCount: 1 }, $set: { updatedAt: new Date() } },
    )

    res.status(201).json({ ...comment, _id: result.insertedId })
  } catch (err) {
    console.error('Failed to create comment:', err)
    res.status(500).json({ error: 'Failed to create comment' })
  }
})

app.patch('/api/forum-comments/:id', async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid comment id' })
    }

    if (!req.body?.text) {
      return res.status(400).json({ error: 'Comment text is required' })
    }

    const result = await getCollection('forumComments').findOneAndUpdate(
      { _id: objectId },
      { $set: { text: req.body.text, updatedAt: new Date() } },
      { returnDocument: 'after' },
    )

    if (!result) {
      return res.status(404).json({ error: 'Comment not found' })
    }

    res.json(result)
  } catch (err) {
    console.error('Failed to update comment:', err)
    res.status(500).json({ error: 'Failed to update comment' })
  }
})

app.delete('/api/forum-comments/:id', async (req, res) => {
  try {
    const objectId = toObjectId(req.params.id)

    if (!objectId) {
      return res.status(400).json({ error: 'Invalid comment id' })
    }

    const comment = await getCollection('forumComments').findOneAndDelete({
      _id: objectId,
    })

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' })
    }

    const postObjectId = toObjectId(comment.postId)
    if (postObjectId) {
      await getCollection('forumPosts').updateOne(
        { _id: postObjectId },
        { $inc: { commentCount: -1 }, $set: { updatedAt: new Date() } },
      )
    }

    res.json({ deleted: true })
  } catch (err) {
    console.error('Failed to delete comment:', err)
    res.status(500).json({ error: 'Failed to delete comment' })
  }
})

app.post('/api/forum-posts/:id/vote', async (req, res) => {
  try {
    const postObjectId = toObjectId(req.params.id)
    const userEmail = req.body?.userEmail?.toLowerCase()
    const voteType = req.body?.voteType

    if (!postObjectId) {
      return res.status(400).json({ error: 'Invalid post id' })
    }

    if (!userEmail || !['like', 'dislike'].includes(voteType)) {
      return res.status(400).json({ error: 'User email and valid vote are required' })
    }

    const postId = req.params.id
    const votesCollection = getCollection('forumVotes')
    const existingVote = await votesCollection.findOne({ postId, userEmail })

    if (existingVote?.voteType === voteType) {
      return res.status(409).json({ error: `You already ${voteType}d this post` })
    }

    if (existingVote) {
      await votesCollection.updateOne(
        { _id: existingVote._id },
        { $set: { voteType, updatedAt: new Date() } },
      )
      await getCollection('forumPosts').updateOne(
        { _id: postObjectId },
        {
          $inc:
            voteType === 'like'
              ? { likes: 1, dislikes: -1 }
              : { likes: -1, dislikes: 1 },
        },
      )
    } else {
      await votesCollection.insertOne({
        postId,
        userEmail,
        voteType,
        createdAt: new Date(),
        updatedAt: new Date(),
      })
      await getCollection('forumPosts').updateOne(
        { _id: postObjectId },
        { $inc: voteType === 'like' ? { likes: 1 } : { dislikes: 1 } },
      )
    }

    const post = await getCollection('forumPosts').findOne({ _id: postObjectId })
    res.json(post)
  } catch (err) {
    console.error('Failed to vote on forum post:', err)
    res.status(500).json({ error: 'Failed to vote on forum post' })
  }
})

app.get('/api/admin/stats', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const [totalUsers, totalClasses, totalBookings] = await Promise.all([
      getAuthCollection('user').countDocuments({}),
      getCollection('classes').countDocuments({}),
      getCollection('bookings').countDocuments({}),
    ])
    res.json({ totalUsers, totalClasses, totalBookings })
  } catch (err) {
    console.error('Failed to fetch admin stats:', err)
    res.status(500).json({ error: 'Failed to fetch admin stats' })
  }
})

app.get('/api/users', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const { page, limit, skip } = getPagination(req.query)
    const filter = {}

    if (req.query.role) {
      filter.role = req.query.role
    }

    if (req.query.search) {
      filter.$or = [
        { name: { $regex: req.query.search, $options: 'i' } },
        { email: { $regex: req.query.search, $options: 'i' } },
      ]
    }

    const usersCollection = getAuthCollection('user')
    const [users, total] = await Promise.all([
      usersCollection
        .find(filter, { projection: { hashedPassword: 0, password: 0 } })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      usersCollection.countDocuments(filter),
    ])

    res.json({
      data: users,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    })
  } catch (err) {
    console.error('Failed to fetch users:', err)
    res.status(500).json({ error: 'Failed to fetch users' })
  }
})

app.patch('/api/users/:id/role', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    const allowedRoles = ['admin', 'trainer', 'user']

    if (!allowedRoles.includes(req.body?.role)) {
      return res.status(400).json({ error: 'Invalid role' })
    }

    const objectId = toObjectId(req.params.id)
    const filter = objectId ? { _id: objectId } : { _id: req.params.id }

    const result = await getAuthCollection('user').findOneAndUpdate(
      filter,
      { $set: { role: req.body.role, updatedAt: new Date() } },
      { returnDocument: 'after', projection: { hashedPassword: 0, password: 0 } },
    )

    if (!result) {
      return res.status(404).json({ error: 'User not found' })
    }

    res.json(result)
  } catch (err) {
    console.error('Failed to update user role:', err)
    res.status(500).json({ error: 'Failed to update user role' })
  }
})

app.patch('/api/users/:id/status', authenticateJWT, authorizeRole('admin'), async (req, res) => {
  try {
    if (typeof req.body?.banned !== 'boolean') {
      return res.status(400).json({ error: 'banned must be a boolean' })
    }

    const objectId = toObjectId(req.params.id)
    const filter = objectId ? { _id: objectId } : { _id: req.params.id }

    const result = await getAuthCollection('user').findOneAndUpdate(
      filter,
      { $set: { banned: req.body.banned, updatedAt: new Date() } },
      { returnDocument: 'after', projection: { hashedPassword: 0, password: 0 } },
    )

    if (!result) {
      return res.status(404).json({ error: 'User not found' })
    }

    res.json(result)
  } catch (err) {
    console.error('Failed to update user status:', err)
    res.status(500).json({ error: 'Failed to update user status' })
  }
})

async function startServer() {
  try {
    await client.connect()
    await client.db('admin').command({ ping: 1 })
    await ensureIndexes()
    console.log(`Connected to MongoDB database "${dbName}".`)

    app.listen(port, () => {
      console.log(`Forge Pulse server listening on port ${port}`)
    })
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error)
    process.exit(1)
  }
}

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/',
  });

  return res.json({ success: true });
});

startServer()
