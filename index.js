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

function authenticateJWT(req, res, next) {
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
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







