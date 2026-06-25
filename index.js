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


