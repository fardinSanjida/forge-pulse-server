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

