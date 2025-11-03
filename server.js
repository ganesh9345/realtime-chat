/**
 * server.js
 * Simple Express + Socket.io chat server with:
 *  - Registration & login (email+password, in-memory demo)
 *  - JWT auth (for REST endpoints)
 *  - Room create/join via Socket.io rooms
 *  - Save chat history in memory (demo) and email transcript to room creator
 *
 * IMPORTANT: For production, use a database and HTTPS.
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // serves index.html and client assets

const server = http.createServer(app);
const io = new Server(server);

// In-memory stores for demo (use DB in real app)
const users = {}; // email -> { email, passwordHash }
const rooms = {}; // roomId -> { creatorEmail, messages: [{from, text, time}], createdAt }

// JWT secret from env
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// ---------- Nodemailer setup ----------
// Option A: OAuth2 (recommended) - set these in .env
// GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN, GMAIL_SENDER_EMAIL

// Option B: App Password - set GMAIL_USER and GMAIL_PASS (less recommended, but works with App Password)
// In .env include either OAuth2 vars OR GMAIL_USER & GMAIL_PASS

let transporterPromise = (async () => {
  if (process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN) {
    // OAuth2
    const { google } = require('googleapis');
    const OAuth2 = google.auth.OAuth2;
    const oauth2Client = new OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      "https://developers.google.com/oauthplayground"
    );
    oauth2Client.setCredentials({
      refresh_token: process.env.GMAIL_REFRESH_TOKEN
    });
    const accessToken = await oauth2Client.getAccessToken();

    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.GMAIL_SENDER_EMAIL,
        clientId: process.env.GMAIL_CLIENT_ID,
        clientSecret: process.env.GMAIL_CLIENT_SECRET,
        refreshToken: process.env.GMAIL_REFRESH_TOKEN,
        accessToken: accessToken.token || accessToken // nodemailer accepts token or object
      }
    });
  } else if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
    // App password / username-password method
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
      }
    });
  } else {
    console.warn('No Gmail config found in environment. Email sending will fail until configured.');
    return null;
  }
})();

// Utility: generate JWT
function generateToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '12h' });
}

// Middleware: verify token
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- REST API ----------

// Register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  if (users[email]) return res.status(400).json({ error: 'User already exists' });
  const hash = await bcrypt.hash(password, 10);
  users[email] = { email, passwordHash: hash };
  const token = generateToken(email);
  res.json({ token, email });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const u = users[email];
  if (!u) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const token = generateToken(email);
  res.json({ token, email });
});

// Create room (requires auth) - returns roomId
app.post('/api/rooms', authMiddleware, async (req, res) => {
  const creator = req.user.email;
  // Generate simple room id (6 chars)
  const roomId = Math.random().toString(36).slice(2, 8).toUpperCase();
  rooms[roomId] = {
    creatorEmail: creator,
    messages: [],
    createdAt: new Date().toISOString()
  };

  // Optionally send an initial email to creator (transcript currently empty)
  const transporter = await transporterPromise;
  if (transporter) {
    const mailOptions = {
      from: process.env.GMAIL_SENDER_EMAIL || process.env.GMAIL_USER,
      to: creator,
      subject: `Room ${roomId} created - X1 Chat`,
      text: `Your room ${roomId} was created. Share this Room ID to others to join.\n\nRoom ID: ${roomId}\nCreated At: ${rooms[roomId].createdAt}`
    };
    transporter.sendMail(mailOptions).catch(err => {
      console.error('Mail send error:', err && err.message);
    });
  }

  res.json({ roomId, creatorEmail: creator });
});

// Get room messages (requires auth)
app.get('/api/rooms/:id/messages', authMiddleware, (req, res) => {
  const id = req.params.id.toUpperCase();
  const room = rooms[id];
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ messages: room.messages, creatorEmail: room.creatorEmail });
});

// Manually request sending transcript via REST (requires auth)
app.post('/api/rooms/:id/send-transcript', authMiddleware, async (req, res) => {
  const id = req.params.id.toUpperCase();
  const room = rooms[id];
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const transporter = await transporterPromise;
  if (!transporter) return res.status(500).json({ error: 'Email not configured' });

  const lines = room.messages.map(m => `${m.time} | ${m.from}: ${m.text}`).join('\n') || '(no messages)';
  const mailOptions = {
    from: process.env.GMAIL_SENDER_EMAIL || process.env.GMAIL_USER,
    to: room.creatorEmail,
    subject: `Transcript for room ${id}`,
    text: `Transcript for room ${id}:\n\n${lines}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ ok: true, message: 'Transcript sent' });
  } catch (err) {
    console.error('Send transcript error:', err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// ---------- Socket.io real-time chat ----------
io.use((socket, next) => {
  // Optional: check token in handshake query for auth
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(); // allow anonymous sockets if frontend doesn't send token
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
  } catch (err) {
    console.log('Socket auth failed, continuing as anonymous');
  }
  next();
});

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id, 'user', socket.user && socket.user.email);

  // join room
  socket.on('join-room', ({ roomId, displayName }, cb) => {
    roomId = (roomId || '').toUpperCase();
    if (!rooms[roomId]) {
      return cb && cb({ error: 'Room not found' });
    }
    socket.join(roomId);
    socket.roomId = roomId;
    socket.displayName = displayName || (socket.user && socket.user.email) || 'Anonymous';
    // send existing messages to this socket
    socket.emit('room-history', rooms[roomId].messages);
    io.to(roomId).emit('system-message', { text: `${socket.displayName} joined the room.` });
    cb && cb({ ok: true });
  });

  // create-room via socket (optional)
  socket.on('create-room', async (data, cb) => {
    const creator = (socket.user && socket.user.email) || data.creatorEmail || 'unknown@example.com';
    const roomId = Math.random().toString(36).slice(2,8).toUpperCase();
    rooms[roomId] = { creatorEmail: creator, messages: [], createdAt: new Date().toISOString() };
    cb && cb({ ok: true, roomId });

    // email creator asynchronously
    const transporter = await transporterPromise;
    if (transporter) {
      const mailOptions = {
        from: process.env.GMAIL_SENDER_EMAIL || process.env.GMAIL_USER,
        to: creator,
        subject: `Room ${roomId} created - X1 Chat`,
        text: `Your room ${roomId} was created. Room ID: ${roomId}`
      };
      transporter.sendMail(mailOptions).catch(e => console.error('Mail send err', e && e.message));
    }
  });

  // handle chat messages
  socket.on('chat-message', (payload) => {
    const { roomId } = socket;
    if (!roomId) return;
    const message = {
      from: socket.displayName || (socket.user && socket.user.email) || 'Anonymous',
      text: String(payload.text || '').slice(0, 2000),
      time: new Date().toLocaleString()
    };
    // store
    rooms[roomId].messages.push(message);
    // broadcast
    io.to(roomId).emit('chat-message', message);
  });

  socket.on('disconnect', () => {
    if (socket.roomId) {
      io.to(socket.roomId).emit('system-message', { text: `${socket.displayName} left the room.` });
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
