import 'dotenv/config';
import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3001;

// Secret key for signing feedback links
// IMPORTANT: Change this to a secure random string in production!
// You can generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const LINK_SECRET = process.env.LINK_SECRET || 'change-this-secret-in-production-abc123';

// PIN to access hub options (home, manual form, link generator). Set FEEDBACK_HUB_PIN in production.
const HUB_PIN = process.env.FEEDBACK_HUB_PIN || '1234';
const PIN_COOKIE_NAME = 'pin_verified';
const PIN_COOKIE_MAX_AGE_HOURS = 24;

// Staff dashboard session (signed cookie)
const STAFF_COOKIE_NAME = 'staff_session';
const STAFF_SESSION_MAX_AGE_HOURS = 24;
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;

function signPinCookie(timestamp) {
    return crypto.createHmac('sha256', LINK_SECRET).update(String(timestamp)).digest('hex');
}

function verifyPinCookie(value) {
    if (!value || typeof value !== 'string') return false;
    const [timestamp, sig] = value.split('.');
    if (!timestamp || !sig) return false;
    const ageHours = (Date.now() - parseInt(timestamp, 10)) / (1000 * 60 * 60);
    if (ageHours < 0 || ageHours > PIN_COOKIE_MAX_AGE_HOURS) return false;
    const expected = signPinCookie(timestamp);
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

function getPinCookie(req) {
    const raw = req.headers.cookie;
    if (!raw) return null;
    const part = raw.split(';').map((s) => s.trim()).find((s) => s.startsWith(PIN_COOKIE_NAME + '='));
    if (!part) return null;
    try {
        return decodeURIComponent(part.slice(PIN_COOKIE_NAME.length + 1));
    } catch {
        return null;
    }
}

function isProtectedGetPath(req) {
    if (req.method !== 'GET') return false;
    const norm = (req.path.replace(/\/$/, '') || '/').toLowerCase();
    return norm === '/' || norm === '/manual' || norm === '/generate';
}

// --- Staff session helpers ---
function signStaffSession(payload) {
    return crypto.createHmac('sha256', LINK_SECRET).update(payload).digest('hex');
}

function verifyStaffCookie(value) {
    if (!value || typeof value !== 'string') return null;
    const [staffId, timestamp, sig] = value.split('.');
    if (!staffId || !timestamp || !sig) return null;
    const ageHours = (Date.now() - parseInt(timestamp, 10)) / (1000 * 60 * 60);
    if (ageHours < 0 || ageHours > STAFF_SESSION_MAX_AGE_HOURS) return null;
    const payload = `${staffId}.${timestamp}`;
    const expected = signStaffSession(payload);
    try {
        if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    } catch {
        return null;
    }
    return parseInt(staffId, 10);
}

function getStaffCookie(req) {
    const raw = req.headers.cookie;
    if (!raw) return null;
    const part = raw.split(';').map((s) => s.trim()).find((s) => s.startsWith(STAFF_COOKIE_NAME + '='));
    if (!part) return null;
    try {
        return decodeURIComponent(part.slice(STAFF_COOKIE_NAME.length + 1));
    } catch {
        return null;
    }
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha512');
    return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(password, stored) {
    const [saltHex, hashHex] = stored.split(':');
    if (!saltHex || !hashHex) return false;
    const salt = Buffer.from(saltHex, 'hex');
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha512');
    return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

app.use(express.json());

// PIN verification endpoint (no cookie required)
app.post('/api/verify-pin', (req, res) => {
    const { pin } = req.body || {};
    let redirect = (req.body && req.body.redirect) || '/';
    // Only allow same-origin path redirects (no protocol/host)
    if (redirect.startsWith('http:') || redirect.startsWith('https:') || redirect.startsWith('//')) {
        redirect = '/';
    }
    if (!redirect.startsWith('/')) redirect = '/';
    if (String(pin) === String(HUB_PIN)) {
        const timestamp = Date.now().toString();
        const signature = signPinCookie(timestamp);
        const cookieValue = `${timestamp}.${signature}`;
        res.cookie(PIN_COOKIE_NAME, cookieValue, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: PIN_COOKIE_MAX_AGE_HOURS * 60 * 60 * 1000,
            path: '/',
        });
        return res.json({ success: true, redirect });
    }
    return res.status(401).json({ success: false, error: 'Incorrect PIN' });
});

// Protect hub pages and generate API: require valid PIN cookie
app.use((req, res, next) => {
    const hasValidPin = verifyPinCookie(getPinCookie(req));
    if (isProtectedGetPath(req) && !hasValidPin) {
        const redirectUrl = '/pin/?redirect=' + encodeURIComponent(req.originalUrl || '/');
        return res.redirect(redirectUrl);
    }
    if (req.method === 'POST' && req.path === '/api/generate-link' && !hasValidPin) {
        return res.status(403).json({ error: 'PIN required' });
    }
    next();
});

// Dashboard page protection: require staff session for /dashboard (not /dashboard/login)
app.use((req, res, next) => {
    if (req.method !== 'GET') return next();
    const norm = (req.path.replace(/\/$/, '') || '/').toLowerCase();
    if (norm !== '/dashboard' && norm !== '/dashboard/') return next();
    if (req.path.startsWith('/dashboard/login')) return next();
    if (req.path === '/dashboard') return res.redirect(301, '/dashboard/');
    const staffId = verifyStaffCookie(getStaffCookie(req));
    if (!staffId) {
        return res.redirect('/dashboard/login/?redirect=' + encodeURIComponent(req.originalUrl || '/dashboard/'));
    }
    next();
});

app.use(express.static(path.join(__dirname, "../client")));

const db = new Database(path.join(__dirname, 'db/app.db'));

// Ensure ip_hash column exists (for existing databases)
const tableInfo = db.prepare("PRAGMA table_info(feedback)").all();
const hasIpHash = tableInfo.some((col) => col.name === 'ip_hash');
if (!hasIpHash) {
    db.prepare('ALTER TABLE feedback ADD COLUMN ip_hash TEXT').run();
}

// Ensure staff table exists (run schema if needed)
try {
    db.prepare("SELECT 1 FROM staff LIMIT 1").get();
} catch {
    db.exec(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
}

// Staff login
app.post('/api/staff/login', (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const user = db.prepare('SELECT id, username, password_hash FROM staff WHERE username = ?').get(username.trim());
    if (!user || !verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    const timestamp = Date.now().toString();
    const payload = `${user.id}.${timestamp}`;
    const sig = signStaffSession(payload);
    const cookieValue = `${payload}.${sig}`;
    res.cookie(STAFF_COOKIE_NAME, cookieValue, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: STAFF_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000,
        path: '/',
    });
    return res.json({ success: true, username: user.username });
});

// Staff logout
app.post('/api/staff/logout', (req, res) => {
    res.clearCookie(STAFF_COOKIE_NAME, { path: '/', httpOnly: true });
    return res.json({ success: true });
});

// Current staff (for dashboard UI)
app.get('/api/staff/me', (req, res) => {
    const staffId = verifyStaffCookie(getStaffCookie(req));
    if (!staffId) return res.status(401).json({ error: 'Not authenticated' });
    const user = db.prepare('SELECT id, username, created_at FROM staff WHERE id = ?').get(staffId);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    return res.json({ id: user.id, username: user.username });
});

// Hash client IP for duplicate check (we don't store raw IPs)
function hashIp(ip) {
    return crypto.createHash('sha256').update(ip + LINK_SECRET).digest('hex').substring(0, 32);
}

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? (typeof forwarded === 'string' ? forwarded : forwarded[0]).split(',')[0].trim() : req.ip;
    return ip || 'unknown';
}

// Generate a token for an event name
function generateToken(eventName) {
    return crypto.createHmac('sha256', LINK_SECRET)
        .update(eventName)
        .digest('hex')
        .substring(0, 32); // Use first 32 chars for shorter URLs
}

// Verify a token matches an event name
function verifyToken(eventName, token) {
    const expectedToken = generateToken(eventName);
    return crypto.timingSafeEqual(
        Buffer.from(token || ''),
        Buffer.from(expectedToken)
    );
}

// Generate a signed feedback link
app.post("/api/generate-link", (req, res) => {
    const { event_name } = req.body;
    
    if (!event_name || !event_name.trim()) {
        return res.status(400).json({ error: "event_name is required" });
    }
    
    const name = event_name.trim();
    const token = generateToken(name);
    const link = `/event/?name=${encodeURIComponent(name)}&token=${token}`;
    
    res.json({ success: true, link, event_name: name });
});

// Dashboard: list feedback (staff only)
app.get("/api/feedback", (req, res) => {
    const staffId = verifyStaffCookie(getStaffCookie(req));
    if (!staffId) return res.status(401).json({ error: 'Authentication required' });
    const rows = db.prepare("SELECT id, event_name, rating, comment, created_at FROM feedback ORDER BY created_at DESC").all();
    res.json(rows);
});

app.post("/api/feedback", (req, res) => {
    const { event_name, rating, comment, token } = req.body;
    
    if (!event_name || !rating) {
        return res.status(400).json({ error: "event_name and rating are required" });
    }
    
    if (rating < 1 || rating > 5) {
        return res.status(400).json({ error: "rating must be between 1 and 5" });
    }
    
    const isLinkSubmission = token !== undefined;

    // Verify token for external (link) submissions
    if (isLinkSubmission) {
        try {
            if (!verifyToken(event_name, token)) {
                return res.status(403).json({ error: "Invalid or expired feedback link" });
            }
        } catch (error) {
            return res.status(403).json({ error: "Invalid or expired feedback link" });
        }

        // Prevent duplicate submissions: same event + same IP within 24 hours
        const ip = getClientIp(req);
        const ipHash = hashIp(ip);
        const existing = db.prepare(
            "SELECT 1 FROM feedback WHERE event_name = ? AND ip_hash = ? AND created_at > datetime('now', '-24 hours') LIMIT 1"
        ).get(event_name, ipHash);
        if (existing) {
            return res.status(403).json({ error: "You have already submitted feedback for this event." });
        }
    }

    try {
        const ipHash = isLinkSubmission ? hashIp(getClientIp(req)) : null;
        const stmt = db.prepare("INSERT INTO feedback (event_name, rating, comment, ip_hash) VALUES (?, ?, ?, ?)");
        const result = stmt.run(event_name, rating, comment || null, ipHash);
        res.json({ success: true, id: result.lastInsertRowid });
    } catch (error) {
        res.status(500).json({ error: "Failed to save feedback" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});