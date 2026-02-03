import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3001;

// Secret key for signing feedback links
// IMPORTANT: Change this to a secure random string in production!
// You can generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const LINK_SECRET = process.env.LINK_SECRET || 'change-this-secret-in-production-abc123';

app.use(express.json());
app.use(express.static(path.join(__dirname, "../client")));

const db = new Database(path.join(__dirname, 'db/app.db'));

// Ensure ip_hash column exists (for existing databases)
const tableInfo = db.prepare("PRAGMA table_info(feedback)").all();
const hasIpHash = tableInfo.some((col) => col.name === 'ip_hash');
if (!hasIpHash) {
    db.prepare('ALTER TABLE feedback ADD COLUMN ip_hash TEXT').run();
}

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

app.get("/api/feedback", (req, res) => {
    const rows = db.prepare("SELECT * FROM feedback ORDER BY created_at DESC").all();
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
    console.log(`Server running on http://localhost:3001`);
})