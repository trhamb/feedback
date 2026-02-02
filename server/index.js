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
    
    // Verify token for external submissions (token will be present in URL-based submissions)
    // Manual submissions from staff don't need a token
    if (token !== undefined) {
        try {
            if (!verifyToken(event_name, token)) {
                return res.status(403).json({ error: "Invalid or expired feedback link" });
            }
        } catch (error) {
            return res.status(403).json({ error: "Invalid or expired feedback link" });
        }
    }
    
    try {
        const stmt = db.prepare("INSERT INTO feedback (event_name, rating, comment) VALUES (?, ?, ?)");
        const result = stmt.run(event_name, rating, comment || null);
        res.json({ success: true, id: result.lastInsertRowid });
    } catch (error) {
        res.status(500).json({ error: "Failed to save feedback" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:3001`);
})