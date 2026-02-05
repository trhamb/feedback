/**
 * Create a staff account for dashboard access.
 * Usage: node scripts/create-staff.js <username> <password>
 * Or from repo root: node server/scripts/create-staff.js <username> <password>
 */
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 64;

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha512');
    return salt.toString('hex') + ':' + hash.toString('hex');
}

const username = process.argv[2];
const password = process.argv[3];

if (!username || !password) {
    console.error('Usage: node create-staff.js <username> <password>');
    process.exit(1);
}

const dbPath = path.join(__dirname, '..', 'db', 'app.db');
const db = new Database(dbPath);

try {
    db.exec(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
} catch (_) {}

try {
    const password_hash = hashPassword(password);
    db.prepare('INSERT INTO staff (username, password_hash) VALUES (?, ?)').run(username.trim(), password_hash);
    console.log('Staff account created for:', username.trim());
} catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        console.error('Error: A staff user with that username already exists.');
    } else {
        console.error('Error:', err.message);
    }
    process.exit(1);
} finally {
    db.close();
}
