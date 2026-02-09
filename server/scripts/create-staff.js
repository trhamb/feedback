/**
 * Create a user account (volunteer, staff, or admin).
 * Usage: node scripts/create-staff.js <username> <password> [role]
 *   role: volunteer | staff | admin (default: staff)
 * Or from repo root: node server/scripts/create-staff.js <username> <password> [role]
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
const roleArg = (process.argv[4] || 'staff').toLowerCase();
const role = roleArg === 'volunteer' || roleArg === 'admin' ? roleArg : 'staff';

if (!username || !password) {
    console.error('Usage: node create-staff.js <username> <password> [role]');
    console.error('  role: volunteer | staff | admin (default: staff)');
    process.exit(1);
}

const dbPath = path.join(__dirname, '..', 'db', 'app.db');
const db = new Database(dbPath);

try {
    db.exec(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'staff' CHECK (role IN ('volunteer', 'staff', 'admin')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`);
} catch (_) {}
// Add role column if missing (existing DBs)
try {
    const info = db.prepare('PRAGMA table_info(staff)').all();
    if (!info.some((c) => c.name === 'role')) {
        db.prepare('ALTER TABLE staff ADD COLUMN role TEXT NOT NULL DEFAULT \'staff\'').run();
    }
} catch (_) {}

try {
    const password_hash = hashPassword(password);
    db.prepare('INSERT INTO staff (username, password_hash, role) VALUES (?, ?, ?)').run(username.trim(), password_hash, role);
    console.log('User created:', username.trim(), 'role:', role);
} catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        console.error('Error: A user with that username already exists.');
    } else {
        console.error('Error:', err.message);
    }
    process.exit(1);
} finally {
    db.close();
}
