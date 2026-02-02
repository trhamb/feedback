import fs from "fs";
import path from "path";
import Database from "better-sqlite3";

const dbDir = path.resolve("db");
const dbPath = path.join(dbDir, "app.db");

const schemaPath = path.join(dbDir, "schema.sql");
const seedPath = path.join(dbDir, "seed.sql");

if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(dbPath);

const schemaSql = fs.readFileSync(schemaPath, "utf8");
db.exec(schemaSql);

const hasSeed = fs.existsSync(seedPath);
if (hasSeed) {
    const seedSql = fs.readFileSync(seedPath, "utf8");
    db.exec(seedSql);
}

db.close();

console.log(`SQLite DB ready at: ${dbPath}`);