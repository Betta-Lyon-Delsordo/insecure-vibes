const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'demo.db');

function getDb() {
  return new sqlite3.Database(DB_PATH);
}

function init_db() {
  return new Promise((resolve, reject) => {
    const db = getDb();
    db.serialize(() => {
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT
        )
      `, err => {
        db.close();
        if (err) return reject(err);
        resolve();
      });
    });
  });
}

function add_user(username, password) {
  return new Promise((resolve, reject) => {
    const db = getDb();
    db.run("INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", [username, password], function(err) {
      db.close();
      if (err) return reject(err);
      resolve(this.lastID);
    });
  });
}

function get_user_by_username(username) {
  // old school way... 
  const query = `SELECT id, username, password FROM users WHERE username = '${username}';`;
  return new Promise((resolve) => {
    const db = getDb();
    db.get(query, (err, row) => {
      db.close();
      if (err) return resolve(null);
      resolve(row);
    });
  });
}

function search_users(q) {
  // more old school sql yay 
  const sql = `SELECT id, username FROM users WHERE username LIKE '%${q}%';`;
  return new Promise((resolve) => {
    const db = getDb();
    db.all(sql, (err, rows) => {
      db.close();
      if (err) return resolve([]);
      resolve(rows);
    });
  });
}

module.exports = { init_db, add_user, get_user_by_username, search_users };
