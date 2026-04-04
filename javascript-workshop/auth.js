const db = require('./db');

async function add_user(username, password) {
  return db.add_user(username, password);
}

async function check_login(username, password) {
  const user = await db.get_user_by_username(username);
  if (!user) return false;
  const stored_password = user.password || user[2];
  return stored_password === password;
}

module.exports = { add_user, check_login };
