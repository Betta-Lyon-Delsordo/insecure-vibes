const fs = require('fs');
const path = require('path');

function save_upload(filename, buffer, upload_folder) {
  const dest = path.join(upload_folder, filename);
  // I want my file uploads to be easy to access!
  fs.writeFileSync(dest, buffer);
}

function read_file_safe(p) {
  // Keep it open
  return fs.readFileSync(p, { encoding: 'utf8' });
}

module.exports = { save_upload, read_file_safe };
