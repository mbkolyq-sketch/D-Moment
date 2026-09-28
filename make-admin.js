'use strict';
require('dotenv').config();
const path = require('path');
const Database = require('better-sqlite3');
const email = process.argv[2];
if (!email) { console.error('الاستخدام: npm run make-admin -- you@example.com'); process.exit(1); }
const db = new Database(path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'lahzatak.db'));
const r = db.prepare("UPDATE users SET role='admin' WHERE email=?").run(email);
console.log(r.changes ? 'تم: ' + email + ' أصبح مشرفًا' : 'لا يوجد مستخدم بهذا البريد (سجّل حسابك أولًا)');
