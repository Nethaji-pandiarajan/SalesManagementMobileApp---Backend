const db = require('./db');

async function test() {
  console.log('Starting DB connection test using ./db.js configuration...');
  try {
    const result = await db.query('SELECT now()');
    console.log('✅ Connection successful!');
    console.log('Database time:', result.rows[0]);
  } catch (err) {
    console.error('❌ Connection failed:');
    console.error(err);
  } finally {
    process.exit();
  }
}

test();
