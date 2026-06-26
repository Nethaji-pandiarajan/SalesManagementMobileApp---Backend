const { Pool } = require('pg');
require('dotenv').config();

const db = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false }
});

async function run() {
  try {
    // Get areas table columns
    const areaCols = await db.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'areas' ORDER BY ordinal_position`);
    console.log('\n=== areas TABLE COLUMNS ===');
    console.log(areaCols.rows.map(r => r.column_name).join(', '));

    // Get shops table columns
    const shopCols = await db.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'shops' ORDER BY ordinal_position`);
    console.log('\n=== shops TABLE COLUMNS ===');
    console.log(shopCols.rows.map(r => r.column_name).join(', '));

    // Areas data
    const areas = await db.query('SELECT * FROM areas ORDER BY area_id LIMIT 20');
    console.log('\n=== AREAS TABLE ===');
    console.table(areas.rows);

    // Sample active shops
    const shops = await db.query("SELECT shop_id, shop_name, area_name FROM shops WHERE status = 'ACTIVE' LIMIT 10");
    console.log('\n=== SHOPS (active sample) ===');
    console.table(shops.rows);

    // Active supply
    const supply = await db.query("SELECT supply_id, areas_covered FROM supply_management WHERE status = 'ACTIVE' LIMIT 5");
    console.log('\n=== ACTIVE SUPPLY ===');
    console.table(supply.rows);

    // Join test
    const match = await db.query(`
      SELECT s.area_name AS shop_area, a.area_name AS canonical_area, a.area_id
      FROM shops s
      LEFT JOIN areas a ON LOWER(TRIM(a.area_name)) = LOWER(TRIM(s.area_name))
      WHERE s.status = 'ACTIVE'
      GROUP BY s.area_name, a.area_name, a.area_id
      LIMIT 20
    `);
    console.log('\n=== SHOP area_name → areas JOIN ===');
    console.table(match.rows);

  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    await db.end();
  }
}
run();
