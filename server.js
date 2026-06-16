const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// POST /login - Authenticate user
// Accepts: { username, password } OR { email, password }
app.post('/login', async (req, res) => {
  const { email, username, password } = req.body;

  // Support login via username or email field
  const loginIdentifier = username || email;

  console.log('\n========== LOGIN ATTEMPT ==========');
  console.log('📨 Raw body received :', JSON.stringify(req.body));
  console.log('📧 Login identifier  :', loginIdentifier, '(from field:', username ? 'username' : 'email', ')');
  console.log('🔑 Password received :', password ? `"${password}" (length: ${password.length})` : 'MISSING');

  if (!loginIdentifier || !password) {
    console.log('❌ Missing identifier or password');
    return res.status(400).json({ error: 'Username/email and password are required' });
  }

  try {
    // Query by username OR email to support both login flows
    const result = await db.query(
      `SELECT * FROM users WHERE (username = $1 OR email = $1) AND status = 'ACTIVE'`,
      [loginIdentifier]
    );

    console.log('📦 DB rows found     :', result.rows.length);

    if (result.rows.length === 0) {
      console.log('❌ No active user found with identifier:', loginIdentifier);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    console.log('👤 User from DB      :', JSON.stringify({
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      org_id: user.org_id,
      role_id: user.role_id,
      status: user.status
    }));
    console.log('🔐 Password in DB    :', user.password
      ? (user.password.startsWith('$2b$') ? `[bcrypt hash] ${user.password.substring(0, 20)}...` : `[plain text] "${user.password}"`)
      : 'NULL/EMPTY'
    );

    // Verify password: Check plain text first (if inserted manually), then try bcrypt
    let validPassword = false;
    if (password === user.password) {
      validPassword = true;
      console.log('✅ Password matched (plain text)');
    } else {
      try {
        validPassword = await bcrypt.compare(password, user.password);
        console.log('🔐 bcrypt compare result:', validPassword);
      } catch (e) {
        console.log('⚠️  bcrypt compare error:', e.message);
        validPassword = false;
      }
    }

    if (!validPassword) {
      console.log('❌ Password mismatch — login denied');
      console.log('   Input password  :', `"${password}"`);
      console.log('   DB password     :', user.password || 'NULL');
      console.log('====================================\n');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: user.user_id,
        id: user.user_id, // Backward compatibility
        email: user.email,
        org_id: user.org_id,
        role_id: user.role_id
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('🎉 Login successful for:', user.username, '(', user.email, ')');
    console.log('====================================\n');

    res.json({
      message: 'Login successful',
      token,
      user: {
        user_id: user.user_id,
        id: user.user_id, // Backward compatibility
        username: user.username,
        email: user.email,
        org_id: user.org_id,
        role_id: user.role_id
      }
    });

  } catch (err) {
    console.error('🔥 Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /logout - Handle logout
// For JWT, logout is primarily handled client-side by discarding the token.
// A backend endpoint provides a clean confirmation and a place to add token blacklisting if needed.
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful. Please discard your token.' });
});

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

// GET /api/vehicle/inventory - Get products loaded in driver's vehicle
app.get('/api/vehicle/inventory', authenticateToken, async (req, res) => {
  const userId = req.user.user_id || req.user.id;
  const orgId = req.user.org_id;

  console.log('\n========== VEHICLE INVENTORY ACCESS ==========');
  console.log('👤 User ID :', userId);
  console.log('🏢 Org ID  :', orgId);

  if (!userId || !orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing user_id or org_id' });
  }

  try {
    // 1. Find the active/open supply/trip assignment for the logged-in user
    const supplyResult = await db.query(
      `SELECT sm.supply_id, sm.date, sm.vehicle_id, v.vehicle_no, v.vehicle_name 
       FROM supply_management sm
       JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
       WHERE sm.user_id = $1 AND sm.status = 'OPEN' AND sm.org_id = $2
       ORDER BY sm.created_on DESC
       LIMIT 1`,
      [userId, orgId]
    );

    if (supplyResult.rows.length === 0) {
      console.log('⚠️ No active/open trip found for driver');
      return res.status(404).json({ error: 'No active trip assignment found for this driver' });
    }

    const activeTrip = supplyResult.rows[0];
    console.log('🚚 Active Trip ID:', activeTrip.supply_id, '| Vehicle:', activeTrip.vehicle_no);

    // 2. Fetch all supply items (van inventory manifest) grouped by category
    const itemsResult = await db.query(
      `SELECT 
        c.category_id,
        c.category_name,
        p.product_id,
        p.product_name,
        p.sku_code,
        p.unit,
        p.rate::float AS rate,
        si.quantity_loaded::float AS quantity_loaded
       FROM supply_items si
       JOIN product p ON si.product_id = p.product_id
       JOIN category c ON p.category_id = c.category_id
       WHERE si.supply_id = $1 AND si.org_id = $2
       ORDER BY c.category_name, p.product_name`,
      [activeTrip.supply_id, orgId]
    );

    // 3. Structure the response grouped by category
    const categoriesMap = {};
    let grandTotalLoadedQuantity = 0;
    let grandTotalLoadedValue = 0;

    itemsResult.rows.forEach(row => {
      const { category_id, category_name, product_id, product_name, sku_code, unit, rate, quantity_loaded } = row;

      if (!categoriesMap[category_id]) {
        categoriesMap[category_id] = {
          category_id,
          category_name,
          total_products_count: 0,
          total_quantity_loaded: 0,
          total_category_value: 0,
          products: []
        };
      }

      const totalProductPrice = quantity_loaded * rate;

      categoriesMap[category_id].products.push({
        product_id,
        sku_code,
        product_name,
        unit,
        rate,
        quantity_loaded,
        total_price: totalProductPrice
      });

      categoriesMap[category_id].total_products_count += 1;
      categoriesMap[category_id].total_quantity_loaded += quantity_loaded;
      categoriesMap[category_id].total_category_value += totalProductPrice;

      grandTotalLoadedQuantity += quantity_loaded;
      grandTotalLoadedValue += totalProductPrice;
    });

    const categoriesList = Object.values(categoriesMap);

    console.log('📦 Categories formatted:', categoriesList.length);
    console.log('==============================================\n');

    res.json({
      supply_id: activeTrip.supply_id,
      date: activeTrip.date,
      vehicle: {
        vehicle_id: activeTrip.vehicle_id,
        vehicle_no: activeTrip.vehicle_no,
        vehicle_name: activeTrip.vehicle_name
      },
      grand_total_quantity_loaded: grandTotalLoadedQuantity,
      grand_total_value: grandTotalLoadedValue,
      categories: categoriesList
    });

  } catch (err) {
    console.error('🔥 Error fetching vehicle inventory:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/vehicle/dashboard-summary - Get dashboard stats and remaining stock for driver's vehicle
app.get('/api/vehicle/dashboard-summary', authenticateToken, async (req, res) => {
  const userId = req.user.user_id || req.user.id;
  const orgId = req.user.org_id;

  console.log('\n========== VEHICLE DASHBOARD SUMMARY ACCESS ==========');
  console.log('👤 User ID :', userId);
  console.log('🏢 Org ID  :', orgId);

  if (!userId || !orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing user_id or org_id' });
  }

  try {
    // 1. Find the active/open supply/trip assignment for the logged-in user
    const supplyResult = await db.query(
      `SELECT sm.supply_id, sm.date, sm.vehicle_id, sm.areas_covered, v.vehicle_no, v.vehicle_name, o.org_name AS organization_name 
       FROM supply_management sm
       JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
       JOIN organizations o ON sm.org_id = o.org_id
       WHERE sm.user_id = $1 AND sm.status = 'OPEN' AND sm.org_id = $2
       ORDER BY sm.created_on DESC
       LIMIT 1`,
      [userId, orgId]
    );

    if (supplyResult.rows.length === 0) {
      console.log('⚠️ No active/open trip found for driver');
      return res.status(404).json({ error: 'No active trip assignment found for this driver' });
    }

    const activeTrip = supplyResult.rows[0];
    const supplyId = activeTrip.supply_id;
    console.log('🚚 Active Trip ID:', supplyId, '| Vehicle:', activeTrip.vehicle_no);

    // 2. Fetch summary stats for the dashboard:
    // - Total number of stocks loaded in the vehicle
    const loadedStockResult = await db.query(
      `SELECT COALESCE(SUM(quantity_loaded), 0.00)::float AS total_loaded
       FROM supply_items
       WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    // - Sold stocks count (total quantity sold)
    const soldStockResult = await db.query(
      `SELECT COALESCE(SUM(si.quantity_sold), 0.00)::float AS total_sold
       FROM sales_items si
       JOIN sales_transactions st ON si.sales_id = st.sales_id
       WHERE st.supply_id = $1 AND st.org_id = $2`,
      [supplyId, orgId]
    );

    // - Total sales count (invoices) and total sales amount (revenue)
    const salesStatsResult = await db.query(
      `SELECT 
         COUNT(sales_id)::int AS total_sales_count,
         COALESCE(SUM(total_amount), 0.00)::float AS total_sales_amount
       FROM sales_transactions
       WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    const totalLoaded = loadedStockResult.rows[0].total_loaded;
    const totalSold = soldStockResult.rows[0].total_sold;
    const totalSalesCount = salesStatsResult.rows[0].total_sales_count;
    const totalSalesAmount = salesStatsResult.rows[0].total_sales_amount;

    // - Fetch sales stats grouped by area
    const areaSalesResult = await db.query(
      `SELECT 
         s.area_name,
         COUNT(st.sales_id)::int AS sales_count,
         COALESCE(SUM(st.total_amount), 0.00)::float AS sales_amount
       FROM sales_transactions st
       JOIN shops s ON st.shop_id = s.shop_id
       WHERE st.supply_id = $1 AND st.org_id = $2
       GROUP BY s.area_name`,
      [supplyId, orgId]
    );

    // Parse areas covered (comma separated)
    const assignedAreas = activeTrip.areas_covered
      ? activeTrip.areas_covered.split(',').map(a => a.trim()).filter(Boolean)
      : [];

    const areaSalesMap = {};
    areaSalesResult.rows.forEach(row => {
      if (row.area_name) {
        areaSalesMap[row.area_name.trim().toLowerCase()] = {
          area_name: row.area_name.trim(),
          sales_count: row.sales_count,
          sales_amount: row.sales_amount
        };
      }
    });

    const processedKeys = new Set();
    const breakdown = [];

    // Process assigned areas first
    assignedAreas.forEach(area => {
      const key = area.toLowerCase();
      processedKeys.add(key);
      const salesData = areaSalesMap[key];
      const salesCount = salesData ? salesData.sales_count : 0;
      const salesAmount = salesData ? salesData.sales_amount : 0;
      const coveragePercentage = totalSalesCount > 0
        ? parseFloat(((salesCount / totalSalesCount) * 100).toFixed(2))
        : 0.00;

      breakdown.push({
        area_name: area,
        sales_count: salesCount,
        sales_amount: salesAmount,
        coverage_percentage: coveragePercentage,
        is_assigned: true
      });
    });

    // Process any other/unassigned areas that got sales
    areaSalesResult.rows.forEach(row => {
      if (row.area_name) {
        const key = row.area_name.trim().toLowerCase();
        if (!processedKeys.has(key)) {
          const coveragePercentage = totalSalesCount > 0
            ? parseFloat(((row.sales_count / totalSalesCount) * 100).toFixed(2))
            : 0.00;

          breakdown.push({
            area_name: row.area_name.trim(),
            sales_count: row.sales_count,
            sales_amount: row.sales_amount,
            coverage_percentage: coveragePercentage,
            is_assigned: false
          });
        }
      }
    });

    // Find the area covered most (highest sales_count, then highest sales_amount)
    let mostCoveredArea = 'None';
    let mostCoveredAreaPercentage = 0.00;

    if (totalSalesCount > 0 && breakdown.length > 0) {
      const sortedBreakdown = [...breakdown].sort((a, b) => {
        if (b.sales_count !== a.sales_count) {
          return b.sales_count - a.sales_count;
        }
        return b.sales_amount - a.sales_amount;
      });

      if (sortedBreakdown[0].sales_count > 0) {
        mostCoveredArea = sortedBreakdown[0].area_name;
        mostCoveredAreaPercentage = sortedBreakdown[0].coverage_percentage;
      }
    }

    // 3. Fetch current stocks summary (stocks loaded, sold, and remaining in the vehicle) per product
    const stocksSummaryResult = await db.query(
      `SELECT 
         p.product_id,
         p.product_name,
         p.sku_code,
         p.unit,
         c.category_name,
         p.rate::float AS rate,
         COALESCE(si.quantity_loaded, 0.00)::float AS quantity_loaded,
         COALESCE(sold.quantity_sold, 0.00)::float AS quantity_sold,
         (COALESCE(si.quantity_loaded, 0.00) - COALESCE(sold.quantity_sold, 0.00))::float AS quantity_remaining
       FROM supply_items si
       JOIN product p ON si.product_id = p.product_id
       JOIN category c ON p.category_id = c.category_id
       LEFT JOIN (
         SELECT s_item.product_id, SUM(s_item.quantity_sold) AS quantity_sold
         FROM sales_items s_item
         JOIN sales_transactions st ON s_item.sales_id = st.sales_id
         WHERE st.supply_id = $1 AND st.org_id = $2
         GROUP BY s_item.product_id
       ) sold ON si.product_id = sold.product_id
       WHERE si.supply_id = $1 AND si.org_id = $2
       ORDER BY c.category_name, p.product_name`,
      [supplyId, orgId]
    );

    console.log('📈 Dashboard stats fetched. Invoices:', totalSalesCount, '| Total Sold:', totalSold);
    console.log('======================================================\n');

    res.json({
      supply_id: supplyId,
      date: activeTrip.date,
      organization_name: activeTrip.organization_name,
      vehicle: {
        vehicle_id: activeTrip.vehicle_id,
        vehicle_no: activeTrip.vehicle_no,
        vehicle_name: activeTrip.vehicle_name
      },
      areas_assigned: activeTrip.areas_covered,
      area_coverage_summary: {
        most_covered_area: mostCoveredArea,
        most_covered_area_percentage: mostCoveredAreaPercentage,
        breakdown: breakdown
      },
      stats: {
        total_stocks_loaded: totalLoaded,
        total_stocks_sold: totalSold,
        total_sales_count: totalSalesCount,
        total_sales_amount: totalSalesAmount
      },
      stocks_summary: stocksSummaryResult.rows
    });

  } catch (err) {
    console.error('🔥 Error fetching vehicle dashboard summary:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/vehicle/assigned-shops - Get list of shops matching the driver's assigned areas
app.get('/api/vehicle/assigned-shops', authenticateToken, async (req, res) => {
  const userId = req.user.user_id || req.user.id;
  const orgId = req.user.org_id;

  console.log('\n========== ASSIGNED SHOPS ACCESS ==========');
  console.log('👤 User ID :', userId);
  console.log('🏢 Org ID  :', orgId);

  if (!userId || !orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing user_id or org_id' });
  }

  try {
    // 1. Find the active/open supply/trip assignment for the logged-in user
    const supplyResult = await db.query(
      `SELECT sm.supply_id, sm.areas_covered 
       FROM supply_management sm
       WHERE sm.user_id = $1 AND sm.status = 'OPEN' AND sm.org_id = $2
       ORDER BY sm.created_on DESC
       LIMIT 1`,
      [userId, orgId]
    );

    if (supplyResult.rows.length === 0) {
      console.log('⚠️ No active/open trip found for driver');
      return res.status(404).json({ error: 'No active trip assignment found for this driver' });
    }

    const activeTrip = supplyResult.rows[0];
    const rawAreas = activeTrip.areas_covered || '';

    // Parse areas to lower-cased and trimmed array
    const areaList = rawAreas
      ? rawAreas.split(',').map(a => a.trim().toLowerCase()).filter(Boolean)
      : [];

    console.log('🚚 Active Trip ID:', activeTrip.supply_id, '| Assigned Areas:', rawAreas);

    if (areaList.length === 0) {
      console.log('⚠️ No areas assigned to this trip');
      return res.json({
        supply_id: activeTrip.supply_id,
        areas_covered: rawAreas,
        shops_by_area: {}
      });
    }

    // 2. Retrieve active shops in the assigned areas with their pending balance
    const shopsResult = await db.query(
      `SELECT 
         s.shop_id,
         s.shop_name,
         s.owner_name,
         s.contact_person,
         s.phone,
         s.address,
         s.city,
         s.area_name,
         s.status,
         COALESCE((SELECT SUM(total_amount) - SUM(paid_amount) FROM sales_transactions WHERE shop_id = s.shop_id AND org_id = s.org_id), 0.00)::float AS pending_balance
       FROM shops s
       WHERE s.org_id = $1 AND LOWER(TRIM(s.area_name)) = ANY($2) AND s.status = 'ACTIVE'
       ORDER BY s.area_name, s.shop_name`,
      [orgId, areaList]
    );

    // 3. Group shops by area name (preserving the casing from DB, falling back to assigned areas)
    const groupedShops = {};

    // Initialize groupedShops with the assigned areas to keep the list clean
    rawAreas.split(',').map(a => a.trim()).filter(Boolean).forEach(area => {
      groupedShops[area] = [];
    });

    shopsResult.rows.forEach(shop => {
      const dbAreaName = shop.area_name ? shop.area_name.trim() : '';

      // Find the matching assigned area key (case-insensitively) to group under
      const matchKey = Object.keys(groupedShops).find(
        key => key.toLowerCase() === dbAreaName.toLowerCase()
      ) || dbAreaName;

      if (!groupedShops[matchKey]) {
        groupedShops[matchKey] = [];
      }

      groupedShops[matchKey].push({
        shop_id: shop.shop_id,
        shop_name: shop.shop_name,
        owner_name: shop.owner_name,
        contact_person: shop.contact_person,
        phone: shop.phone,
        address: shop.address,
        city: shop.city,
        status: shop.status,
        pending_balance: shop.pending_balance
      });
    });

    console.log('📦 Found matching shops:', shopsResult.rows.length);
    console.log('===========================================\n');

    res.json({
      supply_id: activeTrip.supply_id,
      areas_covered: rawAreas,
      shops_by_area: groupedShops
    });

  } catch (err) {
    console.error('🔥 Error fetching assigned shops:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/vehicle/add-shop - Add a new shop validated against driver's assigned areas
app.post('/api/vehicle/add-shop', authenticateToken, async (req, res) => {
  const userId = req.user.user_id || req.user.id;
  const orgId = req.user.org_id;

  const { shop_name, owner_name, contact_person, phone, address, city, area_name } = req.body;

  console.log('\n========== ADD SHOP TO ASSIGNED AREAS ==========');
  console.log('👤 User ID   :', userId);
  console.log('🏢 Org ID    :', orgId);
  console.log('🏪 Shop Name :', shop_name);
  console.log('📍 Area Name :', area_name);

  if (!userId || !orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing user_id or org_id' });
  }

  if (!shop_name || !area_name) {
    return res.status(400).json({ error: 'Shop name and area name are required' });
  }

  try {
    // 1. Find the active/open supply/trip assignment for the logged-in user
    const supplyResult = await db.query(
      `SELECT sm.supply_id, sm.areas_covered 
       FROM supply_management sm
       WHERE sm.user_id = $1 AND sm.status = 'OPEN' AND sm.org_id = $2
       ORDER BY sm.created_on DESC
       LIMIT 1`,
      [userId, orgId]
    );

    if (supplyResult.rows.length === 0) {
      console.log('⚠️ No active/open trip found for driver');
      return res.status(404).json({ error: 'No active trip assignment found for this driver' });
    }

    const activeTrip = supplyResult.rows[0];
    const rawAreas = activeTrip.areas_covered || '';

    // Parse areas to lower-cased and trimmed array
    const areaList = rawAreas
      ? rawAreas.split(',').map(a => a.trim().toLowerCase()).filter(Boolean)
      : [];

    // 2. Validate that the input area_name is in the active trip's areas_covered
    const cleanedInputArea = area_name.trim();
    const isAssigned = areaList.includes(cleanedInputArea.toLowerCase());

    if (!isAssigned) {
      console.log(`❌ Area validation failed. "${cleanedInputArea}" is not in assigned areas: "${rawAreas}"`);
      return res.status(400).json({
        error: `Area "${cleanedInputArea}" is not assigned to your current active trip.`
      });
    }

    // 3. Insert the new shop into the database
    const insertResult = await db.query(
      `INSERT INTO shops (
         shop_name,
         owner_name,
         contact_person,
         phone,
         address,
         city,
         area_name,
         org_id,
         created_by,
         updated_by
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        shop_name.trim(),
        owner_name ? owner_name.trim() : null,
        contact_person ? contact_person.trim() : null,
        phone ? phone.trim() : null,
        address ? address.trim() : null,
        city ? city.trim() : null,
        cleanedInputArea,
        orgId,
        userId,
        userId
      ]
    );

    const newShop = insertResult.rows[0];
    console.log('🎉 New shop created successfully with ID:', newShop.shop_id);
    console.log('================================================\n');

    res.status(201).json({
      message: 'Shop created successfully',
      shop: newShop
    });

  } catch (err) {
    console.error('🔥 Error adding shop:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/products - Get list of active categories and products with their rates
app.get('/api/products', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== PRODUCT CATALOG ACCESS ==========');
  console.log('🏢 Org ID :', orgId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // 1. Fetch all active products joined with their category details
    const result = await db.query(
      `SELECT 
         c.category_id,
         c.category_name,
         c.description AS category_description,
         p.product_id,
         p.sku_code,
         p.product_name,
         p.description AS product_description,
         p.unit,
         p.rate::float AS rate,
         p.status
       FROM product p
       JOIN category c ON p.category_id = c.category_id
       WHERE p.org_id = $1 AND p.status = 'ACTIVE'
       ORDER BY c.category_name, p.product_name`,
      [orgId]
    );

    // 2. Format and group the products by category in JavaScript
    const categoriesMap = {};

    result.rows.forEach(row => {
      const {
        category_id,
        category_name,
        category_description,
        product_id,
        sku_code,
        product_name,
        product_description,
        unit,
        rate,
        status
      } = row;

      if (!categoriesMap[category_id]) {
        categoriesMap[category_id] = {
          category_id,
          category_name,
          category_description,
          products: []
        };
      }

      categoriesMap[category_id].products.push({
        product_id,
        sku_code,
        product_name,
        product_description,
        unit,
        rate,
        status
      });
    });

    const categoriesList = Object.values(categoriesMap);

    console.log('📦 Catalog fetched. Total Categories:', categoriesList.length, '| Total Products:', result.rows.length);
    console.log('============================================\n');

    res.json(categoriesList);

  } catch (err) {
    console.error('🔥 Error fetching product catalog:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// POST /api/sales/record-transaction
// Records a full sale: transaction + items sold + payment
// ============================================================
app.post('/api/sales/record-transaction', authenticateToken, async (req, res) => {
  const userId = req.user.user_id || req.user.id;
  const orgId = req.body.org_id || req.user.org_id;

  if (!orgId) {
    return res.status(400).json({ error: 'org_id is required.' });
  }

  const {
    shop_id,        // integer — the shop being sold to
    supply_id,      // integer — active trip/supply ID
    items,          // array of { product_id, quantity_sold, rate_at_sale }
    paid_amount,    // numeric — amount paid right now (can be 0)
    payment_type,   // string  — 'CASH' | 'UPI' | 'CREDIT' etc.
    description     // optional string note
  } = req.body;

  // ── Basic validation ──────────────────────────────────────
  if (!shop_id || !supply_id || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({
      error: 'shop_id, supply_id, and at least one item are required.'
    });
  }
  if (paid_amount === undefined || paid_amount === null) {
    return res.status(400).json({ error: 'paid_amount is required (use 0 if fully on credit).' });
  }
  if (!payment_type) {
    return res.status(400).json({ error: 'payment_type is required.' });
  }

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Calculate total_amount from items
    let total_amount = 0;
    for (const item of items) {
      if (!item.product_id || item.quantity_sold == null || item.rate_at_sale == null) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: 'Each item must have product_id, quantity_sold, and rate_at_sale.'
        });
      }
      total_amount += parseFloat(item.quantity_sold) * parseFloat(item.rate_at_sale);
    }

    if (parseFloat(paid_amount) < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Paid amount cannot be negative.'
      });
    }

    const pending_amount = total_amount - parseFloat(paid_amount);

    // 2. Insert into sales_transactions
    const txnResult = await client.query(
      `INSERT INTO sales_transactions
         (supply_id, shop_id, total_amount, paid_amount, pending_amount, payment_type, description, org_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING sales_id`,
      [supply_id, shop_id, total_amount.toFixed(2), paid_amount, pending_amount.toFixed(2), payment_type, description || null, orgId]
    );
    const sales_id = txnResult.rows[0].sales_id;

    // 3. Insert each item into sales_items
    for (const item of items) {
      const item_total = parseFloat(item.quantity_sold) * parseFloat(item.rate_at_sale);
      await client.query(
        `INSERT INTO sales_items
           (sales_id, product_id, quantity_sold, rate_at_sale, total_amount, org_id, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
        [sales_id, item.product_id, item.quantity_sold, item.rate_at_sale, item_total.toFixed(2), orgId, userId]
      );
    }

    // 4. Insert into payments (only if something was paid)
    if (parseFloat(paid_amount) > 0) {
      await client.query(
        `INSERT INTO payments
           (shop_id, sales_id, amount_paid, payment_type, collected_by, org_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [shop_id, sales_id, paid_amount, payment_type, userId, orgId]
      );
    }

    await client.query('COMMIT');

    console.log(`\n✅ Transaction recorded | sales_id: ${sales_id} | shop: ${shop_id} | total: ${total_amount.toFixed(2)} | paid: ${paid_amount} | pending: ${pending_amount.toFixed(2)}`);

    res.status(201).json({
      message: 'Transaction recorded successfully.',
      sales_id,
      shop_id,
      supply_id,
      total_amount: parseFloat(total_amount.toFixed(2)),
      paid_amount: parseFloat(paid_amount),
      pending_amount: parseFloat(pending_amount.toFixed(2)),
      payment_type,
      items_count: items.length
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('🔥 Error recording transaction:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  } finally {
    client.release();
  }
});

// ============================================================
// GET /api/sales/report/:supply_id
// Returns sales summary and product breakdown for a given supply ID
// ============================================================
app.get('/api/sales/report/:supply_id', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;
  const supplyId = req.params.supply_id;

  if (!supplyId) {
    return res.status(400).json({ error: 'supply_id is required.' });
  }

  try {
    // 1. Fetch trip and vehicle info
    const tripResult = await db.query(
      `SELECT sm.supply_id, sm.date, v.vehicle_no, v.vehicle_name, u.username AS driver_name
       FROM supply_management sm
       LEFT JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
       LEFT JOIN users u ON sm.user_id = u.user_id
       WHERE sm.supply_id = $1 AND sm.org_id = $2 AND sm.status = 'OPEN'`,
      [supplyId, orgId]
    );

    if (tripResult.rows.length === 0) {
      return res.status(404).json({ error: 'Supply trip assignment not found or unauthorized.' });
    }

    const tripInfo = tripResult.rows[0];

    // 2. Fetch sales summary details:
    // - total_sales_amount, total_amount_collected, total_pending_amount, shops_visited
    const summaryResult = await db.query(
      `SELECT 
         COALESCE(SUM(total_amount), 0.00)::float AS total_sales_amount,
         COALESCE(SUM(paid_amount), 0.00)::float AS total_amount_collected,
         COALESCE(SUM(pending_amount), 0.00)::float AS total_pending_amount,
         COUNT(DISTINCT shop_id)::int AS shops_visited
       FROM sales_transactions
       WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    // - cash_in_hand (sum of paid_amount in transactions where payment_type is CASH)
    const cashResult = await db.query(
      `SELECT COALESCE(SUM(paid_amount), 0.00)::float AS cash_in_hand
       FROM sales_transactions
       WHERE supply_id = $1 AND payment_type = 'CASH' AND org_id = $2`,
      [supplyId, orgId]
    );

    // - total quantity loaded (from supply_items)
    const loadedResult = await db.query(
      `SELECT COALESCE(SUM(quantity_loaded), 0.00)::float AS total_quantity_loaded
       FROM supply_items
       WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    // - total quantity sold (from sales_items)
    const soldResult = await db.query(
      `SELECT COALESCE(SUM(si.quantity_sold), 0.00)::float AS total_quantity_sold
       FROM sales_items si
       JOIN sales_transactions st ON si.sales_id = st.sales_id
       WHERE st.supply_id = $1 AND st.org_id = $2`,
      [supplyId, orgId]
    );

    const summary = summaryResult.rows[0];
    const cashInHand = cashResult.rows[0].cash_in_hand;
    const totalQuantityLoaded = loadedResult.rows[0].total_quantity_loaded;
    const totalQuantitySold = soldResult.rows[0].total_quantity_sold;
    const totalQuantityRemaining = totalQuantityLoaded - totalQuantitySold;

    // 3. Fetch product sales breakdown
    const breakdownResult = await db.query(
      `SELECT 
         p.product_id,
         p.product_name,
         p.rate::float AS rate,
         p.unit,
         COALESCE(si.quantity_loaded, 0.00)::float AS quantity_loaded,
         COALESCE(SUM(sitems.quantity_sold), 0.00)::float AS quantity_sold,
         (COALESCE(si.quantity_loaded, 0.00) - COALESCE(SUM(sitems.quantity_sold), 0.00))::float AS quantity_remaining,
         COALESCE(SUM(sitems.total_amount), 0.00)::float AS sales_amount
       FROM supply_items si
       JOIN product p ON si.product_id = p.product_id
       LEFT JOIN sales_transactions st ON st.supply_id = si.supply_id AND st.org_id = si.org_id
       LEFT JOIN sales_items sitems ON sitems.sales_id = st.sales_id AND sitems.product_id = p.product_id
       WHERE si.supply_id = $1 AND si.org_id = $2
       GROUP BY p.product_id, p.product_name, p.rate, p.unit, si.quantity_loaded
       ORDER BY p.product_name`,
      [supplyId, orgId]
    );

    console.log(`\n📊 Generated Sales Report | supply_id: ${supplyId} | shops visited: ${summary.shops_visited} | sales: ₹${summary.total_sales_amount}`);

    res.json({
      supply_id: parseInt(supplyId),
      date: tripInfo.date,
      vehicle_no: tripInfo.vehicle_no,
      vehicle_name: tripInfo.vehicle_name,
      driver_name: tripInfo.driver_name,
      summary: {
        total_sales_amount: summary.total_sales_amount,
        total_amount_collected: summary.total_amount_collected,
        total_pending_amount: summary.total_pending_amount,
        shops_visited: summary.shops_visited,
        cash_in_hand: cashInHand,
        total_quantity_loaded: totalQuantityLoaded,
        total_quantity_sold: totalQuantitySold,
        total_quantity_remaining: totalQuantityRemaining
      },
      products_breakdown: breakdownResult.rows
    });

  } catch (err) {
    console.error('🔥 Error generating sales report:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// Basic test route
app.get('/', (req, res) => {
  res.send('Backend API is running...');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
