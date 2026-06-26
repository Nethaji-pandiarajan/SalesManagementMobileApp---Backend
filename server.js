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
      `SELECT u.*, r.role_name 
       FROM users u
       LEFT JOIN roles r ON u.role_id = r.role_id
       WHERE (u.username = $1 OR u.email = $1) AND u.status = 'ACTIVE'`,
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
      role_name: user.role_name,
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

    // Check if role is Admin or Sales Executive
    if (user.role_name !== 'Admin' && user.role_name !== 'Sales Executive') {
      console.log('❌ Login denied: User role is neither Admin nor Sales Executive:', user.role_name);
      return res.status(403).json({ error: 'Access denied. Unauthorized role.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        user_id: user.user_id,
        id: user.user_id, // Backward compatibility
        email: user.email,
        org_id: user.org_id,
        role_id: user.role_id,
        role_name: user.role_name,
        role: user.role_name ? (user.role_name.toLowerCase() === 'sales executive' ? 'salesexecutive' : user.role_name.toLowerCase()) : null
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
        role_id: user.role_id,
        role_name: user.role_name,
        role: user.role_name ? (user.role_name.toLowerCase() === 'sales executive' ? 'salesexecutive' : user.role_name.toLowerCase()) : null
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
  let token = authHeader && authHeader.split(' ')[1];

  // Support retrieving token from query parameters for browser-initiated file downloads
  if (!token && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    try {
      const userId = decoded.user_id || decoded.id;
      if (!userId) {
        return res.status(403).json({ error: 'Invalid token payload: user_id missing' });
      }

      // Verify the user is active in the database
      const userRes = await db.query('SELECT status FROM users WHERE user_id = $1', [userId]);
      if (userRes.rows.length === 0 || (userRes.rows[0].status || '').trim().toUpperCase() !== 'ACTIVE') {
        return res.status(403).json({ error: 'User is inactive' });
      }

      req.user = decoded;
      next();
    } catch (dbErr) {
      console.error('🔥 Error checking user status in authenticateToken middleware:', dbErr);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
};

// Middleware to authorize roles
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user.role || '';
    const userRoleName = req.user.role_name || '';
    const isAllowed = allowedRoles.some(role => 
      role.toLowerCase() === userRole.toLowerCase() || 
      role.toLowerCase() === userRoleName.toLowerCase() ||
      (role.toLowerCase() === 'sales executive' && userRole.toLowerCase() === 'salesexecutive') ||
      (role.toLowerCase() === 'sales driver' && userRole.toLowerCase() === 'salesdriver')
    );
    if (!isAllowed) {
      return res.status(403).json({ error: 'Access denied. Unauthorized role.' });
    }
    next();
  };
};

const getAdminVehicleList = async (orgId) => {
  const vehiclesQuery = `
    SELECT 
      v.vehicle_id,
      v.vehicle_no,
      v.vehicle_name,
      v.vehicle_owner,
      v.description,
      v.status AS vehicle_status,
      u.username AS driver_name,
      sm.supply_id,
      sm.status AS trip_status
    FROM vehicle v
    LEFT JOIN (
      SELECT DISTINCT ON (vehicle_id) vehicle_id, supply_id, status, user_id
      FROM supply_management
      WHERE date = CURRENT_DATE AND status = 'OPEN'
      ORDER BY vehicle_id, supply_id DESC
    ) sm ON v.vehicle_id = sm.vehicle_id
    LEFT JOIN users u ON sm.user_id = u.user_id
    WHERE v.org_id = $1 AND v.status IN ('ACTIVE', 'INACTIVE')
    ORDER BY v.vehicle_no
  `;
  const vehiclesResult = await db.query(vehiclesQuery, [orgId]);
  return vehiclesResult.rows;
};

const getVehicleByIdForOrg = async (vehicleId, orgId) => {
  const result = await db.query(
    `SELECT vehicle_id, vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by, created_on, updated_on
     FROM vehicle
     WHERE vehicle_id = $1 AND org_id = $2`,
    [vehicleId, orgId]
  );
  return result.rows[0] || null;
};

const normalizeVehiclePayload = (body) => {
  const vehicle_no = (body.vehicle_no || body.vehicleNo || body.registrationNo || '').toString().trim();
  const vehicle_name = (body.vehicle_name || body.vehicleName || body.name || '').toString().trim();
  const vehicle_owner = (body.vehicle_owner || body.vehicleOwner || body.owner_name || body.owner || '').toString().trim();
  const description = (body.description || '').toString().trim();
  const status = (body.status || 'ACTIVE').toString().trim().toUpperCase();

  return {
    vehicle_no,
    vehicle_name,
    vehicle_owner,
    description,
    status
  };
};

// GET /api/admin/dashboard-summary - Get financial summary stats for admin dashboard
app.get('/api/admin/dashboard-summary', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== ADMIN DASHBOARD SUMMARY ACCESS ==========');
  console.log('👤 User ID :', req.user.user_id);
  console.log('🏢 Org ID  :', orgId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // 1. Get financial summaries
    const financialsQuery = `
      SELECT
        -- Daily
        COALESCE(SUM(CASE WHEN created_on >= CURRENT_DATE THEN total_amount ELSE 0 END), 0.00)::float AS daily_sales,
        COALESCE(SUM(CASE WHEN created_on >= CURRENT_DATE THEN paid_amount ELSE 0 END), 0.00)::float AS daily_collected,
        COALESCE(SUM(CASE WHEN created_on >= CURRENT_DATE THEN pending_amount ELSE 0 END), 0.00)::float AS daily_pending,
        
        -- Weekly (Current calendar week, starting Monday)
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('week', CURRENT_DATE) THEN total_amount ELSE 0 END), 0.00)::float AS weekly_sales,
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('week', CURRENT_DATE) THEN paid_amount ELSE 0 END), 0.00)::float AS weekly_collected,
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('week', CURRENT_DATE) THEN pending_amount ELSE 0 END), 0.00)::float AS weekly_pending,
        
        -- Monthly
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('month', CURRENT_DATE) THEN total_amount ELSE 0 END), 0.00)::float AS monthly_sales,
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('month', CURRENT_DATE) THEN paid_amount ELSE 0 END), 0.00)::float AS monthly_collected,
        COALESCE(SUM(CASE WHEN created_on >= DATE_TRUNC('month', CURRENT_DATE) THEN pending_amount ELSE 0 END), 0.00)::float AS monthly_pending,
        
        -- Overall
        COALESCE(SUM(total_amount), 0.00)::float AS overall_sales,
        COALESCE(SUM(paid_amount), 0.00)::float AS overall_collected,
        COALESCE(SUM(pending_amount), 0.00)::float AS overall_pending
      FROM sales_transactions
      WHERE org_id = $1
    `;

    const financialsResult = await db.query(financialsQuery, [orgId]);
    const row = financialsResult.rows[0];

    // 2. Get all vehicles and their status with driver assigned today
    const vehicles = await getAdminVehicleList(orgId);

    // 3. Get top 5 shops by sales and return their total sales
    const shopsQuery = `
      SELECT 
        s.shop_id,
        s.shop_name,
        s.owner_name,
        s.area_name,
        COALESCE(SUM(st.total_amount), 0.00)::float AS total_sales
      FROM shops s
      JOIN sales_transactions st ON s.shop_id = st.shop_id
      WHERE s.org_id = $1
      GROUP BY s.shop_id, s.shop_name, s.owner_name, s.area_name
      ORDER BY total_sales DESC
      LIMIT 5
    `;
    const shopsResult = await db.query(shopsQuery, [orgId]);

    // Calculate sum of sales amount for top 5 shops
    const topShopsSalesSum = shopsResult.rows.reduce((sum, shop) => sum + (shop.total_sales || 0), 0);

    res.json({
      daily: {
        sales: row.daily_sales,
        collected: row.daily_collected,
        pending: row.daily_pending
      },
      weekly: {
        sales: row.weekly_sales,
        collected: row.weekly_collected,
        pending: row.weekly_pending
      },
      monthly: {
        sales: row.monthly_sales,
        collected: row.monthly_collected,
        pending: row.monthly_pending
      },
      overall: {
        sales: row.overall_sales,
        collected: row.overall_collected,
        pending: row.overall_pending
      },
      vehicles,
      top_shops: shopsResult.rows,
      top_shops_sales_sum: topShopsSalesSum
    });

  } catch (err) {
    console.error('🔥 Error fetching admin dashboard summary:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/admin/vehicles - Get vehicle list for admin dashboard
app.get('/api/admin/vehicles', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== ADMIN VEHICLES ACCESS ==========');
  console.log('🏢 Org ID :', orgId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const vehicles = await getAdminVehicleList(orgId);
    res.json({ vehicles });
  } catch (err) {
    console.error('🔥 Error fetching admin vehicles:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/vehicles - Get vehicles for the current organization
app.get('/api/vehicles', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const vehicles = await getAdminVehicleList(orgId);
    res.json({ vehicles });
  } catch (err) {
    console.error('🔥 Error fetching vehicles:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/vehicles/:vehicleId - Get a single vehicle
app.get('/api/vehicles/:vehicleId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const { vehicleId } = req.params;
  const orgId = req.user.org_id;

  try {
    const vehicle = await getVehicleByIdForOrg(vehicleId, orgId);
    if (!vehicle) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }
    res.json({ vehicle });
  } catch (err) {
    console.error('🔥 Error fetching vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/admin/vehicles - Create a new vehicle
app.post('/api/admin/vehicles', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  const payload = normalizeVehiclePayload(req.body);
  if (!payload.vehicle_no) {
    return res.status(400).json({ error: 'vehicle_no is required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO vehicle (vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
       RETURNING vehicle_id, vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by, created_on, updated_on`,
      [payload.vehicle_no, payload.vehicle_name, payload.vehicle_owner, payload.description, payload.status, orgId, userId]
    );

    res.status(201).json({ vehicle: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Vehicle number already exists' });
    }
    console.error('🔥 Error creating vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/vehicles - Create a new vehicle
app.post('/api/vehicles', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  const payload = normalizeVehiclePayload(req.body);
  if (!payload.vehicle_no) {
    return res.status(400).json({ error: 'vehicle_no is required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO vehicle (vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
       RETURNING vehicle_id, vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by, created_on, updated_on`,
      [payload.vehicle_no, payload.vehicle_name, payload.vehicle_owner, payload.description, payload.status, orgId, userId]
    );

    res.status(201).json({ vehicle: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Vehicle number already exists' });
    }
    console.error('🔥 Error creating vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// PUT /api/admin/vehicles/:vehicleId - Update a vehicle
app.put('/api/admin/vehicles/:vehicleId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const { vehicleId } = req.params;
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  try {
    const existingVehicle = await getVehicleByIdForOrg(vehicleId, orgId);
    if (!existingVehicle) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }

    const payload = normalizeVehiclePayload({ ...existingVehicle, ...req.body });
    const result = await db.query(
      `UPDATE vehicle
       SET vehicle_no = $1,
           vehicle_name = $2,
           vehicle_owner = $3,
           description = $4,
           status = $5,
           updated_by = $6,
           updated_on = CURRENT_TIMESTAMP
       WHERE vehicle_id = $7 AND org_id = $8
       RETURNING vehicle_id, vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by, created_on, updated_on`,
      [payload.vehicle_no, payload.vehicle_name, payload.vehicle_owner, payload.description, payload.status, userId, vehicleId, orgId]
    );

    res.json({ vehicle: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Vehicle number already exists' });
    }
    console.error('🔥 Error updating vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// PUT /api/vehicles/:vehicleId - Update a vehicle
app.put('/api/vehicles/:vehicleId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const { vehicleId } = req.params;
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  try {
    const existingVehicle = await getVehicleByIdForOrg(vehicleId, orgId);
    if (!existingVehicle) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }

    const payload = normalizeVehiclePayload({ ...existingVehicle, ...req.body });
    const result = await db.query(
      `UPDATE vehicle
       SET vehicle_no = $1,
           vehicle_name = $2,
           vehicle_owner = $3,
           description = $4,
           status = $5,
           updated_by = $6,
           updated_on = CURRENT_TIMESTAMP
       WHERE vehicle_id = $7 AND org_id = $8
       RETURNING vehicle_id, vehicle_no, vehicle_name, vehicle_owner, description, status, org_id, created_by, updated_by, created_on, updated_on`,
      [payload.vehicle_no, payload.vehicle_name, payload.vehicle_owner, payload.description, payload.status, userId, vehicleId, orgId]
    );

    res.json({ vehicle: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Vehicle number already exists' });
    }
    console.error('🔥 Error updating vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// DELETE /api/admin/vehicles/:vehicleId - Hard delete a vehicle
app.delete('/api/admin/vehicles/:vehicleId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const { vehicleId } = req.params;
  const orgId = req.user.org_id;

  try {
    const existingVehicle = await getVehicleByIdForOrg(vehicleId, orgId);
    if (!existingVehicle) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }

    await db.query('BEGIN');

    // Set vehicle_id to NULL in referencing table (supply_management)
    await db.query(
      `UPDATE supply_management SET vehicle_id = NULL WHERE vehicle_id = $1 AND org_id = $2`,
      [parseInt(vehicleId, 10), orgId]
    );

    // Hard delete the vehicle from database
    await db.query(
      `DELETE FROM vehicle WHERE vehicle_id = $1 AND org_id = $2`,
      [parseInt(vehicleId, 10), orgId]
    );

    await db.query('COMMIT');

    res.json({ message: 'Vehicle deleted successfully' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error deleting vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// DELETE /api/vehicles/:vehicleId - Hard delete a vehicle
app.delete('/api/vehicles/:vehicleId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const { vehicleId } = req.params;
  const orgId = req.user.org_id;

  try {
    const existingVehicle = await getVehicleByIdForOrg(vehicleId, orgId);
    if (!existingVehicle) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }

    await db.query('BEGIN');

    // Set vehicle_id to NULL in referencing table (supply_management)
    await db.query(
      `UPDATE supply_management SET vehicle_id = NULL WHERE vehicle_id = $1 AND org_id = $2`,
      [parseInt(vehicleId, 10), orgId]
    );

    // Hard delete the vehicle from database
    await db.query(
      `DELETE FROM vehicle WHERE vehicle_id = $1 AND org_id = $2`,
      [parseInt(vehicleId, 10), orgId]
    );

    await db.query('COMMIT');

    res.json({ message: 'Vehicle deleted successfully' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error deleting vehicle:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// ============================================================
// SUPPLY MANAGEMENT ENDPOINTS (Admin Daily Plans & Load Sheets)
// ============================================================

// GET /api/admin/supply - List all daily plans & load sheets with active invoice feed
app.get('/api/admin/supply', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // 1. Fetch all supply plans (trips) that are not deleted or inactive
    const supplyQuery = `
      SELECT supply_id, date, vehicle_id, user_id, areas_covered, status
      FROM supply_management
      WHERE org_id = $1 AND (status IS DISTINCT FROM 'DELETED' AND status IS DISTINCT FROM 'INACTIVE')
      ORDER BY date DESC, supply_id DESC
    `;
    const supplyRes = await db.query(supplyQuery, [orgId]);

    // 2. Fetch all products
    const productsRes = await db.query(
      `SELECT product_id, product_name FROM product WHERE org_id = $1`,
      [orgId]
    );
    const productMap = {};
    productsRes.rows.forEach(p => {
      productMap[p.product_id] = p.product_name;
    });

    // 3. For each supply, resolve area names and loaded oils
    const records = [];
    for (const row of supplyRes.rows) {
      // Resolve area IDs to names
      let areaNames = '';
      if (row.areas_covered) {
        const areaIds = row.areas_covered.split(',').map(id => parseInt(id.trim())).filter(Boolean);
        if (areaIds.length > 0) {
          const areasQuery = await db.query(
            `SELECT area_name FROM areas WHERE area_id = ANY($1::int[]) AND org_id = $2`,
            [areaIds, orgId]
          );
          areaNames = areasQuery.rows.map(r => r.area_name).join(', ');
        }
      }

      // Fetch loaded supply items
      const itemsQuery = await db.query(
        `SELECT product_id, quantity_loaded FROM supply_items WHERE supply_id = $1 AND org_id = $2`,
        [row.supply_id, orgId]
      );
      const oils = {};
      itemsQuery.rows.forEach(item => {
        oils[item.product_id.toString()] = parseFloat(item.quantity_loaded).toString();
      });

      // Format date to local YYYY-MM-DD
      const formattedDate = row.date instanceof Date 
        ? row.date.toISOString().split('T')[0] 
        : row.date;

      records.push({
        supply_id: row.supply_id,
        date: formattedDate,
        vehicle_id: row.vehicle_id ? row.vehicle_id.toString() : '',
        user_id: row.user_id,
        areas_covered: row.areas_covered || '',
        area_names: areaNames,
        status: row.status,
        oils: oils
      });
    }

    // 4. Fetch all invoice feed records for these supply plans
    const invoicesQuery = `
      SELECT 
        st.sales_id AS invoice_id,
        st.supply_id,
        s.shop_name,
        to_char(st.created_on, 'HH24:MI AM') AS time,
        si.product_id AS oil_id,
        si.quantity_sold::float AS qty,
        si.total_amount::float AS value
      FROM sales_transactions st
      JOIN shops s ON st.shop_id = s.shop_id
      JOIN sales_items si ON st.sales_id = si.sales_id
      WHERE st.org_id = $1
      ORDER BY st.created_on DESC
    `;
    const invoicesRes = await db.query(invoicesQuery, [orgId]);
    const invoices = invoicesRes.rows.map(row => ({
      invoice_id: row.invoice_id,
      supply_id: row.supply_id,
      shopName: row.shop_name,
      time: row.time,
      oil_id: row.oil_id ? row.oil_id.toString() : '',
      qty: row.qty,
      value: row.value
    }));

    res.json({ records, invoices });
  } catch (err) {
    console.error('🔥 Error fetching supply management records:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/admin/supply - Create new daily plan & morning load sheet
app.post('/api/admin/supply', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  const { date, vehicle_id, user_id, areas_covered, oils } = req.body;

  if (!date || !vehicle_id || !user_id || !areas_covered) {
    return res.status(400).json({ error: 'Missing required fields: date, vehicle_id, user_id, areas_covered' });
  }

  try {
    // areas_covered contains comma-separated area IDs, e.g. "1,2"
    
    // Resolve area names to return in response
    let areaNames = '';
    const areaIds = areas_covered.split(',').map(id => parseInt(id.trim())).filter(Boolean);
    if (areaIds.length > 0) {
      const areasQuery = await db.query(
        `SELECT area_name FROM areas WHERE area_id = ANY($1::int[]) AND org_id = $2`,
        [areaIds, orgId]
      );
      areaNames = areasQuery.rows.map(r => r.area_name).join(', ');
    }

    // Start transaction to insert supply plan and items
    await db.query('BEGIN');

    const insertSupplyQuery = `
      INSERT INTO supply_management (org_id, date, vehicle_id, user_id, areas_covered, status, created_by)
      VALUES ($1, $2, $3, $4, $5, 'OPEN', $6)
      RETURNING supply_id, date, vehicle_id, user_id, areas_covered, status
    `;
    const supplyResult = await db.query(insertSupplyQuery, [
      orgId,
      date,
      parseInt(vehicle_id),
      parseInt(user_id),
      areas_covered,
      userId
    ]);

    const newSupplyId = supplyResult.rows[0].supply_id;

    // Insert supply loaded items (oils)
    if (oils && typeof oils === 'object') {
      for (const [prodId, qty] of Object.entries(oils)) {
        const quantity = parseFloat(qty);
        if (quantity > 0) {
          await db.query(
            `INSERT INTO supply_items (supply_id, product_id, quantity_loaded, quantity_returned, quantity_damaged, org_id, created_by)
             VALUES ($1, $2, $3, 0, 0, $4, $5)`,
            [newSupplyId, parseInt(prodId), quantity, orgId, userId]
          );
        }
      }
    }

    await db.query('COMMIT');

    // Return the formatted response matching what getAdminSupply returns
    const formattedDate = supplyResult.rows[0].date instanceof Date
      ? supplyResult.rows[0].date.toISOString().split('T')[0]
      : supplyResult.rows[0].date;

    res.status(201).json({
      message: 'Supply plan created successfully',
      record: {
        supply_id: newSupplyId,
        date: formattedDate,
        vehicle_id: vehicle_id.toString(),
        user_id: parseInt(user_id),
        areas_covered: areas_covered,
        area_names: areaNames,
        status: 'OPEN',
        oils: oils || {}
      }
    });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error creating supply plan:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// PUT /api/admin/supply/:supplyId - Update plan & load sheet
app.put('/api/admin/supply/:supplyId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;
  const supplyId = parseInt(req.params.supplyId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  const { date, vehicle_id, user_id, areas_covered, oils } = req.body;

  if (!date || !vehicle_id || !user_id || !areas_covered) {
    return res.status(400).json({ error: 'Missing required fields: date, vehicle_id, user_id, areas_covered' });
  }

  try {
    // areas_covered contains comma-separated area IDs, e.g. "1,2"
    
    // Resolve area names to return in response
    let areaNames = '';
    const areaIds = areas_covered.split(',').map(id => parseInt(id.trim())).filter(Boolean);
    if (areaIds.length > 0) {
      const areasQuery = await db.query(
        `SELECT area_name FROM areas WHERE area_id = ANY($1::int[]) AND org_id = $2`,
        [areaIds, orgId]
      );
      areaNames = areasQuery.rows.map(r => r.area_name).join(', ');
    }

    // Start transaction
    await db.query('BEGIN');

    // Update supply management record
    const updateSupplyQuery = `
      UPDATE supply_management
      SET date = $1, vehicle_id = $2, user_id = $3, areas_covered = $4, updated_by = $5, updated_on = CURRENT_TIMESTAMP
      WHERE supply_id = $6 AND org_id = $7
      RETURNING *
    `;
    const updateResult = await db.query(updateSupplyQuery, [
      date,
      parseInt(vehicle_id),
      parseInt(user_id),
      areas_covered,
      userId,
      supplyId,
      orgId
    ]);

    if (updateResult.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({ error: 'Supply plan not found or unauthorized' });
    }

    // Delete existing loaded items for this supply
    await db.query(
      `DELETE FROM supply_items WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    // Insert new loaded items (oils)
    if (oils && typeof oils === 'object') {
      for (const [prodId, qty] of Object.entries(oils)) {
        const quantity = parseFloat(qty);
        if (quantity > 0) {
          await db.query(
            `INSERT INTO supply_items (supply_id, product_id, quantity_loaded, quantity_returned, quantity_damaged, org_id, created_by)
             VALUES ($1, $2, $3, 0, 0, $4, $5)`,
            [supplyId, parseInt(prodId), quantity, orgId, userId]
          );
        }
      }
    }

    await db.query('COMMIT');

    const formattedDate = updateResult.rows[0].date instanceof Date
      ? updateResult.rows[0].date.toISOString().split('T')[0]
      : updateResult.rows[0].date;

    res.json({
      message: 'Supply plan updated successfully',
      record: {
        supply_id: supplyId,
        date: formattedDate,
        vehicle_id: vehicle_id.toString(),
        user_id: parseInt(user_id),
        areas_covered: areas_covered,
        area_names: areaNames,
        status: updateResult.rows[0].status,
        oils: oils || {}
      }
    });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error updating supply plan:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// DELETE /api/admin/supply/:supplyId - Delete supply plan
app.delete('/api/admin/supply/:supplyId', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const supplyId = parseInt(req.params.supplyId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // Check if there are sales transactions associated with this supply
    const salesCheck = await db.query(
      `SELECT COUNT(*) FROM sales_transactions WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    if (parseInt(salesCheck.rows[0].count) > 0) {
      return res.status(400).json({ error: 'Cannot delete supply plan with active sales transactions.' });
    }

    // Begin deletion
    await db.query('BEGIN');

    // Delete loaded supply items
    await db.query(
      `DELETE FROM supply_items WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    // Delete supply management plan
    await db.query(
      `DELETE FROM supply_management WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    await db.query('COMMIT');
    res.json({ message: 'Supply plan deleted successfully' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error deleting supply plan:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

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

    // - Fetch sales stats grouped by area (join areas table for canonical name, scoped to org)
    const areaSalesResult = await db.query(
      `SELECT 
         COALESCE(a.area_name, s.area_name) AS area_name,
         COUNT(st.sales_id)::int AS sales_count,
         COALESCE(SUM(st.total_amount), 0.00)::float AS sales_amount
       FROM sales_transactions st
       JOIN shops s ON st.shop_id = s.shop_id
       LEFT JOIN areas a ON LOWER(TRIM(a.area_name)) = LOWER(TRIM(s.area_name)) AND a.org_id = $2
       WHERE st.supply_id = $1 AND st.org_id = $2
       GROUP BY COALESCE(a.area_name, s.area_name)`,
      [supplyId, orgId]
    );

    // Parse areas_covered (comma-separated area_ids) and resolve names from areas table
    const areaIdList = activeTrip.areas_covered
      ? activeTrip.areas_covered.split(',').map(a => parseInt(a.trim())).filter(Boolean)
      : [];

    let assignedAreaNames = [];
    if (areaIdList.length > 0) {
      const areasRes = await db.query(
        `SELECT area_id, area_name FROM areas WHERE area_id = ANY($1) AND org_id = $2`,
        [areaIdList, orgId]
      );
      // Preserve the order from areas_covered
      const areaMap = {};
      areasRes.rows.forEach(r => { areaMap[r.area_id] = r.area_name; });
      assignedAreaNames = areaIdList.map(id => areaMap[id]).filter(Boolean);
    }

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
    assignedAreaNames.forEach(area => {
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
      areas_assigned: assignedAreaNames.join(', '),
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
    const rawAreaIds = activeTrip.areas_covered || '';

    // Parse comma-separated area_ids and resolve to area names from areas table
    const areaIdArr = rawAreaIds
      ? rawAreaIds.split(',').map(a => parseInt(a.trim())).filter(Boolean)
      : [];

    console.log('🚚 Active Trip ID:', activeTrip.supply_id, '| Assigned Area IDs:', rawAreaIds);

    if (areaIdArr.length === 0) {
      console.log('⚠️ No areas assigned to this trip');
      return res.json({
        supply_id: activeTrip.supply_id,
        areas_covered: [],
        shops_by_area: {}
      });
    }

    // Resolve area_ids → area_names (scoped to org)
    const areasRes = await db.query(
      `SELECT area_id, area_name FROM areas WHERE area_id = ANY($1) AND org_id = $2`,
      [areaIdArr, orgId]
    );
    const areaIdToName = {};
    areasRes.rows.forEach(r => { areaIdToName[r.area_id] = r.area_name; });
    const resolvedAreaNames = areaIdArr.map(id => areaIdToName[id]).filter(Boolean);
    const areaNameList = resolvedAreaNames.map(n => n.toLowerCase());

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
      [orgId, areaNameList]
    );

    // 3. Group shops by resolved area name
    const groupedShops = {};
    resolvedAreaNames.forEach(area => { groupedShops[area] = []; });

    shopsResult.rows.forEach(shop => {
      const dbAreaName = shop.area_name ? shop.area_name.trim() : '';

      // Find matching key case-insensitively
      const matchKey = Object.keys(groupedShops).find(
        key => key.toLowerCase() === dbAreaName.toLowerCase()
      ) || dbAreaName;

      if (!groupedShops[matchKey]) groupedShops[matchKey] = [];

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
      areas_covered: resolvedAreaNames,
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
    const rawAreaIds = activeTrip.areas_covered || '';

    // Parse comma-separated area_ids and resolve names
    const areaIdArr = rawAreaIds
      ? rawAreaIds.split(',').map(a => parseInt(a.trim())).filter(Boolean)
      : [];

    // Resolve area_ids → area names from areas table (scoped to org)
    const areasRes = await db.query(
      `SELECT area_id, area_name FROM areas WHERE area_id = ANY($1) AND org_id = $2`,
      [areaIdArr, orgId]
    );
    const areaIdToName = {};
    areasRes.rows.forEach(r => { areaIdToName[r.area_id] = r.area_name.toLowerCase(); });
    const assignedAreaNames = areaIdArr.map(id => areaIdToName[id]).filter(Boolean);

    // 2. Validate that the input area_name is in the resolved area names
    const cleanedInputArea = area_name.trim();
    const isAssigned = assignedAreaNames.includes(cleanedInputArea.toLowerCase());

    if (!isAssigned) {
      console.log(`❌ Area validation failed. "${cleanedInputArea}" is not in assigned areas: "${assignedAreaNames.join(', ')}"`);
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
  const { category_id } = req.query;

  console.log('\n========== PRODUCT CATALOG ACCESS ==========');
  console.log('🏢 Org ID      :', orgId);
  if (category_id) console.log('🆔 Category ID :', category_id);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    if (category_id) {
      // Return flat list of products for a specific category
      const result = await db.query(
        `SELECT * FROM product 
         WHERE category_id = $1 AND org_id = $2
         ORDER BY product_name`,
        [category_id, orgId]
      );
      return res.json(result.rows);
    }

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

// POST /api/products - Create a new product
app.post('/api/products', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id;
  const { sku_code, product_name, description, category_id, unit, rate, status } = req.body;

  console.log('\n========== CREATE PRODUCT ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('📦 Name   :', product_name);

  if (!product_name || !product_name.trim()) {
    return res.status(400).json({ error: 'Product name is required' });
  }
  if (rate === undefined || rate === null) {
    return res.status(400).json({ error: 'Rate is required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO product (sku_code, product_name, description, category_id, unit, rate, status, org_id, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
       RETURNING *`,
      [
        sku_code ? sku_code.trim() : null,
        product_name.trim(),
        description ? description.trim() : null,
        category_id || null,
        unit ? unit.trim() : null,
        rate,
        status || 'ACTIVE',
        orgId,
        userId
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error creating product:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/products/:id - Update an existing product
app.put('/api/products/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id;
  const productId = req.params.id;
  const { sku_code, product_name, description, category_id, unit, rate, status } = req.body;

  console.log('\n========== UPDATE PRODUCT ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🆔 ID     :', productId);

  if (!product_name || !product_name.trim()) {
    return res.status(400).json({ error: 'Product name is required' });
  }
  if (rate === undefined || rate === null) {
    return res.status(400).json({ error: 'Rate is required' });
  }

  try {
    const result = await db.query(
      `UPDATE product 
       SET sku_code = $1, product_name = $2, description = $3, category_id = $4, unit = $5, rate = $6, status = $7, updated_by = $8, updated_on = CURRENT_TIMESTAMP
       WHERE product_id = $9 AND org_id = $10
       RETURNING *`,
      [
        sku_code ? sku_code.trim() : null,
        product_name.trim(),
        description ? description.trim() : null,
        category_id || null,
        unit ? unit.trim() : null,
        rate,
        status || 'ACTIVE',
        userId,
        productId,
        orgId
      ]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found or unauthorized' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error updating product:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/products/:id - Soft delete/deactivate a product
app.delete('/api/products/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id;
  const productId = req.params.id;

  console.log('\n========== DELETE PRODUCT ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🆔 ID     :', productId);

  try {
    const result = await db.query(
      `UPDATE product 
       SET status = 'INACTIVE', updated_by = $1, updated_on = CURRENT_TIMESTAMP
       WHERE product_id = $2 AND org_id = $3
       RETURNING *`,
      [userId, productId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found or unauthorized' });
    }
    res.json({ message: 'Product deactivated successfully', product: result.rows[0] });
  } catch (err) {
    console.error('🔥 Error deactivating product:', err);
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
    const tripResult = await db.query(
      `SELECT sm.supply_id, sm.date, sm.status, sm.flagged_discrepancies,
              COALESCE(sm.actual_cash, 0.00)::float AS actual_cash, 
              COALESCE(sm.actual_upi, 0.00)::float AS actual_upi,
              v.vehicle_no, v.vehicle_name, u.username AS driver_name
       FROM supply_management sm
       LEFT JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
       LEFT JOIN users u ON sm.user_id = u.user_id
       WHERE sm.supply_id = $1 AND sm.org_id = $2`,
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

    // - upi_in_hand (sum of paid_amount in transactions where payment_type is UPI)
    const upiResult = await db.query(
      `SELECT COALESCE(SUM(paid_amount), 0.00)::float AS upi_in_hand
       FROM sales_transactions
       WHERE supply_id = $1 AND payment_type = 'UPI' AND org_id = $2`,
      [supplyId, orgId]
    );

    const summary = summaryResult.rows[0];
    const cashInHand = cashResult.rows[0].cash_in_hand;
    const upiInHand = upiResult.rows[0].upi_in_hand;
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

    let parsedDiscrepancies = [];
    if (tripInfo.flagged_discrepancies) {
      try {
        parsedDiscrepancies = JSON.parse(tripInfo.flagged_discrepancies);
        if (!Array.isArray(parsedDiscrepancies)) {
          parsedDiscrepancies = [tripInfo.flagged_discrepancies];
        }
      } catch (e) {
        parsedDiscrepancies = tripInfo.flagged_discrepancies.split(';').map(s => s.trim()).filter(Boolean);
      }
    }

    res.json({
      supply_id: parseInt(supplyId),
      date: tripInfo.date,
      status: tripInfo.status,
      vehicle_no: tripInfo.vehicle_no,
      vehicle_name: tripInfo.vehicle_name,
      driver_name: tripInfo.driver_name,
      actual_cash: tripInfo.actual_cash,
      actual_upi: tripInfo.actual_upi,
      flagged_discrepancies: parsedDiscrepancies,
      summary: {
        total_sales_amount: summary.total_sales_amount,
        total_amount_collected: summary.total_amount_collected,
        total_pending_amount: summary.total_pending_amount,
        shops_visited: summary.shops_visited,
        cash_in_hand: cashInHand,
        upi_in_hand: upiInHand,
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

// Helper to get aggregated report data for Admin
const getAdminReportsData = async (orgId, range, startDate, endDate) => {
  // 1. Build date filter and params
  let dateFilter = '';
  const queryParams = [orgId];

  if (range === 'today') {
    dateFilter = 'sm.date = CURRENT_DATE';
  } else if (range === 'yesterday') {
    dateFilter = 'sm.date = CURRENT_DATE - 1';
  } else if (range === 'week') {
    dateFilter = "sm.date >= DATE_TRUNC('week', CURRENT_DATE)";
  } else if (range === 'custom') {
    if (!startDate || !endDate) {
      throw new Error('startDate and endDate are required for custom range.');
    }
    dateFilter = 'sm.date >= $2 AND sm.date <= $3';
    queryParams.push(startDate, endDate);
  } else {
    // Default to today
    dateFilter = 'sm.date = CURRENT_DATE';
  }

  // 2. Fetch matching supply plan IDs in that range
  const supplyPlansRes = await db.query(
    `SELECT supply_id FROM supply_management sm 
     WHERE sm.org_id = $1 
       AND (sm.status IS DISTINCT FROM 'DELETED' AND sm.status IS DISTINCT FROM 'INACTIVE') 
       AND ${dateFilter}`,
    queryParams
  );
  const supplyIds = supplyPlansRes.rows.map(r => r.supply_id);

  // Default label to show on report
  let dateLabel = '';
  if (range === 'today') dateLabel = 'Today';
  else if (range === 'yesterday') dateLabel = 'Yesterday';
  else if (range === 'week') dateLabel = 'This Week';
  else if (range === 'custom') dateLabel = `${startDate} to ${endDate}`;

  // If no matching trips exist, return clean empty report dataset
  if (supplyIds.length === 0) {
    return {
      date: dateLabel,
      summary: {
        total_sales_amount: 0,
        total_amount_collected: 0,
        total_pending_amount: 0,
        shops_visited: 0,
        cash_in_hand: 0,
        total_quantity_loaded: 0,
        total_quantity_sold: 0,
        total_quantity_remaining: 0
      },
      products_breakdown: []
    };
  }

  // 3. Fetch sales summary details (overall totals)
  const summaryResult = await db.query(
    `SELECT 
       COALESCE(SUM(total_amount), 0.00)::float AS total_sales_amount,
       COALESCE(SUM(paid_amount), 0.00)::float AS total_amount_collected,
       COALESCE(SUM(pending_amount), 0.00)::float AS total_pending_amount,
       COUNT(DISTINCT shop_id)::int AS shops_visited
     FROM sales_transactions
     WHERE supply_id = ANY($1::int[]) AND org_id = $2`,
    [supplyIds, orgId]
  );

  // 4. cash_in_hand (sum of cash payments on these trips)
  const cashResult = await db.query(
    `SELECT COALESCE(SUM(paid_amount), 0.00)::float AS cash_in_hand
     FROM sales_transactions
     WHERE supply_id = ANY($1::int[]) AND payment_type = 'CASH' AND org_id = $2`,
    [supplyIds, orgId]
  );

  // 5. Total loaded stock
  const loadedResult = await db.query(
    `SELECT COALESCE(SUM(quantity_loaded), 0.00)::float AS total_quantity_loaded
     FROM supply_items
     WHERE supply_id = ANY($1::int[]) AND org_id = $2`,
    [supplyIds, orgId]
  );

  // 6. Total sold stock
  const soldResult = await db.query(
    `SELECT COALESCE(SUM(si.quantity_sold), 0.00)::float AS total_quantity_sold
     FROM sales_items si
     JOIN sales_transactions st ON si.sales_id = st.sales_id
     WHERE st.supply_id = ANY($1::int[]) AND st.org_id = $2`,
    [supplyIds, orgId]
  );

  const summary = summaryResult.rows[0];
  const cashInHand = cashResult.rows[0].cash_in_hand;
  const totalQuantityLoaded = loadedResult.rows[0].total_quantity_loaded;
  const totalQuantitySold = soldResult.rows[0].total_quantity_sold;
  const totalQuantityRemaining = totalQuantityLoaded - totalQuantitySold;

  // 7. Products breakdown (using CTE to avoid double counting)
  const breakdownResult = await db.query(
    `WITH loaded_qty AS (
       SELECT product_id, SUM(quantity_loaded) AS total_loaded
       FROM supply_items
       WHERE supply_id = ANY($1::int[]) AND org_id = $2
       GROUP BY product_id
     ),
     sold_qty AS (
       SELECT si.product_id, SUM(si.quantity_sold) AS total_sold, SUM(si.total_amount) AS total_sales_amount
       FROM sales_items si
       JOIN sales_transactions st ON si.sales_id = st.sales_id
       WHERE st.supply_id = ANY($1::int[]) AND st.org_id = $2
       GROUP BY si.product_id
     )
     SELECT 
       p.product_id,
       p.product_name,
       p.rate::float AS rate,
       p.unit,
       COALESCE(l.total_loaded, 0.00)::float AS quantity_loaded,
       COALESCE(s.total_sold, 0.00)::float AS quantity_sold,
       (COALESCE(l.total_loaded, 0.00) - COALESCE(s.total_sold, 0.00))::float AS quantity_remaining,
       COALESCE(s.total_sales_amount, 0.00)::float AS sales_amount
     FROM product p
     LEFT JOIN loaded_qty l ON p.product_id = l.product_id
     LEFT JOIN sold_qty s ON p.product_id = s.product_id
     WHERE p.org_id = $2 AND p.status = 'ACTIVE'
     ORDER BY p.product_name`,
    [supplyIds, orgId]
  );

  return {
    date: dateLabel,
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
  };
};

// GET /api/admin/reports - Get aggregated reports for Admin
app.get('/api/admin/reports', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const { range, startDate, endDate } = req.query;

  console.log('\n========== ADMIN REPORTS ACCESS ==========');
  console.log('🏢 Org ID    :', orgId);
  console.log('📅 Range     :', range);
  console.log('📅 StartDate :', startDate);
  console.log('📅 EndDate   :', endDate);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const data = await getAdminReportsData(orgId, range, startDate, endDate);
    console.log(`✅ Generated Admin Sales Report | range: ${range} | sales: ₹${data.summary.total_sales_amount}`);
    res.json(data);
  } catch (err) {
    console.error('🔥 Error generating Admin sales report:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/admin/reports/export/csv - Export admin report to CSV
app.get('/api/admin/reports/export/csv', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const { range, startDate, endDate } = req.query;

  console.log('\n========== EXPORT CSV ==========');
  console.log('🏢 Org ID    :', orgId);
  console.log('📅 Range     :', range);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const data = await getAdminReportsData(orgId, range, startDate, endDate);
    const todayStr = new Date().toISOString().split('T')[0];

    const cleanCsvValue = (val) => {
      if (val === null || val === undefined) return '';
      const str = String(val).replace(/"/g, '""');
      return str.includes(',') || str.includes('\n') || str.includes('"') ? `"${str}"` : str;
    };

    let csv = 'Sales Report,' + cleanCsvValue(data.date) + '\n\n';
    csv += 'OVERALL SUMMARY\n';
    csv += 'Metric,Value\n';
    csv += 'Total Sales Amount,' + data.summary.total_sales_amount + '\n';
    csv += 'Total Amount Collected,' + data.summary.total_amount_collected + '\n';
    csv += 'Total Pending Amount,' + data.summary.total_pending_amount + '\n';
    csv += 'Shops Visited,' + data.summary.shops_visited + '\n';
    csv += 'Total Cash In Hand,' + data.summary.cash_in_hand + '\n';
    csv += 'Total Quantity Loaded (L),' + data.summary.total_quantity_loaded + '\n';
    csv += 'Total Quantity Sold (L),' + data.summary.total_quantity_sold + '\n';
    csv += 'Total Quantity Remaining (L),' + data.summary.total_quantity_remaining + '\n\n';

    csv += 'PRODUCT SALES BREAKDOWN\n';
    csv += 'Product ID,Product Name,Rate,Unit,Loaded Qty,Sold Qty,Remaining Qty,Sales Value\n';
    data.products_breakdown.forEach(p => {
      csv += `${p.product_id},${cleanCsvValue(p.product_name)},${p.rate},${cleanCsvValue(p.unit)},${p.quantity_loaded},${p.quantity_sold},${p.quantity_remaining},${p.sales_amount}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="sales_report_${range || 'today'}_${todayStr}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('🔥 CSV Export error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/admin/reports/export/excel - Export admin report to Excel (HTML format)
app.get('/api/admin/reports/export/excel', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const { range, startDate, endDate } = req.query;

  console.log('\n========== EXPORT EXCEL ==========');
  console.log('🏢 Org ID    :', orgId);
  console.log('📅 Range     :', range);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const data = await getAdminReportsData(orgId, range, startDate, endDate);
    const todayStr = new Date().toISOString().split('T')[0];

    let html = `<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8" />
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .title { font-size: 16px; font-weight: bold; background-color: #087E66; color: #ffffff; text-align: center; height: 35px; }
    .section-header { font-size: 13px; font-weight: bold; background-color: #F1F5F9; color: #1E293B; height: 25px; }
    .summary-table, .breakdown-table { border-collapse: collapse; margin-bottom: 20px; }
    .summary-table td, .breakdown-table th, .breakdown-table td { border: 1px solid #CBD5E1; padding: 6px; }
    .breakdown-table th { background-color: #087E66; color: #ffffff; font-weight: bold; text-align: left; }
    .currency { text-align: right; }
    .number { text-align: right; }
    .accent-bg { background-color: #F1F5F9; font-weight: bold; }
  </style>
</head>
<body>
  <h2>Sales Report - ${data.date}</h2>
  
  <h3>Overall Summary</h3>
  <table class="summary-table">
    <tr><td class="accent-bg">Metric</td><td class="accent-bg">Value</td></tr>
    <tr><td>Total Sales Amount</td><td class="currency">₹${data.summary.total_sales_amount.toFixed(2)}</td></tr>
    <tr><td>Total Amount Collected</td><td class="currency">₹${data.summary.total_amount_collected.toFixed(2)}</td></tr>
    <tr><td>Total Pending Amount</td><td class="currency">₹${data.summary.total_pending_amount.toFixed(2)}</td></tr>
    <tr><td>Shops Visited</td><td class="number">${data.summary.shops_visited}</td></tr>
    <tr><td>Total Cash In Hand</td><td class="currency">₹${data.summary.cash_in_hand.toFixed(2)}</td></tr>
    <tr><td>Total Quantity Loaded (L)</td><td class="number">${data.summary.total_quantity_loaded}</td></tr>
    <tr><td>Total Quantity Sold (L)</td><td class="number">${data.summary.total_quantity_sold}</td></tr>
    <tr><td>Total Quantity Remaining (L)</td><td class="number">${data.summary.total_quantity_remaining}</td></tr>
  </table>
  
  <h3>Product Sales Breakdown</h3>
  <table class="breakdown-table">
    <thead>
      <tr>
        <th>Product ID</th>
        <th>Product Name</th>
        <th>Rate</th>
        <th>Unit</th>
        <th>Loaded Qty</th>
        <th>Sold Qty</th>
        <th>Remaining Qty</th>
        <th>Sales Value</th>
      </tr>
    </thead>
    <tbody>
      ${data.products_breakdown.map(p => `
        <tr>
          <td>${p.product_id}</td>
          <td>${p.product_name}</td>
          <td class="currency">₹${p.rate.toFixed(2)}</td>
          <td>${p.unit}</td>
          <td class="number">${p.quantity_loaded}</td>
          <td class="number">${p.quantity_sold}</td>
          <td class="number">${p.quantity_remaining}</td>
          <td class="currency">₹${p.sales_amount.toFixed(2)}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
</body>
</html>`;

    res.setHeader('Content-Type', 'application/vnd.ms-excel');
    res.setHeader('Content-Disposition', `attachment; filename="sales_report_${range || 'today'}_${todayStr}.xls"`);
    res.send(html);
  } catch (err) {
    console.error('🔥 Excel Export error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/admin/reports/export/pdf - Export admin report to PDF
app.get('/api/admin/reports/export/pdf', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const { range, startDate, endDate } = req.query;

  console.log('\n========== EXPORT PDF ==========');
  console.log('🏢 Org ID    :', orgId);
  console.log('📅 Range     :', range);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    const data = await getAdminReportsData(orgId, range, startDate, endDate);
    
    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({ margin: 50, size: 'LETTER' });
    
    const todayStr = new Date().toISOString().split('T')[0];
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="sales_report_${range || 'today'}_${todayStr}.pdf"`);
    
    doc.pipe(res);
    
    // Design colors
    const primaryColor = '#087E66';
    const secondaryColor = '#1E293B';
    const lightSlate = '#64748B';
    const borderLight = '#CBD5E1';
    
    // Header
    doc.fillColor(primaryColor)
       .fontSize(22)
       .font('Helvetica-Bold')
       .text('SALES PERFORMANCE REPORT', 50, 50);
       
    doc.fillColor(lightSlate)
       .fontSize(10)
       .font('Helvetica')
       .text('Oil Company Sales Management System', 50, 78);
       
    doc.fillColor(secondaryColor)
       .fontSize(12)
       .font('Helvetica-Bold')
       .text(`Report Period: ${data.date}`, 50, 95);
       
    doc.moveTo(50, 115)
       .lineTo(562, 115)
       .strokeColor(borderLight)
       .lineWidth(1)
       .stroke();
       
    // Grid Cards Helper
    const drawCard = (x, y, label, val, isCurrency = false, isVolume = false) => {
      // Draw background
      doc.rect(x, y, 230, 50)
         .fillAndStroke('#F8FAFC', '#E2E8F0');
         
      // Draw accent bar
      doc.rect(x, y, 4, 50)
         .fill(primaryColor);
         
      doc.fillColor(lightSlate)
         .fontSize(8)
         .font('Helvetica-Bold')
         .text(label.toUpperCase(), x + 15, y + 10);
         
      let valStr = '';
      if (isCurrency) {
        valStr = `INR ${val.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
      } else if (isVolume) {
        valStr = `${val.toLocaleString('en-IN')} L`;
      } else {
        valStr = val.toLocaleString('en-IN');
      }
      
      doc.fillColor(secondaryColor)
         .fontSize(14)
         .font('Helvetica-Bold')
         .text(valStr, x + 15, y + 25);
    };
    
    // Summary row 1
    drawCard(50, 130, 'Total Sales Amount', data.summary.total_sales_amount, true);
    drawCard(300, 130, 'Total Amount Collected', data.summary.total_amount_collected, true);
    
    // Summary row 2
    drawCard(50, 195, 'Total Quantity Sold', data.summary.total_quantity_sold, false, true);
    drawCard(300, 195, 'Shops Visited', data.summary.shops_visited);
    
    // Summary row 3
    drawCard(50, 260, 'Total Cash In Hand', data.summary.cash_in_hand, true);
    drawCard(300, 260, 'Total Quantity Remaining', data.summary.total_quantity_remaining, false, true);
    
    // Table heading
    doc.fillColor(primaryColor)
       .fontSize(14)
       .font('Helvetica-Bold')
       .text('PRODUCT SALES BREAKDOWN', 50, 335);
       
    // Header Bar
    doc.rect(50, 355, 512, 20)
       .fill(primaryColor);
       
    doc.fillColor('#FFFFFF')
       .fontSize(8)
       .font('Helvetica-Bold');
       
    doc.text('PRODUCT NAME', 55, 361, { width: 180 });
    doc.text('RATE', 240, 361, { width: 50, align: 'right' });
    doc.text('LOADED', 295, 361, { width: 55, align: 'right' });
    doc.text('SOLD', 355, 361, { width: 50, align: 'right' });
    doc.text('REMAINING', 410, 361, { width: 55, align: 'right' });
    doc.text('SALES VALUE', 470, 361, { width: 85, align: 'right' });
    
    let currentY = 380;
    
    data.products_breakdown.forEach((p, idx) => {
      if (currentY > 700) {
        doc.addPage();
        currentY = 50;
        
        // Draw header bar on new page
        doc.rect(50, currentY, 512, 20)
           .fill(primaryColor);
           
        doc.fillColor('#FFFFFF')
           .fontSize(8)
           .font('Helvetica-Bold');
           
        doc.text('PRODUCT NAME', 55, currentY + 6, { width: 180 });
        doc.text('RATE', 240, currentY + 6, { width: 50, align: 'right' });
        doc.text('LOADED', 295, currentY + 6, { width: 55, align: 'right' });
        doc.text('SOLD', 355, currentY + 6, { width: 50, align: 'right' });
        doc.text('REMAINING', 410, currentY + 6, { width: 55, align: 'right' });
        doc.text('SALES VALUE', 470, currentY + 6, { width: 85, align: 'right' });
        
        currentY += 25;
      }
      
      // Row alternating bg
      if (idx % 2 === 1) {
        doc.rect(50, currentY - 3, 512, 20)
           .fill('#F8FAFC');
      }
      
      doc.fillColor(secondaryColor)
         .fontSize(8)
         .font('Helvetica');
         
      doc.text(p.product_name, 55, currentY, { width: 180 });
      doc.text(`INR ${p.rate.toFixed(2)}`, 240, currentY, { width: 50, align: 'right' });
      doc.text(`${p.quantity_loaded} ${p.unit || 'L'}`, 295, currentY, { width: 55, align: 'right' });
      doc.text(`${p.quantity_sold} ${p.unit || 'L'}`, 355, currentY, { width: 50, align: 'right' });
      doc.text(`${p.quantity_remaining} ${p.unit || 'L'}`, 410, currentY, { width: 55, align: 'right' });
      doc.text(`INR ${p.sales_amount.toFixed(2)}`, 470, currentY, { width: 85, align: 'right' });
      
      // Draw grid line
      doc.moveTo(50, currentY + 14)
         .lineTo(562, currentY + 14)
         .strokeColor('#F1F5F9')
         .lineWidth(0.5)
         .stroke();
         
      currentY += 20;
    });
    
    // Signatures / Footer
    if (currentY > 650) {
      doc.addPage();
      currentY = 50;
    }
    
    doc.fillColor(lightSlate)
       .fontSize(8)
       .font('Helvetica-Oblique')
       .text(`Report generated on: ${new Date().toLocaleString()}`, 50, currentY + 20);
       
    // Prep by
    doc.moveTo(50, currentY + 80)
       .lineTo(200, currentY + 80)
       .strokeColor(secondaryColor)
       .lineWidth(0.5)
       .stroke();
       
    doc.fillColor(secondaryColor)
       .fontSize(8)
       .font('Helvetica-Bold')
       .text('Prepared By (Sales Manager)', 50, currentY + 85);
       
    // Approved by
    doc.moveTo(412, currentY + 80)
       .lineTo(562, currentY + 80)
       .strokeColor(secondaryColor)
       .lineWidth(0.5)
       .stroke();
       
    doc.text('Approved By (Administrator)', 412, currentY + 85);
    
    doc.end();
  } catch (err) {
    console.error('🔥 PDF Export error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error', details: err.message });
    }
  }
});


// ============================================================
// AREAS CRUD ENDPOINTS
// ============================================================

// GET /api/areas - List all areas for the org
app.get('/api/areas', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;
  console.log('\n========== GET AREAS ==========');
  console.log('🏢 Org ID:', orgId);

  try {
    const result = await db.query(
      `SELECT * FROM areas WHERE org_id = $1 ORDER BY area_name`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('🔥 Error fetching areas:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/areas - Create a new area for the org
app.post('/api/areas', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const { area_name, description, status } = req.body;

  console.log('\n========== CREATE AREA ==========');
  console.log('🏢 Org ID:', orgId, '| 📍 Name:', area_name);

  if (!area_name || !area_name.trim()) {
    return res.status(400).json({ error: 'Area name is required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO areas (area_name, description, status, org_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [area_name.trim(), description ? description.trim() : null, status || 'ACTIVE', orgId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error creating area:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/areas/:id - Update an existing area (scoped to org)
app.put('/api/areas/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const areaId = req.params.id;
  const { area_name, description, status } = req.body;

  console.log('\n========== UPDATE AREA ==========');
  console.log('🏢 Org ID:', orgId, '| 🆔 Area ID:', areaId);

  if (!area_name || !area_name.trim()) {
    return res.status(400).json({ error: 'Area name is required' });
  }

  try {
    const result = await db.query(
      `UPDATE areas
       SET area_name = $1, description = $2, status = $3, updated_on = CURRENT_TIMESTAMP
       WHERE area_id = $4 AND org_id = $5
       RETURNING *`,
      [area_name.trim(), description ? description.trim() : null, status || 'ACTIVE', areaId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Area not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error updating area:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/areas/:id - Soft delete/deactivate an area (scoped to org)
app.delete('/api/areas/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const areaId = req.params.id;

  console.log('\n========== DELETE AREA ==========');
  console.log('🏢 Org ID:', orgId, '| 🆔 Area ID:', areaId);

  try {
    const result = await db.query(
      `UPDATE areas
       SET status = 'INACTIVE', updated_on = CURRENT_TIMESTAMP
       WHERE area_id = $1 AND org_id = $2
       RETURNING *`,
      [areaId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Area not found' });
    }
    res.json({ message: 'Area deactivated successfully', area: result.rows[0] });
  } catch (err) {
    console.error('🔥 Error deactivating area:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// CATEGORY CRUD ENDPOINTS
// ============================================================

// GET /api/categories - List all categories
app.get('/api/categories', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== GET CATEGORIES ==========');
  console.log('🏢 Org ID :', orgId);

  try {
    const result = await db.query(
      `SELECT * FROM category WHERE org_id = $1 ORDER BY category_name`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('🔥 Error fetching categories:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/categories - Create a new category
app.post('/api/categories', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id;
  const { category_name, description, status } = req.body;

  console.log('\n========== CREATE CATEGORY ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🏷️ Name   :', category_name);

  if (!category_name || !category_name.trim()) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  try {
    const result = await db.query(
      `INSERT INTO category (category_name, description, status, org_id, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [category_name.trim(), description ? description.trim() : null, status || 'ACTIVE', orgId, userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error creating category:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/categories/:id - Update an existing category
app.put('/api/categories/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const categoryId = req.params.id;
  const { category_name, description, status } = req.body;

  console.log('\n========== UPDATE CATEGORY ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🆔 ID     :', categoryId);

  if (!category_name || !category_name.trim()) {
    return res.status(400).json({ error: 'Category name is required' });
  }

  try {
    const result = await db.query(
      `UPDATE category 
       SET category_name = $1, description = $2, status = $3, updated_on = CURRENT_TIMESTAMP
       WHERE category_id = $4 AND org_id = $5
       RETURNING *`,
      [category_name.trim(), description ? description.trim() : null, status || 'ACTIVE', categoryId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Category not found or unauthorized' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error updating category:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/categories/:id - Soft delete/deactivate a category
app.delete('/api/categories/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const categoryId = req.params.id;

  console.log('\n========== DELETE CATEGORY ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🆔 ID     :', categoryId);

  try {
    const result = await db.query(
      `UPDATE category 
       SET status = 'INACTIVE', updated_on = CURRENT_TIMESTAMP
       WHERE category_id = $1 AND org_id = $2
       RETURNING *`,
      [categoryId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Category not found or unauthorized' });
    }
    res.json({ message: 'Category deactivated successfully', category: result.rows[0] });
  } catch (err) {
    console.error('🔥 Error deactivating category:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// USER CRUD ENDPOINTS
// ============================================================

// GET /api/users - List all users in the organization
app.get('/api/users', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== GET USERS ==========');
  console.log('🏢 Org ID :', orgId);

  try {
    const result = await db.query(
      `SELECT u.user_id, u.username, u.email, u.phone, u.status, u.address, u.state, u.org_id, u.role_id, r.role_name, u.created_on, u.updated_on
       FROM users u
       LEFT JOIN roles r ON u.role_id = r.role_id
       WHERE u.org_id = $1
       ORDER BY u.username`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('🔥 Error fetching users:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/users - Create a new user
app.post('/api/users', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const currentUserId = req.user.user_id;
  const { username, email, phone, status, address, state, role_id, password } = req.body;

  console.log('\n========== CREATE USER ==========');
  console.log('🏢 Org ID   :', orgId);
  console.log('👤 Username :', username);

  if (!username || !username.trim()) {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!password || !password.trim()) {
    return res.status(400).json({ error: 'Password is required' });
  }
  if (!role_id) {
    return res.status(400).json({ error: 'Role is required' });
  }

  try {
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password.trim(), salt);

    const result = await db.query(
      `INSERT INTO users (username, email, phone, status, address, state, org_id, role_id, password, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
       RETURNING user_id, username, email, phone, status, address, state, org_id, role_id, created_on, updated_on`,
      [
        username.trim(),
        email ? email.trim().toLowerCase() : null,
        phone ? phone.trim() : null,
        status || 'ACTIVE',
        address ? address.trim() : null,
        state ? state.trim() : null,
        orgId,
        role_id,
        hashedPassword,
        currentUserId
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error creating user:', err);
    if (err.message.includes('unique_username_per_org') || err.message.includes('users_username_key')) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/users/:id - Update an existing user
app.put('/api/users/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const currentUserId = req.user.user_id;
  const targetUserId = req.params.id;
  const { username, email, phone, status, address, state, role_id, password } = req.body;

  console.log('\n========== UPDATE USER ==========');
  console.log('🏢 Org ID   :', orgId);
  console.log('🆔 ID       :', targetUserId);

  if (!username || !username.trim()) {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!role_id) {
    return res.status(400).json({ error: 'Role is required' });
  }

  try {
    let query = `
      UPDATE users 
      SET username = $1, email = $2, phone = $3, status = $4, address = $5, state = $6, role_id = $7, updated_by = $8, updated_on = CURRENT_TIMESTAMP
    `;
    const queryParams = [
      username.trim(),
      email ? email.trim().toLowerCase() : null,
      phone ? phone.trim() : null,
      status || 'ACTIVE',
      address ? address.trim() : null,
      state ? state.trim() : null,
      role_id,
      currentUserId
    ];

    if (password && password.trim()) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password.trim(), salt);
      query += `, password = $9 WHERE user_id = $10 AND org_id = $11`;
      queryParams.push(hashedPassword, targetUserId, orgId);
    } else {
      query += ` WHERE user_id = $9 AND org_id = $10`;
      queryParams.push(targetUserId, orgId);
    }

    query += ` RETURNING user_id, username, email, phone, status, address, state, org_id, role_id, created_on, updated_on`;

    const result = await db.query(query, queryParams);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found or unauthorized' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('🔥 Error updating user:', err);
    if (err.message.includes('unique_username_per_org') || err.message.includes('users_username_key')) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/users/:id - Soft delete/deactivate a user
app.delete('/api/users/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const currentUserId = req.user.user_id;
  const targetUserId = req.params.id;

  console.log('\n========== DELETE USER ==========');
  console.log('🏢 Org ID :', orgId);
  console.log('🆔 ID     :', targetUserId);

  try {
    const result = await db.query(
      `UPDATE users 
       SET status = 'INACTIVE', updated_by = $1, updated_on = CURRENT_TIMESTAMP
       WHERE user_id = $2 AND org_id = $3
       RETURNING user_id, username, email, status`,
      [currentUserId, targetUserId, orgId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found or unauthorized' });
    }
    res.json({ message: 'User deactivated successfully', user: result.rows[0] });
  } catch (err) {
    console.error('🔥 Error deactivating user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/roles - Helper to fetch roles for select dropdowns
app.get('/api/roles', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  try {
    const result = await db.query(
      `SELECT * FROM roles WHERE org_id = $1 ORDER BY role_name`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('🔥 Error fetching roles:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// EOD RECONCILIATION ENDPOINTS
// ============================================================

// GET /api/reconciliation/active - Retrieve logged-in driver's active trip for EOD
app.get('/api/reconciliation/active', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;

  console.log('\n========== DRIVER ACTIVE RECONCILIATION ==========');
  console.log('👤 User ID :', userId);
  console.log('🏢 Org ID  :', orgId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // Find active trip (OPEN or PENDING_APPROVAL)
    const tripQuery = `
      SELECT sm.supply_id, sm.date, sm.vehicle_id, sm.status, 
             COALESCE(sm.actual_cash, 0.00)::float AS actual_cash, 
             COALESCE(sm.actual_upi, 0.00)::float AS actual_upi,
             v.vehicle_no, v.vehicle_name
      FROM supply_management sm
      LEFT JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
      WHERE sm.user_id = $1 AND sm.org_id = $2 AND sm.status IN ('OPEN', 'PENDING_APPROVAL', 'CLOSED', 'RECONCILED')
      ORDER BY sm.date DESC, sm.supply_id DESC
      LIMIT 1
    `;
    const tripRes = await db.query(tripQuery, [userId, orgId]);

    if (tripRes.rows.length === 0) {
      return res.status(404).json({ error: 'No active trip found for EOD reconciliation.' });
    }

    const trip = tripRes.rows[0];
    const supplyId = trip.supply_id;

    // Fetch loaded inventory
    const loadedQuery = `
      SELECT si.product_id, si.quantity_loaded::float AS quantity_loaded, 
             si.quantity_returned::float AS quantity_returned, 
             p.product_name, p.rate::float AS rate, p.unit
      FROM supply_items si
      JOIN product p ON si.product_id = p.product_id
      WHERE si.supply_id = $1 AND si.org_id = $2
    `;
    const loadedRes = await db.query(loadedQuery, [supplyId, orgId]);

    // Fetch sold inventory
    const soldQuery = `
      SELECT si.product_id, COALESCE(SUM(si.quantity_sold), 0.00)::float AS quantity_sold
      FROM sales_items si
      JOIN sales_transactions st ON si.sales_id = st.sales_id
      WHERE st.supply_id = $1 AND st.org_id = $2
      GROUP BY si.product_id
    `;
    const soldRes = await db.query(soldQuery, [supplyId, orgId]);
    const soldMap = {};
    soldRes.rows.forEach(r => {
      soldMap[r.product_id] = r.quantity_sold;
    });

    // Fetch expected financials
    const financialsQuery = `
      SELECT 
        COALESCE(SUM(CASE WHEN payment_type = 'CASH' THEN paid_amount ELSE 0 END), 0.00)::float AS expected_cash,
        COALESCE(SUM(CASE WHEN payment_type = 'UPI' THEN paid_amount ELSE 0 END), 0.00)::float AS expected_upi
      FROM sales_transactions
      WHERE supply_id = $1 AND org_id = $2
    `;
    const financialsRes = await db.query(financialsQuery, [supplyId, orgId]);
    const financials = financialsRes.rows[0];

    const inventory = loadedRes.rows.map(item => {
      const sold = soldMap[item.product_id] || 0;
      const expected = Math.max(0, item.quantity_loaded - sold);
      return {
        id: item.product_id.toString(),
        name: item.product_name,
        loaded: item.quantity_loaded,
        sold: sold,
        expected: expected,
        actual: item.quantity_returned === null ? '' : String(item.quantity_returned),
        rate: item.rate,
        unit: item.unit
      };
    });

    const formattedDate = trip.date instanceof Date 
      ? trip.date.toISOString().split('T')[0] 
      : trip.date;

    res.json({
      supply_id: supplyId,
      date: formattedDate,
      status: trip.status === 'OPEN' ? 'in_progress' : (trip.status === 'PENDING_APPROVAL' ? 'pending_approval' : 'reconciled'),
      vehicleNo: trip.vehicle_no || '',
      vehicleName: trip.vehicle_name || '',
      inventory,
      financials: {
        expectedCash: financials.expected_cash,
        actualCash: trip.actual_cash,
        expectedUpi: financials.expected_upi,
        actualUpi: trip.actual_upi
      }
    });

  } catch (err) {
    console.error('🔥 Error fetching active reconciliation trip:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/reconciliation/:supplyId/submit - Driver submits EOD sheets
app.post('/api/reconciliation/:supplyId/submit', authenticateToken, async (req, res) => {
  const orgId = req.user.org_id;
  const userId = req.user.user_id || req.user.id;
  const supplyId = parseInt(req.params.supplyId, 10);
  const { actual_cash, actual_upi, inventory } = req.body;

  console.log('\n========== SUBMIT EOD RECONCILIATION ==========');
  console.log('👤 Driver ID :', userId);
  console.log('🚚 Supply ID :', supplyId);
  console.log('💵 Cash      :', actual_cash);
  console.log('📱 UPI       :', actual_upi);

  if (isNaN(supplyId) || !orgId) {
    return res.status(400).json({ error: 'Invalid parameters.' });
  }

  try {
    // Verify trip belongs to driver and is OPEN/PENDING_APPROVAL
    const tripCheck = await db.query(
      `SELECT status FROM supply_management WHERE supply_id = $1 AND user_id = $2 AND org_id = $3`,
      [supplyId, userId, orgId]
    );

    if (tripCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Trip not found or unauthorized.' });
    }

    if (tripCheck.rows[0].status === 'CLOSED') {
      return res.status(400).json({ error: 'Reconciliation is already locked and closed.' });
    }

    await db.query('BEGIN');

    // Update supply_management
    await db.query(
      `UPDATE supply_management
       SET status = 'PENDING_APPROVAL', 
           actual_cash = $1, 
           actual_upi = $2, 
           updated_by = $3, 
           updated_on = CURRENT_TIMESTAMP
       WHERE supply_id = $4 AND org_id = $5`,
      [parseFloat(actual_cash || 0), parseFloat(actual_upi || 0), userId, supplyId, orgId]
    );

    // Update supply_items returned counts
    if (inventory && Array.isArray(inventory)) {
      for (const item of inventory) {
        const prodId = parseInt(item.id, 10);
        const actualQty = item.actual === '' ? null : parseFloat(item.actual);
        if (!isNaN(prodId)) {
          await db.query(
            `UPDATE supply_items
             SET quantity_returned = $1
             WHERE supply_id = $2 AND product_id = $3 AND org_id = $4`,
            [actualQty, supplyId, prodId, orgId]
          );
        }
      }
    }

    await db.query('COMMIT');
    res.json({ message: 'EOD Sheet submitted successfully. Pending Admin review.' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error submitting EOD Reconciliation:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /api/admin/reconciliation - Retrieve all active/reconciled sheets for admin
app.get('/api/admin/reconciliation', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;

  console.log('\n========== ADMIN GET RECONCILIATIONS ==========');
  console.log('🏢 Org ID :', orgId);

  if (!orgId) {
    return res.status(400).json({ error: 'Invalid token payload: missing org_id' });
  }

  try {
    // Retrieve trips in the last 30 days that are not deleted/inactive
    const tripsQuery = `
      SELECT sm.supply_id, sm.date, sm.status, sm.flagged_discrepancies,
             COALESCE(sm.actual_cash, 0.00)::float AS actual_cash, 
             COALESCE(sm.actual_upi, 0.00)::float AS actual_upi,
             u.username AS driver_name,
             v.vehicle_no, v.vehicle_name
      FROM supply_management sm
      LEFT JOIN users u ON sm.user_id = u.user_id
      LEFT JOIN vehicle v ON sm.vehicle_id = v.vehicle_id
      WHERE sm.org_id = $1 
        AND sm.status IN ('OPEN', 'PENDING_APPROVAL', 'CLOSED', 'RECONCILED')
        AND sm.date >= CURRENT_DATE - 30
      ORDER BY sm.date DESC, sm.supply_id DESC
    `;
    const tripsRes = await db.query(tripsQuery, [orgId]);

    const reconciliationsList = [];

    for (const trip of tripsRes.rows) {
      const supplyId = trip.supply_id;

      // Fetch loaded inventory
      const loadedQuery = `
        SELECT si.product_id, si.quantity_loaded::float AS quantity_loaded, 
               si.quantity_returned::float AS quantity_returned, 
               p.product_name, p.rate::float AS rate, p.unit
        FROM supply_items si
        JOIN product p ON si.product_id = p.product_id
        WHERE si.supply_id = $1 AND si.org_id = $2
      `;
      const loadedRes = await db.query(loadedQuery, [supplyId, orgId]);

      // Fetch sold inventory
      const soldQuery = `
        SELECT si.product_id, COALESCE(SUM(si.quantity_sold), 0.00)::float AS quantity_sold
        FROM sales_items si
        JOIN sales_transactions st ON si.sales_id = st.sales_id
        WHERE st.supply_id = $1 AND st.org_id = $2
        GROUP BY si.product_id
      `;
      const soldRes = await db.query(soldQuery, [supplyId, orgId]);
      const soldMap = {};
      soldRes.rows.forEach(r => {
        soldMap[r.product_id] = r.quantity_sold;
      });

      // Fetch expected financials
      const financialsQuery = `
        SELECT 
          COALESCE(SUM(CASE WHEN payment_type = 'CASH' THEN paid_amount ELSE 0 END), 0.00)::float AS expected_cash,
          COALESCE(SUM(CASE WHEN payment_type = 'UPI' THEN paid_amount ELSE 0 END), 0.00)::float AS expected_upi
        FROM sales_transactions
        WHERE supply_id = $1 AND org_id = $2
      `;
      const financialsRes = await db.query(financialsQuery, [supplyId, orgId]);
      const financials = financialsRes.rows[0];

      const inventory = loadedRes.rows.map(item => {
        const sold = soldMap[item.product_id] || 0;
        const expected = Math.max(0, item.quantity_loaded - sold);
        return {
          id: item.product_id.toString(),
          name: item.product_name,
          loaded: item.quantity_loaded,
          sold: sold,
          expected: expected,
          actual: item.quantity_returned === null ? '' : String(item.quantity_returned),
          rate: item.rate,
          unit: item.unit
        };
      });

      const formattedDate = trip.date instanceof Date 
        ? trip.date.toISOString().split('T')[0] 
        : trip.date;

      let parsedDiscrepancies = [];
      if (trip.flagged_discrepancies) {
        try {
          parsedDiscrepancies = JSON.parse(trip.flagged_discrepancies);
          if (!Array.isArray(parsedDiscrepancies)) {
            parsedDiscrepancies = [trip.flagged_discrepancies];
          }
        } catch (e) {
          // If not valid JSON, split by semicolon
          parsedDiscrepancies = trip.flagged_discrepancies.split(';').map(s => s.trim()).filter(Boolean);
        }
      }

      reconciliationsList.push({
        driverName: trip.driver_name || 'Driver',
        status: trip.status === 'OPEN' ? 'in_progress' : (trip.status === 'PENDING_APPROVAL' ? 'pending_approval' : 'reconciled'),
        date: formattedDate,
        vehicleNo: trip.vehicle_no || '',
        vehicleName: trip.vehicle_name || '',
        supply_id: supplyId,
        inventory,
        financials: {
          expectedCash: financials.expected_cash,
          actualCash: trip.actual_cash,
          expectedUpi: financials.expected_upi,
          actualUpi: trip.actual_upi
        },
        flaggedDiscrepancies: parsedDiscrepancies
      });
    }

    res.json(reconciliationsList);

  } catch (err) {
    console.error('🔥 Error listing reconciliations for Admin:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/admin/reconciliation/:supplyId/approve - Admin approves and closes trip
app.post('/api/admin/reconciliation/:supplyId/approve', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const currentUserId = req.user.user_id || req.user.id;
  const supplyId = parseInt(req.params.supplyId, 10);
  const { flagged_discrepancies } = req.body;

  console.log('\n========== ADMIN APPROVE RECONCILIATION ==========');
  console.log('🚚 Supply ID :', supplyId);
  console.log('⚠️ Discreps  :', flagged_discrepancies);

  if (isNaN(supplyId) || !orgId) {
    return res.status(400).json({ error: 'Invalid parameters.' });
  }

  try {
    const discrepanciesStr = Array.isArray(flagged_discrepancies) 
      ? JSON.stringify(flagged_discrepancies) 
      : (flagged_discrepancies || null);

    const result = await db.query(
      `UPDATE supply_management
       SET status = 'CLOSED', 
           flagged_discrepancies = $1,
           updated_by = $2, 
           updated_on = CURRENT_TIMESTAMP
       WHERE supply_id = $3 AND org_id = $4
       RETURNING supply_id`,
      [discrepanciesStr, currentUserId, supplyId, orgId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Trip not found or unauthorized.' });
    }

    res.json({ message: 'Trip reconciliation approved and day closed successfully.' });

  } catch (err) {
    console.error('🔥 Error approving reconciliation:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /api/admin/reconciliation/:supplyId/reject - Admin rejects and resets EOD sheets
app.post('/api/admin/reconciliation/:supplyId/reject', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
  const orgId = req.user.org_id;
  const currentUserId = req.user.user_id || req.user.id;
  const supplyId = parseInt(req.params.supplyId, 10);

  console.log('\n========== ADMIN REJECT RECONCILIATION ==========');
  console.log('🚚 Supply ID :', supplyId);

  if (isNaN(supplyId) || !orgId) {
    return res.status(400).json({ error: 'Invalid parameters.' });
  }

  try {
    await db.query('BEGIN');

    // Reset supply_management trip status back to OPEN and clear entries
    const result = await db.query(
      `UPDATE supply_management
       SET status = 'OPEN', 
           actual_cash = 0, 
           actual_upi = 0, 
           flagged_discrepancies = NULL,
           updated_by = $1, 
           updated_on = CURRENT_TIMESTAMP
       WHERE supply_id = $2 AND org_id = $3
       RETURNING supply_id`,
      [currentUserId, supplyId, orgId]
    );

    if (result.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({ error: 'Trip not found or unauthorized.' });
    }

    // Reset returned quantity in supply_items
    await db.query(
      `UPDATE supply_items
       SET quantity_returned = NULL
       WHERE supply_id = $1 AND org_id = $2`,
      [supplyId, orgId]
    );

    await db.query('COMMIT');
    res.json({ message: 'Reconciliation rejected and EOD sheet sent back to driver.' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('🔥 Error rejecting EOD Reconciliation:', err);
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
