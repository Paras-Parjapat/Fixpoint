import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

/* ------------------------------------------------------------
   CONFIG
   ------------------------------------------------------------ */
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/* ------------------------------------------------------------
   HELPERS
   ------------------------------------------------------------ */
const shortTicketId = () =>
  `FP-${Date.now().toString(36).toUpperCase().slice(-4)}${Math.random()
    .toString(36)
    .toUpperCase()
    .slice(2, 6)}`;

const requireAuth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Missing token" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

/* ------------------------------------------------------------
   HEALTH
   ------------------------------------------------------------ */
app.get('/health', async (_req, res) => {
  try {
    const result = await pool.query('SELECT NOW() AS now');
    res.json({ ok: true, dbTime: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ error: "Database connection failed" });
  }
});

/* ------------------------------------------------------------
   COLLEGES
   ------------------------------------------------------------ */
app.get('/api/colleges/exists', async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT 1 FROM colleges LIMIT 1");
    res.json({ anyCollegeExists: rows.length > 0 });
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});

app.post('/api/colleges', async (req, res) => {
  try {
    const { name, id } = req.body || {};
    const collegeId = String(id || "").trim().toUpperCase().replace(/\s+/g, "-");

    if (!name || name.trim().length < 2) {
      return res.status(400).json({ error: "Invalid college name" });
    }
    if (!/^[A-Z0-9][A-Z0-9-]{3,39}$/.test(collegeId)) {
      return res.status(400).json({ error: "Invalid College ID format" });
    }

    const { rows: existing } = await pool.query("SELECT 1 FROM colleges LIMIT 1");
    if (existing.length) {
      return res.status(409).json({ error: "A college already exists on this server" });
    }

    const defaults = {
      student:   "STUDENT-2026",
      professor: "PROFESSOR-2026",
      control:   "CONTROL-2026",
      worker:    "WORKER-2026",
      principal: "PRINCIPAL-2026"
    };

    const hashed = {};
    for (const [role, plain] of Object.entries(defaults)) {
      hashed[role] = await bcrypt.hash(plain, 10);
    }

    const { rows } = await pool.query(
      "INSERT INTO colleges (id, name, role_access_ids) VALUES ($1, $2, $3) RETURNING id, name",
      [collegeId, name.trim(), hashed]
    );

    res.status(201).json({ college: rows[0], initialRoleIds: defaults });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create college" });
  }
});

app.post('/api/colleges/login', async (req, res) => {
  try {
    const { name, collegeId } = req.body || {};
    const id = String(collegeId || "").toUpperCase();

    const { rows } = await pool.query(
      "SELECT id, name FROM colleges WHERE id = $1",
      [id]
    );
    if (!rows[0]) return res.status(404).json({ error: "College not found" });
    if (rows[0].name.trim().toLowerCase() !== String(name || "").trim().toLowerCase()) {
      return res.status(401).json({ error: "College name does not match" });
    }

    res.json({ college: rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

/* ------------------------------------------------------------
   AUTH — VERIFY ROLE ID
   ------------------------------------------------------------ */
app.post('/api/auth/verify-role', async (req, res) => {
  try {
    const { collegeId, role, roleAccessId } = req.body || {};

    if (!collegeId || !role || !roleAccessId) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const { rows } = await pool.query(
      "SELECT role_access_ids FROM colleges WHERE id = $1",
      [String(collegeId).toUpperCase()]
    );
    if (!rows[0]) return res.status(404).json({ error: "College not found" });

    const hash = rows[0].role_access_ids?.[role];
    if (!hash) return res.status(400).json({ error: "Role not configured" });

    const valid = await bcrypt.compare(
      String(roleAccessId).trim().toUpperCase(),
      hash
    );

    res.json({ valid });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

/* ------------------------------------------------------------
   AUTH — ADMIN TOKEN
   ------------------------------------------------------------ */
app.post('/api/auth/admin-token', async (req, res) => {
  try {
    const { collegeId, roleAccessId } = req.body || {};
    const id = String(collegeId || "").toUpperCase();

    if (!id || !roleAccessId) {
      return res.status(400).json({ error: "collegeId and roleAccessId required" });
    }

    const { rows } = await pool.query(
      "SELECT role_access_ids FROM colleges WHERE id = $1",
      [id]
    );
    if (!rows[0]) return res.status(404).json({ error: "College not found" });

    const hash = rows[0].role_access_ids?.principal;
    if (!hash) return res.status(400).json({ error: "Admin role not configured" });

    const ok = await bcrypt.compare(
      String(roleAccessId).trim().toUpperCase(),
      hash
    );
    if (!ok) return res.status(401).json({ error: "Invalid admin access ID" });

    const token = jwt.sign(
      { role: "principal", collegeId: id, name: "Admin" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not issue token" });
  }
});

/* ------------------------------------------------------------
   UPDATE ROLE IDS (admin only)
   ------------------------------------------------------------ */
app.patch('/api/colleges/me/role-ids', requireAuth, async (req, res) => {
  try {
    if (req.user.role !== "principal") {
      return res.status(403).json({ error: "Admin only" });
    }

    const { student, professor, control, worker, principal } = req.body || {};

    const { rows: c } = await pool.query(
      "SELECT role_access_ids FROM colleges WHERE id = $1",
      [req.user.collegeId]
    );
    if (!c[0]) return res.status(404).json({ error: "College not found" });

    const hashed = { ...(c[0].role_access_ids || {}) };
    const updates = { student, professor, control, worker, principal };
    let changed = 0;

    for (const [role, plain] of Object.entries(updates)) {
      if (plain && String(plain).trim().length >= 4) {
        hashed[role] = await bcrypt.hash(String(plain).trim().toUpperCase(), 10);
        changed++;
      }
    }

    if (!changed) {
      return res.status(400).json({ error: "No valid new IDs provided (each must be 4+ chars)" });
    }

    await pool.query(
      "UPDATE colleges SET role_access_ids = $1 WHERE id = $2",
      [hashed, req.user.collegeId]
    );

    res.json({ ok: true, changed });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

/* ------------------------------------------------------------
   AUTH — SIGNUP / LOGIN (kept for future migration)
   ------------------------------------------------------------ */
app.post('/api/auth/signup', async (req, res) => {
  try {
    const b = req.body || {};
    const phone = String(b.phone || "").replace(/\D/g, "");
    const collegeId = String(b.collegeId || "").toUpperCase();

    const { rows: c } = await pool.query(
      "SELECT role_access_ids FROM colleges WHERE id = $1",
      [collegeId]
    );
    if (!c[0]) return res.status(404).json({ error: "College not found" });

    const hash = c[0].role_access_ids?.[b.role];
    if (!hash || !(await bcrypt.compare(String(b.roleAccessId || "").toUpperCase(), hash))) {
      return res.status(401).json({ error: "Invalid role access ID" });
    }

    const { rows: dup } = await pool.query(
      "SELECT id FROM accounts WHERE college_id=$1 AND role=$2 AND phone=$3 AND deleted_at IS NULL",
      [collegeId, b.role, phone]
    );
    if (dup.length) return res.status(409).json({ error: "Account already exists. Please log in." });

    const { rows } = await pool.query(
      `INSERT INTO accounts (college_id, role, name, father_name, phone, branch, year, department, designation)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [collegeId, b.role, b.name, b.fatherName || "", phone, b.branch || "", b.year || "", b.department || "", b.designation || ""]
    );

    if (b.role === "student") {
      await pool.query(
        `INSERT INTO student_profiles (college_id, account_id, name, father_name, title, branch, year, bio, line)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [collegeId, rows[0].id, b.name, b.fatherName || "", "B.Tech Student", b.branch || "IT", b.year || "Year 1", "No bio added yet.", "Keep learning. Keep building."]
      );
    }

    res.status(201).json({ account: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const b = req.body || {};
    const phone = String(b.phone || "").replace(/\D/g, "");
    const collegeId = String(b.collegeId || "").toUpperCase();

    const { rows: c } = await pool.query(
      "SELECT role_access_ids FROM colleges WHERE id = $1",
      [collegeId]
    );
    if (!c[0]) return res.status(404).json({ error: "College not found" });

    const hash = c[0].role_access_ids?.[b.role];
    if (!hash || !(await bcrypt.compare(String(b.roleAccessId || "").toUpperCase(), hash))) {
      return res.status(401).json({ error: "Invalid role access ID" });
    }

    const { rows } = await pool.query(
      "SELECT * FROM accounts WHERE college_id=$1 AND role=$2 AND phone=$3 AND deleted_at IS NULL",
      [collegeId, b.role, phone]
    );
    const account = rows[0];
    if (!account) return res.status(401).json({ error: "No account found. Sign up first." });

    const token = jwt.sign(
      { id: account.id, role: account.role, collegeId: account.college_id, phone: account.phone, name: account.name },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token, account });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ------------------------------------------------------------
   TICKETS
   ------------------------------------------------------------ */
app.get('/api/tickets', requireAuth, async (req, res) => {
  const { collegeId, role, id } = req.user;
  const where = ["college_id = $1"];
  const params = [collegeId];
  if (role === "student") { params.push(id); where.push(`owner_id = $${params.length}`); }

  const { rows } = await pool.query(
    `SELECT * FROM tickets WHERE ${where.join(" AND ")} ORDER BY created_at DESC`,
    params
  );
  res.json({ tickets: rows });
});

app.post('/api/tickets', requireAuth, async (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Only students can create tickets" });
  const b = req.body || {};
  const { rows } = await pool.query(
    `INSERT INTO tickets (short_id, college_id, owner_id, name, phone, category, urgent, description, issue_image)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [shortTicketId(), req.user.collegeId, req.user.id, b.name, b.phone, b.category, !!b.urgent, b.description, b.issueImage || null]
  );
  res.status(201).json({ ticket: rows[0] });
});

/* ------------------------------------------------------------
   LECTURES
   ------------------------------------------------------------ */
app.get('/api/lectures', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM lectures WHERE college_id = $1 ORDER BY date DESC",
    [req.user.collegeId]
  );
  res.json({ lectures: rows });
});

app.post('/api/lectures', requireAuth, async (req, res) => {
  const b = req.body || {};
  const { rows } = await pool.query(
    `INSERT INTO lectures (college_id, professor_id, professor_name, professor_phone, subject, branch, year, semester, room, date, start_time, end_time, type)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [req.user.collegeId, req.user.id, req.user.name, req.user.phone, b.subject, b.branch, b.year, b.semester, b.room, b.date, b.startTime, b.endTime, b.type]
  );
  res.status(201).json({ lecture: rows[0] });
});

/* ------------------------------------------------------------
   START
   ------------------------------------------------------------ */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 FixPoint API running on http://localhost:${PORT}`);
  console.log(`   Endpoints loaded:`);
  console.log(`   POST /api/colleges`);
  console.log(`   POST /api/colleges/login`);
  console.log(`   POST /api/auth/verify-role`);
  console.log(`   POST /api/auth/admin-token`);
  console.log(`   PATCH /api/colleges/me/role-ids`);
  console.log(`   POST /api/auth/signup`);
  console.log(`   POST /api/auth/login`);
});