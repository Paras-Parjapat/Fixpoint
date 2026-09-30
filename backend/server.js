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

app.use(
  express.json({
    limit: '10mb'
  })
);

/* ------------------------------------------------------------
   HELPERS + DATABASE INITIALIZATION
   ------------------------------------------------------------ */

const normalizeCollegeId = (value) =>
  String(value || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "-");

const parseRoleAccessIds = (value) => {
  if (!value) return {};

  if (typeof value === "object") {
    return value;
  }

  try {
    const parsed = JSON.parse(String(value));

    return parsed && typeof parsed === "object"
      ? parsed
      : {};
  } catch {
    return {};
  }
};

const shortTicketId = () =>
  `FP-${Date.now()
    .toString(36)
    .toUpperCase()
    .slice(-4)}${Math.random()
    .toString(36)
    .toUpperCase()
    .slice(2, 6)}`;

const isProduction =
  process.env.NODE_ENV === "production";

const sendDbError = (res, publicMessage, err) => {
  console.error(
    `[DB ERROR] ${publicMessage}`,
    err
  );

  const payload = {
    error: publicMessage,

    ...(isProduction
      ? {}
      : {
          details:
            err?.message ||
            "Unknown database error",

          code:
            err?.code ||
            null
        })
  };

  return res
    .status(500)
    .json(payload);
};

const requireAuth = (req, res, next) => {
  try {
    const token =
      req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({
          error: "Missing token"
        });
    }

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res
      .status(401)
      .json({
        error: "Invalid or expired token"
      });
  }
};

/* ------------------------------------------------------------
   DATABASE SCHEMA
   ------------------------------------------------------------ */

async function ensureDatabaseSchema() {
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL is not configured."
    );
  }

  /*
    Required for UUID defaults.
  */
  await pool.query(
    `CREATE EXTENSION IF NOT EXISTS pgcrypto`
  );

  /* ----------------------------------------------------------
     COLLEGES
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS colleges (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      role_access_ids JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  /*
    These ALTER statements protect against an older
    colleges table created by the previous version.
  */

  await pool.query(`
    ALTER TABLE colleges
    ADD COLUMN IF NOT EXISTS name TEXT
  `);

  await pool.query(`
    ALTER TABLE colleges
    ADD COLUMN IF NOT EXISTS role_access_ids
    JSONB DEFAULT '{}'::jsonb
  `);

  await pool.query(`
    ALTER TABLE colleges
    ADD COLUMN IF NOT EXISTS created_at
    TIMESTAMPTZ DEFAULT NOW()
  `);

  /* ----------------------------------------------------------
     ACCOUNTS
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

      college_id TEXT NOT NULL,

      role TEXT NOT NULL,

      name TEXT NOT NULL,

      father_name TEXT NOT NULL DEFAULT '',

      phone TEXT NOT NULL,

      branch TEXT NOT NULL DEFAULT '',

      year TEXT NOT NULL DEFAULT '',

      department TEXT NOT NULL DEFAULT '',

      designation TEXT NOT NULL DEFAULT '',

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

      deleted_at TIMESTAMPTZ
    )
  `);

  /* ----------------------------------------------------------
     STUDENT PROFILES
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS student_profiles (
      id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

      college_id TEXT NOT NULL,

      account_id UUID NOT NULL,

      name TEXT NOT NULL,

      father_name TEXT NOT NULL DEFAULT '',

      title TEXT NOT NULL
        DEFAULT 'B.Tech Student',

      branch TEXT NOT NULL
        DEFAULT 'IT',

      year TEXT NOT NULL
        DEFAULT 'Year 1',

      bio TEXT NOT NULL
        DEFAULT 'No bio added yet.',

      line TEXT NOT NULL
        DEFAULT 'Keep learning. Keep building.',

      updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

      UNIQUE (college_id, account_id)
    )
  `);

  /* ----------------------------------------------------------
     TICKETS
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

      short_id TEXT UNIQUE NOT NULL,

      college_id TEXT NOT NULL,

      owner_id UUID,

      name TEXT NOT NULL DEFAULT '',

      phone TEXT NOT NULL DEFAULT '',

      category TEXT NOT NULL DEFAULT '',

      urgent BOOLEAN NOT NULL DEFAULT FALSE,

      description TEXT NOT NULL DEFAULT '',

      issue_image TEXT,

      fix_image TEXT,

      forwarded BOOLEAN NOT NULL DEFAULT FALSE,

      forwarded_at TIMESTAMPTZ,

      fixed_at TIMESTAMPTZ,

      status TEXT NOT NULL DEFAULT 'pending',

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);

  /* ----------------------------------------------------------
     LECTURES
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS lectures (
      id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

      college_id TEXT NOT NULL,

      professor_id UUID,

      professor_name TEXT NOT NULL DEFAULT '',

      professor_phone TEXT NOT NULL DEFAULT '',

      subject TEXT NOT NULL DEFAULT '',

      branch TEXT NOT NULL DEFAULT '',

      year TEXT NOT NULL DEFAULT '',

      semester TEXT NOT NULL DEFAULT '',

      room TEXT NOT NULL DEFAULT '',

      date DATE,

      start_time TIME,

      end_time TIME,

      type TEXT NOT NULL DEFAULT '',

      attendance TEXT,

      attendance_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);

  /* ----------------------------------------------------------
     PYQS
     ---------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pyqs (
      id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

      college_id TEXT NOT NULL,

      title TEXT NOT NULL,

      subject TEXT NOT NULL DEFAULT '',

      branch TEXT NOT NULL DEFAULT '',

      year INTEGER NOT NULL,

      semester TEXT NOT NULL DEFAULT '',

      description TEXT NOT NULL DEFAULT '',

      file_data TEXT NOT NULL,

      file_name TEXT NOT NULL,

      file_size INTEGER NOT NULL DEFAULT 0,

      uploaded_by_phone TEXT NOT NULL DEFAULT '',

      uploaded_by_name TEXT NOT NULL DEFAULT '',

      uploaded_by_role TEXT NOT NULL DEFAULT '',

      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    )
  `);
}

/* ------------------------------------------------------------
   HEALTH
   ------------------------------------------------------------ */

app.get(
  '/health',
  async (_req, res) => {
    try {
      const result =
        await pool.query(
          'SELECT NOW() AS now'
        );

      res.json({
        ok: true,
        dbTime:
          result.rows[0].now
      });
    } catch (err) {
      return sendDbError(
        res,
        "Database connection failed",
        err
      );
    }
  }
);

/* ------------------------------------------------------------
   COLLEGES
   ------------------------------------------------------------ */

/*
  Check whether at least one college exists.
*/

app.get(
  '/api/colleges/exists',
  async (_req, res) => {
    try {
      const { rows } =
        await pool.query(
          "SELECT 1 FROM colleges LIMIT 1"
        );

      res.json({
        anyCollegeExists:
          rows.length > 0
      });
    } catch (err) {
      return sendDbError(
        res,
        "Could not check college status",
        err
      );
    }
  }
);

/*
  CREATE COLLEGE
*/

app.post(
  '/api/colleges',
  async (req, res) => {
    try {
      const {
        name,
        id
      } = req.body || {};

      const collegeName =
        String(name || "").trim();

      const collegeId =
        normalizeCollegeId(id);

      /* Validate name */

      if (collegeName.length < 2) {
        return res.status(400).json({
          error:
            "Invalid college name"
        });
      }

      /* Validate College ID */

      if (
        !/^[A-Z0-9][A-Z0-9-]{3,39}$/
          .test(collegeId)
      ) {
        return res.status(400).json({
          error:
            "Invalid College ID format"
        });
      }

      /*
        Check whether a college already
        exists on this server.
      */

      const {
        rows: existing
      } = await pool.query(
        `
        SELECT id, name
        FROM colleges
        ORDER BY created_at ASC
        LIMIT 1
        `
      );

      /*
        IMPORTANT:
        If the exact same college is submitted
        again, don't treat it as an error.

        This helps if the frontend accidentally
        sends the request more than once.
      */

      if (existing.length) {
        const sameId =
          normalizeCollegeId(
            existing[0].id
          ) === collegeId;

        const sameName =
          existing[0].name
            .trim()
            .toLowerCase() ===
          collegeName.toLowerCase();

        if (
          sameId &&
          sameName
        ) {
          return res.status(200).json({
            college: {
              id: existing[0].id,
              name: existing[0].name
            },

            reused: true
          });
        }

        /*
          A different college already exists.
          Since this application is configured
          for one college workspace, return 409.
        */

        return res.status(409).json({
          error:
            "A different college is already registered on this server. Use College Login for that college."
        });
      }

      /*
        Default role access IDs.
      */

      const defaults = {
        student:
          "STUDENT-2026",

        professor:
          "PROFESSOR-2026",

        control:
          "CONTROL-2026",

        worker:
          "WORKER-2026",

        principal:
          "PRINCIPAL-2026"
      };

      /*
        Hash role access IDs.
      */

      const hashed = {};

      for (
        const [role, plain]
        of Object.entries(defaults)
      ) {
        hashed[role] =
          await bcrypt.hash(
            plain,
            10
          );
      }

      /*
        Insert the college.
      */

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO colleges
          (id, name, role_access_ids)
        VALUES
          ($1, $2, $3)
        RETURNING id, name
        `,
        [
          collegeId,
          collegeName,
          hashed
        ]
      );

      return res
        .status(201)
        .json({
          college: rows[0],
          initialRoleIds:
            defaults
        });
    } catch (err) {
      /*
        PostgreSQL unique violation.
      */

      if (
        err?.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "That College ID is already registered. Use College Login."
        });
      }

      return sendDbError(
        res,
        "Could not create college",
        err
      );
    }
  }
);

/*
  COLLEGE LOGIN

  This endpoint checks the Render/PostgreSQL
  database directly.

  It does NOT depend on localStorage.
*/

app.post(
  '/api/colleges/login',
  async (req, res) => {
    try {
      const {
        name,
        collegeId
      } = req.body || {};

      const id =
        normalizeCollegeId(
          collegeId
        );

      const collegeName =
        String(name || "").trim();

      if (
        !collegeName ||
        !id
      ) {
        return res.status(400).json({
          error:
            "College name and College ID are required"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT id, name
        FROM colleges
        WHERE id = $1
        `,
        [id]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      if (
        rows[0].name
          .trim()
          .toLowerCase() !==
        collegeName.toLowerCase()
      ) {
        return res.status(401).json({
          error:
            "College name does not match"
        });
      }

      return res.json({
        college: rows[0]
      });
    } catch (err) {
      return sendDbError(
        res,
        "Login failed",
        err
      );
    }
  }
);

/* ------------------------------------------------------------
   AUTH — VERIFY ROLE ID
   ------------------------------------------------------------ */

app.post(
  '/api/auth/verify-role',
  async (req, res) => {
    try {
      const {
        collegeId,
        role,
        roleAccessId
      } = req.body || {};

      if (
        !collegeId ||
        !role ||
        !roleAccessId
      ) {
        return res.status(400).json({
          error:
            "Missing fields"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [
          normalizeCollegeId(
            collegeId
          )
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const roleAccessIds =
        parseRoleAccessIds(
          rows[0].role_access_ids
        );

      const hash =
        roleAccessIds[role];

      if (!hash) {
        return res.status(400).json({
          error:
            "Role not configured"
        });
      }

      const valid =
        await bcrypt.compare(
          String(roleAccessId)
            .trim()
            .toUpperCase(),
          hash
        );

      return res.json({
        valid
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Verification failed"
      });
    }
  }
);

/* ------------------------------------------------------------
   AUTH — ADMIN TOKEN
   ------------------------------------------------------------ */

app.post(
  '/api/auth/admin-token',
  async (req, res) => {
    try {
      const {
        collegeId,
        roleAccessId
      } = req.body || {};

      const id =
        normalizeCollegeId(
          collegeId
        );

      if (
        !id ||
        !roleAccessId
      ) {
        return res.status(400).json({
          error:
            "collegeId and roleAccessId required"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [id]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const roleAccessIds =
        parseRoleAccessIds(
          rows[0].role_access_ids
        );

      const hash =
        roleAccessIds.principal;

      if (!hash) {
        return res.status(400).json({
          error:
            "Admin role not configured"
        });
      }

      const ok =
        await bcrypt.compare(
          String(roleAccessId)
            .trim()
            .toUpperCase(),
          hash
        );

      if (!ok) {
        return res.status(401).json({
          error:
            "Invalid admin access ID"
        });
      }

      const token =
        jwt.sign(
          {
            role:
              "principal",

            collegeId:
              id,

            name:
              "Admin"
          },

          JWT_SECRET,

          {
            expiresIn:
              "30d"
          }
        );

      return res.json({
        token
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not issue token"
      });
    }
  }
);

/* ------------------------------------------------------------
   AUTH — ROLE TOKEN
   ------------------------------------------------------------ */

app.post(
  '/api/auth/role-token',
  async (req, res) => {
    try {
      const {
        collegeId,
        role,
        roleAccessId,
        phone,
        name
      } = req.body || {};

      const id =
        normalizeCollegeId(
          collegeId
        );

      if (
        !id ||
        !role ||
        !roleAccessId ||
        !phone
      ) {
        return res.status(400).json({
          error:
            "Missing required fields"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [id]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const roleAccessIds =
        parseRoleAccessIds(
          rows[0].role_access_ids
        );

      const hash =
        roleAccessIds[role];

      if (!hash) {
        return res.status(400).json({
          error:
            "Role not configured"
        });
      }

      const ok =
        await bcrypt.compare(
          String(roleAccessId)
            .trim()
            .toUpperCase(),
          hash
        );

      if (!ok) {
        return res.status(401).json({
          error:
            "Invalid role access ID"
        });
      }

      const token =
        jwt.sign(
          {
            id:
              `${role}:${phone}`,

            role,

            collegeId:
              id,

            phone,

            name:
              name || "User"
          },

          JWT_SECRET,

          {
            expiresIn:
              "30d"
          }
        );

      return res.json({
        token
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not issue token"
      });
    }
  }
);

/* ------------------------------------------------------------
   UPDATE ROLE IDS — ADMIN ONLY
   ------------------------------------------------------------ */

app.patch(
  '/api/colleges/me/role-ids',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "principal"
      ) {
        return res.status(403).json({
          error:
            "Admin only"
        });
      }

      const {
        student,
        professor,
        control,
        worker,
        principal
      } = req.body || {};

      const {
        rows: c
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [req.user.collegeId]
      );

      if (!c[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const hashed = {
        ...parseRoleAccessIds(
          c[0].role_access_ids
        )
      };

      const updates = {
        student,
        professor,
        control,
        worker,
        principal
      };

      let changed = 0;

      for (
        const [role, plain]
        of Object.entries(
          updates
        )
      ) {
        if (
          plain &&
          String(
            plain
          )
            .trim()
            .length >= 4
        ) {
          hashed[role] =
            await bcrypt.hash(
              String(
                plain
              )
                .trim()
                .toUpperCase(),
              10
            );

          changed++;
        }
      }

      if (!changed) {
        return res.status(400).json({
          error:
            "No valid new IDs provided (each must be 4+ chars)"
        });
      }

      await pool.query(
        `
        UPDATE colleges
        SET role_access_ids = $1
        WHERE id = $2
        `,
        [
          hashed,
          req.user.collegeId
        ]
      );

      return res.json({
        ok: true,
        changed
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Update failed"
      });
    }
  }
);

/* ------------------------------------------------------------
   AUTH — SIGNUP
   ------------------------------------------------------------ */

app.post(
  '/api/auth/signup',
  async (req, res) => {
    try {
      const b =
        req.body || {};

      const phone =
        String(
          b.phone || ""
        ).replace(
          /\D/g,
          ""
        );

      const collegeId =
        normalizeCollegeId(
          b.collegeId
        );

      const {
        rows: c
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [collegeId]
      );

      if (!c[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const roleAccessIds =
        parseRoleAccessIds(
          c[0].role_access_ids
        );

      const hash =
        roleAccessIds[
          b.role
        ];

      if (
        !hash ||
        !(
          await bcrypt.compare(
            String(
              b.roleAccessId ||
              ""
            )
              .trim()
              .toUpperCase(),
            hash
          )
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid role access ID"
        });
      }

      const {
        rows: dup
      } = await pool.query(
        `
        SELECT id
        FROM accounts
        WHERE
          college_id = $1
          AND role = $2
          AND phone = $3
          AND deleted_at IS NULL
        `,
        [
          collegeId,
          b.role,
          phone
        ]
      );

      if (dup.length) {
        return res.status(409).json({
          error:
            "Account already exists. Please log in."
        });
      }

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO accounts
          (
            college_id,
            role,
            name,
            father_name,
            phone,
            branch,
            year,
            department,
            designation
          )
        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9
          )
        RETURNING *
        `,
        [
          collegeId,
          b.role,
          b.name,
          b.fatherName || "",
          phone,
          b.branch || "",
          b.year || "",
          b.department || "",
          b.designation || ""
        ]
      );

      /*
        Automatically create student profile.
      */

      if (
        b.role ===
        "student"
      ) {
        await pool.query(
          `
          INSERT INTO student_profiles
            (
              college_id,
              account_id,
              name,
              father_name,
              title,
              branch,
              year,
              bio,
              line
            )
          VALUES
            (
              $1,$2,$3,$4,$5,
              $6,$7,$8,$9
            )
          `,
          [
            collegeId,
            rows[0].id,
            b.name,
            b.fatherName || "",
            "B.Tech Student",
            b.branch || "IT",
            b.year || "Year 1",
            "No bio added yet.",
            "Keep learning. Keep building."
          ]
        );
      }

      return res.status(201).json({
        account:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Signup failed"
      });
    }
  }
);

/* ------------------------------------------------------------
   AUTH — LOGIN
   ------------------------------------------------------------ */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const b =
        req.body || {};

      const phone =
        String(
          b.phone || ""
        ).replace(
          /\D/g,
          ""
        );

      const collegeId =
        normalizeCollegeId(
          b.collegeId
        );

      const {
        rows: c
      } = await pool.query(
        `
        SELECT role_access_ids
        FROM colleges
        WHERE id = $1
        `,
        [collegeId]
      );

      if (!c[0]) {
        return res.status(404).json({
          error:
            "College not found"
        });
      }

      const roleAccessIds =
        parseRoleAccessIds(
          c[0].role_access_ids
        );

      const hash =
        roleAccessIds[
          b.role
        ];

      if (
        !hash ||
        !(
          await bcrypt.compare(
            String(
              b.roleAccessId ||
              ""
            )
              .trim()
              .toUpperCase(),
            hash
          )
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid role access ID"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT *
        FROM accounts
        WHERE
          college_id = $1
          AND role = $2
          AND phone = $3
          AND deleted_at IS NULL
        `,
        [
          collegeId,
          b.role,
          phone
        ]
      );

      const account =
        rows[0];

      if (!account) {
        return res.status(401).json({
          error:
            "No account found. Sign up first."
        });
      }

      const token =
        jwt.sign(
          {
            id:
              account.id,

            role:
              account.role,

            collegeId:
              account.college_id,

            phone:
              account.phone,

            name:
              account.name
          },

          JWT_SECRET,

          {
            expiresIn:
              "30d"
          }
        );

      return res.json({
        token,
        account
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Login failed"
      });
    }
  }
);

/* ------------------------------------------------------------
   TICKETS
   ------------------------------------------------------------ */

app.get(
  '/api/tickets',
  requireAuth,
  async (req, res) => {
    try {
      const {
        collegeId,
        role,
        id
      } = req.user;

      const where = [
        "college_id = $1"
      ];

      const params = [
        collegeId
      ];

      if (
        role ===
        "student"
      ) {
        params.push(id);

        where.push(
          `owner_id = $${params.length}`
        );
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT *
        FROM tickets
        WHERE ${where.join(
          " AND "
        )}
        ORDER BY created_at DESC
        `,
        params
      );

      return res.json({
        tickets:
          rows
      });
    } catch (err) {
      return sendDbError(
        res,
        "Could not load tickets",
        err
      );
    }
  }
);

app.post(
  '/api/tickets',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "student"
      ) {
        return res.status(403).json({
          error:
            "Only students can create tickets"
        });
      }

      const b =
        req.body || {};

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO tickets
          (
            short_id,
            college_id,
            owner_id,
            name,
            phone,
            category,
            urgent,
            description,
            issue_image
          )
        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9
          )
        RETURNING *
        `,
        [
          shortTicketId(),

          req.user.collegeId,

          req.user.id,

          b.name || "",

          b.phone || "",

          b.category || "",

          !!b.urgent,

          b.description || "",

          b.issueImage || null
        ]
      );

      return res.status(201).json({
        ticket:
          rows[0]
      });
    } catch (err) {
      return sendDbError(
        res,
        "Could not create ticket",
        err
      );
    }
  }
);

/* ------------------------------------------------------------
   LECTURES
   ------------------------------------------------------------ */

app.get(
  '/api/lectures',
  requireAuth,
  async (req, res) => {
    try {
      const {
        rows
      } = await pool.query(
        `
        SELECT *
        FROM lectures
        WHERE college_id = $1
        ORDER BY date DESC
        `,
        [
          req.user.collegeId
        ]
      );

      return res.json({
        lectures:
          rows
      });
    } catch (err) {
      return sendDbError(
        res,
        "Could not load lectures",
        err
      );
    }
  }
);

app.post(
  '/api/lectures',
  requireAuth,
  async (req, res) => {
    try {
      const b =
        req.body || {};

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO lectures
          (
            college_id,
            professor_id,
            professor_name,
            professor_phone,
            subject,
            branch,
            year,
            semester,
            room,
            date,
            start_time,
            end_time,
            type
          )
        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9,$10,
            $11,$12,$13
          )
        RETURNING *
        `,
        [
          req.user.collegeId,

          req.user.id,

          req.user.name ||
            "",

          req.user.phone ||
            "",

          b.subject ||
            "",

          b.branch ||
            "",

          b.year ||
            "",

          b.semester ||
            "",

          b.room ||
            "",

          b.date ||
            null,

          b.startTime ||
            null,

          b.endTime ||
            null,

          b.type ||
            ""
        ]
      );

      return res.status(201).json({
        lecture:
          rows[0]
      });
    } catch (err) {
      return sendDbError(
        res,
        "Could not create lecture",
        err
      );
    }
  }
);

/* ------------------------------------------------------------
   TICKETS — CONTROL FORWARD
   ------------------------------------------------------------ */

app.patch(
  '/api/tickets/:id/forward',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "control"
      ) {
        return res.status(403).json({
          error:
            "Only Control can forward"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        UPDATE tickets

        SET
          forwarded = TRUE,
          forwarded_at = NOW(),
          status = 'forwarded'

        WHERE
          short_id = $1
          AND college_id = $2
          AND status = 'pending'

        RETURNING *
        `,
        [
          req.params.id,
          req.user.collegeId
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found or already forwarded"
        });
      }

      return res.json({
        ticket:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not forward"
      });
    }
  }
);

/* ------------------------------------------------------------
   TICKETS — WORKER FIX
   ------------------------------------------------------------ */

app.post(
  '/api/tickets/:id/fix',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "worker"
      ) {
        return res.status(403).json({
          error:
            "Only workers can mark fixed"
        });
      }

      const {
        fixImage
      } = req.body || {};

      if (!fixImage) {
        return res.status(400).json({
          error:
            "fixImage required"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        UPDATE tickets

        SET
          fix_image = $1,
          fixed_at = NOW(),
          status = 'fixed'

        WHERE
          short_id = $2
          AND college_id = $3
          AND forwarded = TRUE

        RETURNING *
        `,
        [
          fixImage,
          req.params.id,
          req.user.collegeId
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found or not forwarded"
        });
      }

      return res.json({
        ticket:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not mark fixed"
      });
    }
  }
);

/* ------------------------------------------------------------
   LECTURES — ATTENDANCE
   ------------------------------------------------------------ */

app.patch(
  '/api/lectures/:id/attendance',
  requireAuth,
  async (req, res) => {
    try {
      const {
        attendance
      } = req.body || {};

      if (
        ![
          "attend",
          "not-attend"
        ].includes(attendance)
      ) {
        return res.status(400).json({
          error:
            "attendance must be 'attend' or 'not-attend'"
        });
      }

      const where = [
        "id = $1",
        "college_id = $2"
      ];

      const params = [
        req.params.id,
        req.user.collegeId
      ];

      /*
        Professor can update only their own lecture.
      */

      if (
        req.user.role ===
        "professor"
      ) {
        params.push(
          req.user.id
        );

        where.push(
          `professor_id = $${params.length}`
        );
      }

      /*
        IMPORTANT FIX:
        The attendance placeholder must come
        AFTER all WHERE parameters.

        Previous code accidentally used $3 for
        attendance even when professor_id was also $3.
      */

      const attendanceParams =
        [
          ...params,
          attendance
        ];

      const attendancePlaceholder =
        params.length + 1;

      const {
        rows
      } = await pool.query(
        `
        UPDATE lectures

        SET
          attendance =
            $${attendancePlaceholder},

          attendance_at =
            NOW()

        WHERE
          ${where.join(" AND ")}

        RETURNING *
        `,
        attendanceParams
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found or not yours"
        });
      }

      return res.json({
        lecture:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not update attendance"
      });
    }
  }
);

/* ------------------------------------------------------------
   ACCOUNTS — ADMIN
   ------------------------------------------------------------ */

app.get(
  '/api/accounts',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "principal"
      ) {
        return res.status(403).json({
          error:
            "Admin only"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT
          id,
          role,
          name,
          father_name,
          phone,
          branch,
          year,
          department,
          designation,
          created_at

        FROM accounts

        WHERE
          college_id = $1
          AND deleted_at IS NULL

        ORDER BY name
        `,
        [
          req.user.collegeId
        ]
      );

      return res.json({
        accounts:
          rows
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not load accounts"
      });
    }
  }
);

/* ------------------------------------------------------------
   STUDENT DIRECTORY
   ------------------------------------------------------------ */

app.get(
  '/api/accounts/directory/students',
  requireAuth,
  async (req, res) => {
    try {
      if (
        ![
          "student",
          "professor",
          "principal"
        ].includes(
          req.user.role
        )
      ) {
        return res.status(403).json({
          error:
            "Not allowed"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT
          a.id,
          a.name,
          a.father_name,
          a.branch,
          a.year,
          a.phone,

          p.title,
          p.bio,
          p.line

        FROM accounts a

        LEFT JOIN student_profiles p

          ON
            p.account_id =
              a.id

          AND
            p.college_id =
              a.college_id

        WHERE
          a.college_id = $1

          AND
            a.role = 'student'

          AND
            a.deleted_at IS NULL

        ORDER BY a.name
        `,
        [
          req.user.collegeId
        ]
      );

      return res.json({
        students:
          rows
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not load students"
      });
    }
  }
);

/* ------------------------------------------------------------
   FACULTY DIRECTORY
   ------------------------------------------------------------ */

app.get(
  '/api/accounts/directory/faculty',
  requireAuth,
  async (req, res) => {
    try {
      if (
        ![
          "professor",
          "principal"
        ].includes(
          req.user.role
        )
      ) {
        return res.status(403).json({
          error:
            "Not allowed"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT
          id,
          name,
          phone,
          designation,
          department,
          branch

        FROM accounts

        WHERE
          college_id = $1

          AND
            role = 'professor'

          AND
            deleted_at IS NULL

        ORDER BY name
        `,
        [
          req.user.collegeId
        ]
      );

      return res.json({
        faculty:
          rows
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not load faculty"
      });
    }
  }
);

/* ------------------------------------------------------------
   CREATE ACCOUNT — ADMIN
   ------------------------------------------------------------ */

app.post(
  '/api/accounts',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "principal"
      ) {
        return res.status(403).json({
          error:
            "Admin only"
        });
      }

      const b =
        req.body || {};

      if (
        !b.role ||
        !b.name ||
        !b.phone
      ) {
        return res.status(400).json({
          error:
            "Role, name and phone required"
        });
      }

      const phone =
        String(
          b.phone
        ).replace(
          /\D/g,
          ""
        );

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO accounts
          (
            college_id,
            role,
            name,
            father_name,
            phone,
            branch,
            year,
            department,
            designation
          )

        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9
          )

        RETURNING *
        `,
        [
          req.user.collegeId,

          b.role,

          b.name,

          b.fatherName ||
            "",

          phone,

          b.branch ||
            "",

          b.year ||
            "",

          b.department ||
            "",

          b.designation ||
            ""
        ]
      );

      /*
        Create student profile if needed.
      */

      if (
        b.role ===
        "student"
      ) {
        await pool.query(
          `
          INSERT INTO student_profiles
            (
              college_id,
              account_id,
              name,
              father_name,
              title,
              branch,
              year,
              bio,
              line
            )

          VALUES
            (
              $1,$2,$3,$4,$5,
              $6,$7,$8,$9
            )
          `,
          [
            req.user.collegeId,

            rows[0].id,

            b.name,

            b.fatherName ||
              "",

            "B.Tech Student",

            b.branch ||
              "IT",

            b.year ||
              "Year 1",

            "No bio added yet.",

            "Keep learning. Keep building."
          ]
        );
      }

      return res.status(201).json({
        account:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not add account"
      });
    }
  }
);

/* ------------------------------------------------------------
   UPDATE ACCOUNT — ADMIN
   ------------------------------------------------------------ */

app.patch(
  '/api/accounts/:id',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "principal"
      ) {
        return res.status(403).json({
          error:
            "Admin only"
        });
      }

      const b =
        req.body || {};

      const phone =
        String(
          b.phone || ""
        ).replace(
          /\D/g,
          ""
        );

      const {
        rows
      } = await pool.query(
        `
        UPDATE accounts

        SET
          name = $1,
          father_name = $2,
          phone = $3,
          branch = $4,
          year = $5,
          department = $6,
          designation = $7

        WHERE
          id = $8
          AND college_id = $9

        RETURNING *
        `,
        [
          b.name,

          b.fatherName ||
            "",

          phone,

          b.branch ||
            "",

          b.year ||
            "",

          b.department ||
            "",

          b.designation ||
            "",

          req.params.id,

          req.user.collegeId
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found"
        });
      }

      return res.json({
        account:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not update account"
      });
    }
  }
);

/* ------------------------------------------------------------
   DELETE ACCOUNT — ADMIN
   ------------------------------------------------------------ */

app.delete(
  '/api/accounts/:id',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "principal"
      ) {
        return res.status(403).json({
          error:
            "Admin only"
        });
      }

      await pool.query(
        `
        UPDATE accounts

        SET
          deleted_at = NOW()

        WHERE
          id = $1
          AND college_id = $2
        `,
        [
          req.params.id,
          req.user.collegeId
        ]
      );

      return res.json({
        ok: true
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not delete"
      });
    }
  }
);

/* ------------------------------------------------------------
   PROFILES — OWN STUDENT PROFILE
   ------------------------------------------------------------ */

app.get(
  '/api/profiles/me',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "student"
      ) {
        return res.status(403).json({
          error:
            "Student only"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT *
        FROM student_profiles
        WHERE
          account_id = $1
          AND college_id = $2
        `,
        [
          req.user.id,
          req.user.collegeId
        ]
      );

      return res.json({
        profile:
          rows[0] ||
          null
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not load profile"
      });
    }
  }
);

/* ------------------------------------------------------------
   UPDATE STUDENT PROFILE
   ------------------------------------------------------------ */

app.put(
  '/api/profiles/me',
  requireAuth,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "student"
      ) {
        return res.status(403).json({
          error:
            "Student only"
        });
      }

      const b =
        req.body || {};

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO student_profiles
          (
            college_id,
            account_id,
            name,
            father_name,
            title,
            branch,
            year,
            bio,
            line
          )

        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9
          )

        ON CONFLICT
          (college_id, account_id)

        DO UPDATE SET

          name =
            $3,

          father_name =
            $4,

          title =
            $5,

          branch =
            $6,

          year =
            $7,

          bio =
            $8,

          line =
            $9,

          updated_at =
            NOW()

        RETURNING *
        `,
        [
          req.user.collegeId,

          req.user.id,

          b.name,

          b.fatherName ||
            "",

          b.title ||
            "B.Tech Student",

          b.branch ||
            "IT",

          b.year ||
            "Year 1",

          b.bio ||
            "No bio added yet.",

          b.line ||
            "Keep learning. Keep building."
        ]
      );

      return res.json({
        profile:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not save profile"
      });
    }
  }
);

/* ------------------------------------------------------------
   PYQ
   ------------------------------------------------------------ */

const PYQ_MAX_SIZE =
  4 * 1024 * 1024;

/*
  List PYQs
*/

app.get(
  '/api/pyqs',
  requireAuth,
  async (req, res) => {
    try {
      const {
        collegeId
      } = req.user;

      const {
        branch,
        year,
        semester
      } = req.query;

      const where = [
        "college_id = $1"
      ];

      const params = [
        collegeId
      ];

      if (branch) {
        params.push(
          branch
        );

        where.push(
          `branch = $${params.length}`
        );
      }

      if (year) {
        params.push(
          Number(year)
        );

        where.push(
          `year = $${params.length}`
        );
      }

      if (semester) {
        params.push(
          semester
        );

        where.push(
          `semester = $${params.length}`
        );
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT
          id,
          title,
          subject,
          branch,
          year,
          semester,
          description,
          file_name,
          file_size,
          uploaded_by_name,
          uploaded_by_role,
          uploaded_by_phone,
          created_at

        FROM pyqs

        WHERE
          ${where.join(
            " AND "
          )}

        ORDER BY
          created_at DESC
        `,
        params
      );

      return res.json({
        pyqs:
          rows
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not load PYQs"
      });
    }
  }
);

/*
  Get one PYQ
*/

app.get(
  '/api/pyqs/:id',
  requireAuth,
  async (req, res) => {
    try {
      const {
        rows
      } = await pool.query(
        `
        SELECT
          file_data,
          file_name

        FROM pyqs

        WHERE
          id = $1
          AND college_id = $2
        `,
        [
          req.params.id,
          req.user.collegeId
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found"
        });
      }

      return res.json({
        file_data:
          rows[0]
            .file_data,

        file_name:
          rows[0]
            .file_name
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not fetch file"
      });
    }
  }
);

/*
  Upload PYQ
*/

app.post(
  '/api/pyqs',
  requireAuth,
  async (req, res) => {
    try {
      if (
        ![
          "professor",
          "control",
          "principal"
        ].includes(
          req.user.role
        )
      ) {
        return res.status(403).json({
          error:
            "Only faculty can upload PYQs"
        });
      }

      const b =
        req.body || {};

      if (
        !b.title ||
        !b.branch ||
        !b.year ||
        !b.fileData ||
        !b.fileName
      ) {
        return res.status(400).json({
          error:
            "Missing required fields"
        });
      }

      /*
        Approximate Base64 decoded size.
      */

      const approxSize =
        Math.round(
          String(
            b.fileData
          ).length *
            0.75
        );

      if (
        approxSize >
        PYQ_MAX_SIZE
      ) {
        return res.status(413).json({
          error:
            "PDF too large (max 4 MB)"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        INSERT INTO pyqs
          (
            college_id,
            title,
            subject,
            branch,
            year,
            semester,
            description,
            file_data,
            file_name,
            file_size,
            uploaded_by_phone,
            uploaded_by_name,
            uploaded_by_role
          )

        VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9,$10,
            $11,$12,$13
          )

        RETURNING
          id,
          title,
          subject,
          branch,
          year,
          semester,
          description,
          file_name,
          file_size,
          uploaded_by_name,
          uploaded_by_role,
          uploaded_by_phone,
          created_at
        `,
        [
          req.user.collegeId,

          b.title,

          b.subject ||
            "",

          b.branch,

          Number(
            b.year
          ),

          b.semester ||
            "",

          b.description ||
            "",

          b.fileData,

          b.fileName,

          approxSize,

          req.user.phone ||
            "",

          req.user.name ||
            "",

          req.user.role
        ]
      );

      return res.status(201).json({
        pyq:
          rows[0]
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not save PYQ"
      });
    }
  }
);

/*
  Delete PYQ
*/

app.delete(
  '/api/pyqs/:id',
  requireAuth,
  async (req, res) => {
    try {
      if (
        ![
          "professor",
          "control",
          "principal"
        ].includes(
          req.user.role
        )
      ) {
        return res.status(403).json({
          error:
            "Not allowed"
        });
      }

      const {
        rows
      } = await pool.query(
        `
        SELECT
          uploaded_by_phone

        FROM pyqs

        WHERE
          id = $1
          AND college_id = $2
        `,
        [
          req.params.id,
          req.user.collegeId
        ]
      );

      if (!rows[0]) {
        return res.status(404).json({
          error:
            "Not found"
        });
      }

      const canDelete =
        req.user.role ===
          "principal" ||

        rows[0]
          .uploaded_by_phone ===
          (
            req.user.phone ||
            ""
          );

      if (!canDelete) {
        return res.status(403).json({
          error:
            "You can only delete your own uploads"
        });
      }

      await pool.query(
        `
        DELETE FROM pyqs
        WHERE id = $1
        `,
        [
          req.params.id
        ]
      );

      return res.json({
        ok: true
      });
    } catch (err) {
      console.error(err);

      return res.status(500).json({
        error:
          "Could not delete"
      });
    }
  }
);

/* ------------------------------------------------------------
   START SERVER
   ------------------------------------------------------------ */

const PORT =
  process.env.PORT ||
  4000;

async function startServer() {
  try {
    /*
      Check/create DB schema before
      accepting requests.
    */

    await ensureDatabaseSchema();

    app.listen(
      PORT,
      () => {
        console.log(
          `🚀 FixPoint API running on port ${PORT}`
        );

        console.log(
          `Database schema check: OK`
        );

        console.log(
          `POST   /api/colleges`
        );

        console.log(
          `POST   /api/colleges/login`
        );

        console.log(
          `GET    /api/colleges/exists`
        );

        console.log(
          `PATCH  /api/colleges/me/role-ids`
        );

        console.log(
          `POST   /api/auth/verify-role`
        );

        console.log(
          `POST   /api/auth/admin-token`
        );

        console.log(
          `POST   /api/auth/role-token`
        );

        console.log(
          `POST   /api/auth/signup`
        );

        console.log(
          `POST   /api/auth/login`
        );

        console.log(
          `GET    /api/tickets`
        );

        console.log(
          `POST   /api/tickets`
        );

        console.log(
          `GET    /api/lectures`
        );

        console.log(
          `POST   /api/lectures`
        );

        console.log(
          `GET    /api/pyqs`
        );

        console.log(
          `POST   /api/pyqs`
        );

        console.log(
          `DELETE /api/pyqs/:id`
        );
      }
    );
  } catch (err) {
    console.error(
      "❌ FixPoint API failed to start:",
      err
    );

    process.exit(1);
  }
}

startServer();
