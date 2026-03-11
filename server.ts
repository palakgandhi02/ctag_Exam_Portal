import express from "express";
import { createServer as createViteServer } from "vite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = "exam_platform.db";
const db = new Database(dbPath);
const JWT_SECRET = process.env.JWT_SECRET || "ctag-secret-key-2026";

// Initialize Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
    name TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    option_a TEXT NOT NULL,
    option_b TEXT NOT NULL,
    option_c TEXT NOT NULL,
    option_d TEXT NOT NULL,
    correct_answer TEXT NOT NULL,
    topic TEXT,
    difficulty TEXT
  );

  CREATE TABLE IF NOT EXISTS exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    duration_minutes INTEGER DEFAULT 150,
    is_active INTEGER DEFAULT 0,
    scheduled_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS exam_questions (
    exam_id INTEGER,
    question_id INTEGER,
    order_index INTEGER,
    PRIMARY KEY (exam_id, question_id),
    FOREIGN KEY (exam_id) REFERENCES exams(id),
    FOREIGN KEY (question_id) REFERENCES questions(id)
  );

  CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    exam_id INTEGER,
    question_id INTEGER,
    selected_option TEXT,
    is_correct INTEGER,
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (exam_id) REFERENCES exams(id),
    FOREIGN KEY (question_id) REFERENCES questions(id)
  );

  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    exam_id INTEGER,
    score INTEGER,
    total_questions INTEGER,
    accuracy REAL,
    obtained_marks REAL DEFAULT 0,
    wrong_attempted INTEGER DEFAULT 0,
    not_attempted INTEGER DEFAULT 0,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (exam_id) REFERENCES exams(id)
  );

  CREATE TABLE IF NOT EXISTS warning_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    exam_id INTEGER,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (exam_id) REFERENCES exams(id)
  );
`);

// Migration for existing databases
try {
  db.prepare("ALTER TABLE exams ADD COLUMN scheduled_at DATETIME").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE results ADD COLUMN obtained_marks REAL DEFAULT 0").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE results ADD COLUMN wrong_attempted INTEGER DEFAULT 0").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE results ADD COLUMN not_attempted INTEGER DEFAULT 0").run();
} catch (e) {}

// Seed Admin User
const adminEmail = "support@c-tag.online";
const adminPass = "TE@M4ctag";
const existingAdmin = db.prepare("SELECT * FROM users WHERE email = ?").get(adminEmail);
if (!existingAdmin) {
  const hashedPass = bcrypt.hashSync(adminPass, 10);
  db.prepare("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)").run(
    adminEmail,
    hashedPass,
    "admin",
    "C-TAG Admin"
  );
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT || 3000;
  console.log(`Starting server on port ${PORT}...`);
  app.use(express.json());

  // --- Auth Middleware ---
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.status(403).json({ error: "Forbidden" });
      req.user = user;
      next();
    });
  };

  const isAdmin = (req: any, res: any, next: any) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" });
    next();
  };

  // --- Auth APIs ---
  app.post("/api/login", (req, res) => {
    const { email, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, name: user.name } });
  });

  app.post("/api/register", (req, res) => {
    const { email, password, name } = req.body;
    try {
      const hashedPass = bcrypt.hashSync(password, 10);
      db.prepare("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)").run(
        email,
        hashedPass,
        "student",
        name
      );
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Email already exists" });
    }
  });

  // --- Question APIs ---
  app.get("/api/admin/questions", authenticateToken, isAdmin, (req, res) => {
    const questions = db.prepare("SELECT * FROM questions").all();
    res.json(questions);
  });

  app.post("/api/admin/questions", authenticateToken, isAdmin, (req, res) => {
    const { text, option_a, option_b, option_c, option_d, correct_answer, topic, difficulty } = req.body;
    const result = db.prepare(`
      INSERT INTO questions (text, option_a, option_b, option_c, option_d, correct_answer, topic, difficulty)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(text, option_a, option_b, option_c, option_d, correct_answer, topic, difficulty);
    res.json({ id: result.lastInsertRowid });
  });

  app.post("/api/admin/questions/bulk", authenticateToken, isAdmin, (req, res) => {
    const { questions } = req.body;
    const insert = db.prepare(`
      INSERT INTO questions (text, option_a, option_b, option_c, option_d, correct_answer, topic, difficulty)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertMany = db.transaction((qs) => {
      for (const q of qs) insert.run(q.text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_answer, q.topic, q.difficulty);
    });
    insertMany(questions);
    res.json({ success: true });
  });

  // --- Exam APIs ---
  app.get("/api/exams", authenticateToken, (req, res) => {
    const exams = db.prepare("SELECT * FROM exams WHERE is_active = 1").all();
    res.json(exams);
  });

  app.get("/api/admin/exams", authenticateToken, isAdmin, (req, res) => {
    const exams = db.prepare("SELECT * FROM exams").all();
    res.json(exams);
  });

  app.post("/api/admin/exams", authenticateToken, isAdmin, (req, res) => {
    try {
      const { title, duration_minutes, question_ids, scheduled_at } = req.body;
      const result = db.prepare("INSERT INTO exams (title, duration_minutes, scheduled_at) VALUES (?, ?, ?)").run(title, duration_minutes, scheduled_at);
      const examId = Number(result.lastInsertRowid);
      
      const insertQ = db.prepare("INSERT INTO exam_questions (exam_id, question_id, order_index) VALUES (?, ?, ?)");
      question_ids.forEach((id: number, index: number) => {
        insertQ.run(examId, id, index);
      });
      
      res.json({ id: examId });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  });

  app.patch("/api/admin/exams/:id/toggle", authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    const { is_active } = req.body;
    db.prepare("UPDATE exams SET is_active = ? WHERE id = ?").run(is_active ? 1 : 0, id);
    res.json({ success: true });
  });

  // --- Exam Engine APIs ---
  app.get("/api/exams/:id/questions", authenticateToken, (req, res) => {
    const { id } = req.params;
    const questions = db.prepare(`
      SELECT q.* FROM questions q
      JOIN exam_questions eq ON q.id = eq.question_id
      WHERE eq.exam_id = ?
      ORDER BY eq.order_index ASC
    `).all(id);
    res.json(questions);
  });

  app.post("/api/exams/:id/submit", authenticateToken, (req, res) => {
    const { id: examId } = req.params;
    const { responses } = req.body;
    const studentId = (req as any).user.id;

    // Check if already submitted
    const existing = db.prepare("SELECT id FROM results WHERE student_id = ? AND exam_id = ?").get(studentId, examId);
    if (existing) return res.status(400).json({ error: "Exam already submitted" });

    // Get total questions for this exam
    const examQuestions = db.prepare("SELECT COUNT(*) as count FROM exam_questions WHERE exam_id = ?").get(examId) as any;
    const totalQuestions = examQuestions.count;

    let score = 0;
    let wrongAttempted = 0;
    let attempted = 0;

    const insertResponse = db.prepare(`
      INSERT INTO responses (student_id, exam_id, question_id, selected_option, is_correct)
      VALUES (?, ?, ?, ?, ?)
    `);

    responses.forEach((resp: any) => {
      if (resp.selected_option) {
        attempted++;
        const question: any = db.prepare("SELECT correct_answer FROM questions WHERE id = ?").get(resp.question_id);
        const isCorrect = question.correct_answer.toUpperCase() === resp.selected_option.toUpperCase() ? 1 : 0;
        if (isCorrect) {
          score++;
        } else {
          wrongAttempted++;
        }
        insertResponse.run(studentId, examId, resp.question_id, resp.selected_option, isCorrect);
      } else {
        // Not attempted
        insertResponse.run(studentId, examId, resp.question_id, null, 0);
      }
    });

    const notAttempted = totalQuestions - attempted;
    const accuracy = totalQuestions > 0 ? (score / totalQuestions) * 100 : 0;
    const obtainedMarks = (score * 2) - (wrongAttempted * 0.5);

    db.prepare(`
      INSERT INTO results (student_id, exam_id, score, total_questions, accuracy, obtained_marks, wrong_attempted, not_attempted)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(studentId, examId, score, totalQuestions, accuracy, obtainedMarks, wrongAttempted, notAttempted);

    res.json({ score, total: totalQuestions, accuracy, obtained_marks: obtainedMarks, wrong_attempted: wrongAttempted, not_attempted: notAttempted });
  });

  app.post("/api/exams/:id/warning", authenticateToken, (req, res) => {
    const { id: examId } = req.params;
    const { message } = req.body;
    const studentId = (req as any).user.id;
    db.prepare("INSERT INTO warning_logs (student_id, exam_id, message) VALUES (?, ?, ?)").run(studentId, examId, message);
    res.json({ success: true });
  });

  // --- Analytics APIs ---
  app.get("/api/admin/analytics/:examId", authenticateToken, isAdmin, (req, res) => {
    const { examId } = req.params;
    const results = db.prepare(`
      SELECT r.*, u.name as student_name 
      FROM results r
      JOIN users u ON r.student_id = u.id
      WHERE r.exam_id = ?
      ORDER BY r.obtained_marks DESC
    `).all(examId);

    const stats = db.prepare(`
      SELECT 
        COUNT(*) as total_students,
        AVG(obtained_marks) as avg_score,
        MAX(obtained_marks) as max_score,
        MIN(obtained_marks) as min_score
      FROM results
      WHERE exam_id = ?
    `).get(examId);

    const warnings = db.prepare(`
      SELECT w.*, u.name as student_name
      FROM warning_logs w
      JOIN users u ON w.student_id = u.id
      WHERE w.exam_id = ?
    `).all(examId);

    // Get detailed responses for Excel export (topics)
    const detailedResponses = db.prepare(`
      SELECT res.*, q.topic, q.correct_answer
      FROM responses res
      JOIN questions q ON res.question_id = q.id
      WHERE res.exam_id = ?
    `).all(examId);

    res.json({ results, stats, warnings, detailedResponses });
  });

  app.get("/api/admin/dashboard-stats", authenticateToken, isAdmin, (req, res) => {
    const totalExams = db.prepare("SELECT COUNT(*) as count FROM exams").get() as any;
    const totalStudents = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'student'").get() as any;
    const totalQuestions = db.prepare("SELECT COUNT(*) as count FROM questions").get() as any;
    const recentResults = db.prepare(`
      SELECT r.*, u.name as student_name, e.title as exam_title
      FROM results r
      JOIN users u ON r.student_id = u.id
      JOIN exams e ON r.exam_id = e.id
      ORDER BY r.submitted_at DESC
      LIMIT 5
    `).all();

    res.json({
      totalExams: totalExams.count,
      totalStudents: totalStudents.count,
      totalQuestions: totalQuestions.count,
      recentResults
    });
  });

  // --- Student APIs ---
  app.get("/api/student/results", authenticateToken, (req, res) => {
    const studentId = (req as any).user.id;
    const results = db.prepare(`
      SELECT r.*, e.title as exam_title
      FROM results r
      JOIN exams e ON r.exam_id = e.id
      WHERE r.student_id = ?
      ORDER BY r.submitted_at DESC
    `).all(studentId);
    res.json(results);
  });

  // --- Vite / Static Files ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error("Failed to start server:", err);
});
