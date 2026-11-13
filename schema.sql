-- ============================================================================
-- PhishShield Phishing Awareness Simulation - Database Schema (SQLite3)
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. Simulation Sessions Table
-- Tracks participant identity, state progression, dwell time, and vulnerability posture
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uuid TEXT UNIQUE NOT NULL,
    participant_id TEXT NOT NULL,
    department TEXT DEFAULT 'General',
    ip_address TEXT DEFAULT '127.0.0.1',
    user_agent TEXT DEFAULT 'Unknown Browser',
    current_step TEXT DEFAULT 'intro', -- 'intro', 'email_simulation', 'login_trap', 'awareness_lesson', 'quiz', 'completed'
    status TEXT DEFAULT 'in_progress', -- 'in_progress', 'completed', 'abandoned'
    risk_rating TEXT DEFAULT 'unassessed', -- 'low', 'medium', 'high', 'critical'
    compromised_status INTEGER DEFAULT 0, -- 1 if participant clicked phishing link or entered credentials
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_uuid ON sessions(session_uuid);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_risk ON sessions(risk_rating);

-- 2. Interaction Events Table
-- Captures granular user interaction telemetry during each stage of the simulation
CREATE TABLE IF NOT EXISTS interaction_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    session_uuid TEXT NOT NULL,
    event_type TEXT NOT NULL, 
    -- Event Types:
    -- 'SESSION_START', 'EMAIL_OPENED', 'HEADER_EXPANDED', 'SUSPICIOUS_LINK_HOVERED',
    -- 'SUSPICIOUS_LINK_CLICKED', 'REPORT_PHISH_CLICKED', 'LOGIN_PAGE_VIEWED',
    -- 'CREDENTIAL_ATTEMPTED', 'AWARENESS_ALERT_TRIGGERED', 'LESSON_ACCESSED',
    -- 'RED_FLAG_INSPECTED', 'LESSON_COMPLETED', 'QUIZ_STARTED', 'QUIZ_ANSWER_SELECTED',
    -- 'QUIZ_SUBMITTED', 'FEEDBACK_REVIEWED'
    stage TEXT NOT NULL, -- 'intro', 'email_simulation', 'login_trap', 'awareness_lesson', 'quiz', 'completed'
    target_element TEXT,
    dwell_time_ms INTEGER DEFAULT 0,
    metadata_json TEXT DEFAULT '{}',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON interaction_events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_session_uuid ON interaction_events(session_uuid);
CREATE INDEX IF NOT EXISTS idx_events_type ON interaction_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON interaction_events(timestamp);

-- 3. Quiz Results Table
-- Stores user answers, scoring calculation, pass/fail evaluation, and feedback
CREATE TABLE IF NOT EXISTS quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER UNIQUE NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    session_uuid TEXT NOT NULL,
    q1_answer TEXT NOT NULL,
    q1_is_correct INTEGER NOT NULL,
    q2_answer TEXT NOT NULL,
    q2_is_correct INTEGER NOT NULL,
    q3_answer TEXT,
    q3_is_correct INTEGER,
    total_questions INTEGER NOT NULL DEFAULT 2,
    score INTEGER NOT NULL,
    percentage REAL NOT NULL,
    passed INTEGER NOT NULL, -- 1 if score >= 80%, 0 otherwise
    time_taken_seconds INTEGER DEFAULT 0,
    feedback TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_quiz_session_id ON quiz_results(session_id);
CREATE INDEX IF NOT EXISTS idx_quiz_passed ON quiz_results(passed);


-- 4. Admin Users Table
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
