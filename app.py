"""
Flask Application Entry Point for PhishShield
Provides REST APIs for:
- Simulation Session Management
- Interaction Event Storage & Telemetry
- Quiz Result Evaluation & Storage
- Cybersecurity Analytics & Vulnerability Reporting
- Database Management & Inspection
"""

import os
import json
import sqlite3
import bcrypt
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from database import get_db_connection, init_db, query_db, execute_db
from models import SimulationSession, InteractionEvent, QuizSubmission, calculate_risk_rating

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-before-deployment"
)
# Enable CORS for cross-origin frontend requests
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Ensure database is initialized on startup
with app.app_context():
    init_db()
token_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# ============================================================================
# Admin Authentication
# ============================================================================

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "success": False,
                "error": "Admin login required"
            }), 401

        token = auth_header.split(" ", 1)[1]

        try:
            admin_data = token_serializer.loads(
                token,
                salt="admin-auth",
                max_age=3600
            )

            admin = query_db(
                "SELECT id, username FROM admin_users WHERE id = ?",
                (admin_data.get("admin_id"),),
                one=True
            )

            if not admin:
                raise BadSignature("Admin account not found")

            request.admin = admin

        except (BadSignature, SignatureExpired):
            return jsonify({
                "success": False,
                "error": "Invalid or expired admin token"
            }), 401

        return func(*args, **kwargs)

    return wrapper

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Username and password are required"
        }), 400

    admin = query_db(
        "SELECT * FROM admin_users WHERE username = ?",
        (username,),
        one=True
    )

    if not admin or not bcrypt.checkpw(
        password.encode("utf-8"),
        admin["password_hash"].encode("utf-8")
    ):
        return jsonify({
            "success": False,
            "error": "Invalid username or password"
        }), 401
    token = token_serializer.dumps(
        {"admin_id": admin["id"]},
        salt="admin-auth"
    )

    return jsonify({
        "success": True,
        "message": "Admin login successful",
        "token": token,
        "username": admin["username"]
    }), 200

# ============================================================================
# Health & Meta Endpoints
# ============================================================================

@app.route("/", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    """API health status and route discovery."""
    return jsonify({
        "status": "online",
        "service": "PhishShield Cybersecurity Simulation Backend",
        "framework": "Flask 3.0",
        "database": "SQLite3 (phishing_simulation.db)",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "sessions": {
                "start": "POST /api/sessions/start",
                "get": "GET /api/sessions/<uuid>",
                "update_step": "PATCH /api/sessions/<uuid>/step",
                "list": "GET /api/sessions"
            },
            "events": {
                "log": "POST /api/events",
                "list": "GET /api/events"
            },
            "quiz": {
                "submit": "POST /api/quiz/submit",
                "results": "GET /api/quiz/results/<uuid>"
            },
            "analytics": {
                "summary": "GET /api/analytics/summary"
            },
            "database": {
                "tables": "GET /api/db/tables",
                "seed": "POST /api/db/seed",
                "export": "GET /api/db/export"
            }
        }
    }), 200


# ============================================================================
# Admin Registration API
# ============================================================================



# ============================================================================
# 1. Simulation Session Management
# ============================================================================

@app.route("/api/sessions/start", methods=["POST"])
def start_session():
    """
    Initializes a new simulation session for a participant.
    Payload: { participant_id?: str, department?: str }
    """
    data = request.get_json(silent=True) or {}
    participant_id = data.get("participant_id") or f"user_{datetime.utcnow().strftime('%M%S%f')[:6]}"
    department = data.get("department", "Corporate")
    ip_addr = request.remote_addr or "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "Unknown Browser")

    session = SimulationSession.create_new(
        participant_id=participant_id,
        department=department,
        ip=ip_addr,
        user_agent=user_agent
    )

    query = """
        INSERT INTO sessions (
            session_uuid, participant_id, department, ip_address, 
            user_agent, current_step, status, risk_rating, compromised_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    session_id = execute_db(query, (
        session.session_uuid,
        session.participant_id,
        session.department,
        session.ip_address,
        session.user_agent,
        session.current_step,
        session.status,
        session.risk_rating,
        session.compromised_status
    ))

    # Log initial SESSION_START event
    execute_db("""
        INSERT INTO interaction_events (
            session_id, session_uuid, event_type, stage, target_element, metadata_json
        ) VALUES (?, ?, 'SESSION_START', 'intro', 'start_button', ?)
    """, (session_id, session.session_uuid, json.dumps({"source": "frontend_init"})))

    return jsonify({
        "success": True,
        "message": "Simulation session created successfully",
        "session": {
            "id": session_id,
            "session_uuid": session.session_uuid,
            "participant_id": session.participant_id,
            "department": session.department,
            "current_step": "intro",
            "status": "in_progress",
            "risk_rating": "unassessed"
        }
    }), 201


@app.route("/api/sessions/<session_uuid>", methods=["GET"])
@admin_required
def get_session(session_uuid):
    """Retrieves full session details including event timeline and quiz result."""
    session = query_db("SELECT * FROM sessions WHERE session_uuid = ?", (session_uuid,), one=True)
    if not session:
        return jsonify({"success": False, "error": "Session not found"}), 404

    events = query_db(
        "SELECT * FROM interaction_events WHERE session_uuid = ? ORDER BY timestamp ASC",
        (session_uuid,)
    )
    quiz_result = query_db(
        "SELECT * FROM quiz_results WHERE session_uuid = ?",
        (session_uuid,),
        one=True
    )

    # Parse JSON metadata in events
    for ev in events:
        try:
            ev["metadata"] = json.loads(ev.get("metadata_json", "{}"))
        except Exception:
            ev["metadata"] = {}

    return jsonify({
        "success": True,
        "session": session,
        "events": events,
        "quiz_result": quiz_result
    }), 200


@app.route("/api/sessions/<session_uuid>/step", methods=["PATCH"])
def update_session_step(session_uuid):
    """Advances participant progression step (e.g. intro -> email_simulation -> login_trap -> awareness -> quiz)."""
    data = request.get_json(silent=True) or {}
    new_step = data.get("step")
    if not new_step:
        return jsonify({"success": False, "error": "Missing 'step' parameter"}), 400

    execute_db("""
        UPDATE sessions 
        SET current_step = ?, updated_at = CURRENT_TIMESTAMP
        WHERE session_uuid = ?
    """, (new_step, session_uuid))

    return jsonify({"success": True, "session_uuid": session_uuid, "current_step": new_step}), 200


@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    """Lists recent simulation sessions with optional limit and status filters."""
    limit = int(request.args.get("limit", 50))
    status = request.args.get("status")

    if status:
        rows = query_db(
            "SELECT * FROM sessions WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, limit)
        )
    else:
        rows = query_db(
            "SELECT * FROM sessions ORDER BY id DESC LIMIT ?",
            (limit,)
        )

    return jsonify({"success": True, "count": len(rows), "sessions": rows}), 200


# ============================================================================
# 2. Interaction Event Storage (Telemetry)
# ============================================================================

@app.route("/api/events", methods=["POST"])
def log_event():
    """
    Stores an interaction event from the simulation interface.
    Required: session_uuid, event_type, stage
    Optional: target_element, dwell_time_ms, metadata
    """
    data = request.get_json(silent=True) or {}
    session_uuid = data.get("session_uuid")
    event_type = data.get("event_type")
    stage = data.get("stage", "simulation")

    if not session_uuid or not event_type:
        return jsonify({"success": False, "error": "session_uuid and event_type are required"}), 400

    session = query_db("SELECT id, compromised_status FROM sessions WHERE session_uuid = ?", (session_uuid,), one=True)
    if not session:
        return jsonify({"success": False, "error": "Session not found"}), 404

    target_element = data.get("target_element")
    dwell_time_ms = int(data.get("dwell_time_ms", 0))
    metadata = data.get("metadata", {})
    meta_json = json.dumps(metadata) if isinstance(metadata, dict) else str(metadata)

    event_id = execute_db("""
        INSERT INTO interaction_events (
            session_id, session_uuid, event_type, stage, target_element, dwell_time_ms, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (session["id"], session_uuid, event_type, stage, target_element, dwell_time_ms, meta_json))

    # Flag compromised status if phishing link clicked or credential entered
    if event_type in ["SUSPICIOUS_LINK_CLICKED", "CREDENTIAL_ATTEMPTED"]:
        execute_db("""
            UPDATE sessions 
            SET compromised_status = 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (session["id"],))

    return jsonify({
        "success": True,
        "event_id": event_id,
        "session_uuid": session_uuid,
        "event_type": event_type
    }), 201


@app.route("/api/events", methods=["GET"])
@admin_required
def list_events():
    """Fetches interaction events with optional filtering by session_uuid or event_type."""
    session_uuid = request.args.get("session_uuid")
    event_type = request.args.get("event_type")
    limit = int(request.args.get("limit", 100))

    params = []
    where_clauses = []

    if session_uuid:
        where_clauses.append("session_uuid = ?")
        params.append(session_uuid)
    if event_type:
        where_clauses.append("event_type = ?")
        params.append(event_type)

    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    params.append(limit)

    query = f"SELECT * FROM interaction_events {where_str} ORDER BY id DESC LIMIT ?"
    rows = query_db(query, tuple(params))

    for r in rows:
        try:
            r["metadata"] = json.loads(r.get("metadata_json", "{}"))
        except Exception:
            r["metadata"] = {}

    return jsonify({"success": True, "count": len(rows), "events": rows}), 200


# ============================================================================
# 3. Quiz Result Storage & Evaluation
# ============================================================================

@app.route("/api/quiz/submit", methods=["POST"])
def submit_quiz():
    """
    Evaluates participant answers, stores score into quiz_results,
    computes risk profile, and marks session as completed.
    Payload: { session_uuid, q1_answer, q2_answer, q3_answer?, time_taken_seconds? }
    """
    data = request.get_json(silent=True) or {}
    session_uuid = data.get("session_uuid")
    q1_answer = data.get("q1_answer")
    q2_answer = data.get("q2_answer")
    q3_answer = data.get("q3_answer")
    time_taken = int(data.get("time_taken_seconds", 0))

    if not session_uuid or q1_answer is None or q2_answer is None:
        return jsonify({
            "success": False, 
            "error": "session_uuid, q1_answer, and q2_answer are required"
        }), 400

    session = query_db("SELECT * FROM sessions WHERE session_uuid = ?", (session_uuid,), one=True)
    if not session:
        return jsonify({"success": False, "error": "Session not found"}), 404

    submission = QuizSubmission(
        q1_answer=str(q1_answer),
        q2_answer=str(q2_answer),
        q3_answer=str(q3_answer) if q3_answer is not None else None,
        time_taken_seconds=time_taken
    )
    result = submission.evaluate()

    # Check if participant previously reported phishing
    reported_event = query_db(
        "SELECT id FROM interaction_events WHERE session_id = ? AND event_type = 'REPORT_PHISH_CLICKED'",
        (session["id"],),
        one=True
    )
    reported_phish = bool(reported_event)

    # Compute risk rating
    final_risk = calculate_risk_rating(
        compromised_status=session["compromised_status"],
        quiz_passed=result["passed"],
        reported_phish=reported_phish
    )

    # Upsert quiz result (SQLite REPLACE INTO)
    execute_db("""
        INSERT OR REPLACE INTO quiz_results (
            session_id, session_uuid, q1_answer, q1_is_correct,
            q2_answer, q2_is_correct, q3_answer, q3_is_correct,
            total_questions, score, percentage, passed, time_taken_seconds, feedback
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session["id"],
        session_uuid,
        submission.q1_answer,
        result["q1_is_correct"],
        submission.q2_answer,
        result["q2_is_correct"],
        submission.q3_answer,
        result.get("q3_is_correct"),
        result["total_questions"],
        result["score"],
        result["percentage"],
        result["passed"],
        time_taken,
        result["feedback"]
    ))

    # Update session status to completed
    execute_db("""
        UPDATE sessions
        SET status = 'completed',
            current_step = 'completed',
            risk_rating = ?,
            completed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (final_risk, session["id"]))

    # Record QUIZ_SUBMITTED event
    execute_db("""
        INSERT INTO interaction_events (
            session_id, session_uuid, event_type, stage, target_element, metadata_json
        ) VALUES (?, ?, 'QUIZ_SUBMITTED', 'quiz', 'submit_button', ?)
    """, (session["id"], session_uuid, json.dumps({
        "score": result["score"],
        "percentage": result["percentage"],
        "passed": result["passed"],
        "risk_rating": final_risk
    })))

    return jsonify({
        "success": True,
        "session_uuid": session_uuid,
        "score": result["score"],
        "total_questions": result["total_questions"],
        "percentage": result["percentage"],
        "passed": bool(result["passed"]),
        "risk_rating": final_risk,
        "feedback": result["feedback"]
    }), 200


@app.route("/api/quiz/results/<session_uuid>", methods=["GET"])
@admin_required
def get_quiz_result(session_uuid):
    """Fetches stored quiz evaluation for a session."""
    row = query_db("SELECT * FROM quiz_results WHERE session_uuid = ?", (session_uuid,), one=True)
    if not row:
        return jsonify({"success": False, "error": "No quiz result recorded for this session"}), 404
    return jsonify({"success": True, "quiz_result": row}), 200


# ============================================================================
# 4. Cybersecurity Analytics & Vulnerability Reporting
# ============================================================================

@app.route("/api/analytics/summary", methods=["GET"])
@admin_required
def get_analytics_summary():
    """Aggregates security telemetry, vulnerability rates, and quiz pass rates."""
    total_sessions = query_db("SELECT COUNT(*) as count FROM sessions", one=True)["count"]
    completed_sessions = query_db("SELECT COUNT(*) as count FROM sessions WHERE status = 'completed'", one=True)["count"]
    
    # Vulnerability metrics
    compromised_count = query_db("SELECT COUNT(*) as count FROM sessions WHERE compromised_status = 1", one=True)["count"]
    reported_phish_count = query_db("""
        SELECT COUNT(DISTINCT session_id) as count 
        FROM interaction_events 
        WHERE event_type = 'REPORT_PHISH_CLICKED'
    """, one=True)["count"]

    # Quiz metrics
    quiz_totals = query_db("""
        SELECT 
            COUNT(*) as attempts,
            SUM(passed) as passed_count,
            AVG(percentage) as avg_score,
            AVG(time_taken_seconds) as avg_time
        FROM quiz_results
    """, one=True)

    quiz_attempts = quiz_totals["attempts"] or 0
    quiz_passed = quiz_totals["passed_count"] or 0
    avg_score = round(quiz_totals["avg_score"] or 0.0, 1)
    pass_rate = round((quiz_passed / quiz_attempts * 100), 1) if quiz_attempts > 0 else 0.0
    compromise_rate = round((compromised_count / total_sessions * 100), 1) if total_sessions > 0 else 0.0

    # Risk distribution
    risk_rows = query_db("""
        SELECT risk_rating, COUNT(*) as count 
        FROM sessions 
        GROUP BY risk_rating
    """)
    risk_distribution = {r["risk_rating"]: r["count"] for r in risk_rows}

    # Top interaction events
    event_counts = query_db("""
        SELECT event_type, COUNT(*) as count 
        FROM interaction_events 
        GROUP BY event_type 
        ORDER BY count DESC 
        LIMIT 10
    """)

    return jsonify({
        "success": True,
        "metrics": {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "compromised_sessions": compromised_count,
            "compromise_rate_percent": compromise_rate,
            "phish_reported_count": reported_phish_count,
            "quiz_attempts": quiz_attempts,
            "quiz_pass_rate_percent": pass_rate,
            "average_quiz_score_percent": avg_score,
            "risk_distribution": risk_distribution,
            "event_frequency": event_counts
        }
    }), 200


# ============================================================================
# 5. Database Management & Inspection
# ============================================================================

@app.route("/api/db/tables", methods=["GET"])
@admin_required
def get_db_tables():
    """Inspects SQLite database tables, column schemas, and row counts."""
    tables = ["sessions", "interaction_events", "quiz_results"]
    result = {}
    for table in tables:
        count = query_db(f"SELECT COUNT(*) as count FROM {table}", one=True)["count"]
        sample = query_db(f"SELECT * FROM {table} ORDER BY id DESC LIMIT 5")
        schema_info = query_db(f"PRAGMA table_info({table})")
        result[table] = {
            "row_count": count,
            "columns": [{"name": col["name"], "type": col["type"]} for col in schema_info],
            "recent_rows": sample
        }
    return jsonify({"success": True, "database": "phishing_simulation.db", "tables": result}), 200


@app.route("/api/db/seed", methods=["POST"])
@admin_required
def seed_database():
    """Seeds benchmark cybersecurity simulation sessions and events."""
    from seed import run_seed
    seeded_count = run_seed()
    return jsonify({
        "success": True,
        "message": f"Database populated with {seeded_count} benchmark training cohorts."
    }), 200


@app.route("/api/db/export", methods=["GET"])
@admin_required
def export_database():
    """Exports full database records as JSON."""
    return jsonify({
        "exported_at": datetime.utcnow().isoformat(),
        "sessions": query_db("SELECT * FROM sessions"),
        "interaction_events": query_db("SELECT * FROM interaction_events"),
        "quiz_results": query_db("SELECT * FROM quiz_results")
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
