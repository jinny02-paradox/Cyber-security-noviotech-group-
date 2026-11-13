# PhishShield Backend (Flask + SQLite)

A production-grade Python Flask backend for phishing awareness simulations, interaction telemetry tracking, database management, and quiz assessment scoring.

## Architecture

- **Web Framework**: Flask 3.0 with Flask-CORS
- **Database Engine**: SQLite 3 with WAL mode, foreign keys, and indexes (`phishing_simulation.db`)
- **Key Modules**:
  - `app.py`: REST API routing, request validation, CORS, error handling
  - `database.py`: SQLite connection lifecycle, transaction queries, and schema migration
  - `models.py`: Data models, response evaluation, and cybersecurity risk scoring
  - `schema.sql`: Full DDL for `sessions`, `interaction_events`, and `quiz_results`
  - `seed.py`: Benchmark data generator for cohort analytics

---

## Quickstart (Local Python Execution)

1. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Initialize and seed the database**:
   ```bash
   python backend/seed.py
   ```

4. **Start the Flask server**:
   ```bash
   python backend/app.py
   # Or using flask CLI:
   export FLASK_APP=backend/app.py
   flask run --port=5000
   ```

Server will be running at `http://localhost:5000`.

---

## API Endpoints Reference

### 1. Simulation Session Management
- `POST /api/sessions/start`
  - Body: `{"participant_id": "alice@company.com", "department": "Finance"}`
  - Returns: `{"session_uuid": "...", "status": "in_progress", "current_step": "intro"}`
- `GET /api/sessions/<session_uuid>`
  - Returns full session data, logged event stream, and quiz results.
- `PATCH /api/sessions/<session_uuid>/step`
  - Body: `{"step": "email_simulation"}`
- `GET /api/sessions`
  - Query params: `?limit=50&status=completed`

### 2. Interaction Telemetry & Event Storage
- `POST /api/events`
  - Body:
    ```json
    {
      "session_uuid": "...",
      "event_type": "SUSPICIOUS_LINK_CLICKED",
      "stage": "email_simulation",
      "target_element": "password_reset_button",
      "dwell_time_ms": 3200,
      "metadata": {"href": "http://evil-domain.com"}
    }
    ```
- `GET /api/events`
  - Query params: `?session_uuid=...&event_type=...&limit=100`

### 3. Quiz Result Storage & Assessment
- `POST /api/quiz/submit`
  - Body:
    ```json
    {
      "session_uuid": "...",
      "q1_answer": "Never share the OTP",
      "q2_answer": "Verify the URL",
      "time_taken_seconds": 45
    }
    ```
  - Evaluates score, marks session as `completed`, computes risk rating (`low`, `medium`, `high`, `critical`), and stores feedback.
- `GET /api/quiz/results/<session_uuid>`

### 4. Cohort Analytics & Database Inspection
- `GET /api/analytics/summary`: Aggregate compromise rate, quiz pass percentage, vulnerability breakdown.
- `GET /api/db/tables`: Inspect SQLite tables, column types, row counts, and sample records.
- `GET /api/db/export`: Export all tables as JSON.
- `POST /api/db/seed`: Seed benchmark cohort data.
