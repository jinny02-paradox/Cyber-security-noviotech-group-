"""
Database Seeding Script for PhishShield Phishing Awareness Simulation.
Populates realistic benchmark cohorts, telemetry events, and quiz evaluations.
"""

import os
import json
import uuid
from datetime import datetime, timedelta
import random

from database import init_db, get_db_connection, execute_db

def run_seed():
    init_db()
    conn = get_db_connection()
    cur = conn.cursor()

    # Clear existing demo data
    cur.execute("DELETE FROM quiz_results;")
    cur.execute("DELETE FROM interaction_events;")
    cur.execute("DELETE FROM sessions;")
    conn.commit()

    departments = ["Finance & Accounting", "Software Engineering", "Human Resources", "Legal & Compliance", "Sales & Marketing", "Customer Operations"]
    cohorts = [
        # (id_suffix, dept, clicked_link, entered_creds, reported_phish, q1_ans, q2_ans, q1_ok, q2_ok, risk)
        ("101", "Finance & Accounting", False, False, True, "Never share the OTP", "Verify the URL", 1, 1, "low"),
        ("102", "Human Resources", True, True, False, "Share the OTP", "Click immediately", 0, 0, "critical"),
        ("103", "Software Engineering", False, False, True, "Never share the OTP", "Verify the URL", 1, 1, "low"),
        ("104", "Sales & Marketing", True, False, False, "Never share the OTP", "Verify the URL", 1, 1, "medium"),
        ("105", "Customer Operations", True, True, False, "Never share the OTP", "Click immediately", 1, 0, "high"),
        ("106", "Legal & Compliance", False, False, True, "Never share the OTP", "Verify the URL", 1, 1, "low"),
        ("107", "Finance & Accounting", True, True, False, "Share the OTP", "Verify the URL", 0, 1, "high"),
        ("108", "Human Resources", True, False, False, "Never share the OTP", "Verify the URL", 1, 1, "medium"),
        ("109", "Software Engineering", False, False, True, "Never share the OTP", "Verify the URL", 1, 1, "low"),
        ("110", "Sales & Marketing", True, True, False, "Share the OTP", "Click immediately", 0, 0, "critical"),
        ("111", "Customer Operations", False, False, False, "Never share the OTP", "Verify the URL", 1, 1, "low"),
        ("112", "Legal & Compliance", False, False, True, "Never share the OTP", "Verify the URL", 1, 1, "low")
    ]

    base_time = datetime.utcnow() - timedelta(days=2)
    session_count = 0

    for idx, (suffix, dept, clicked, creds, reported, q1_val, q2_val, q1_ok, q2_ok, risk) in enumerate(cohorts):
        s_uuid = f"bench-{suffix}-{uuid.uuid4().hex[:8]}"
        p_id = f"emp_{suffix}_{dept[:3].lower()}"
        start_ts = base_time + timedelta(hours=idx * 3, minutes=random.randint(5, 45))
        end_ts = start_ts + timedelta(minutes=random.randint(4, 12))

        cur.execute("""
            INSERT INTO sessions (
                session_uuid, participant_id, department, ip_address, 
                user_agent, current_step, status, risk_rating, compromised_status,
                started_at, completed_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'completed', 'completed', ?, ?, ?, ?, ?, ?)
        """, (
            s_uuid, p_id, dept, f"192.168.1.{10 + idx}",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
            risk, 1 if (clicked or creds) else 0,
            start_ts.isoformat(), end_ts.isoformat(),
            start_ts.isoformat(), end_ts.isoformat()
        ))
        sess_id = cur.lastrowid
        session_count += 1

        # Seed timeline events
        events_timeline = [
            ("SESSION_START", "intro", "start_button", random.randint(2000, 5000), {"step": "intro"}),
            ("EMAIL_OPENED", "email_simulation", "inbox_row", random.randint(3000, 8000), {"subject": "URGENT: Mandatory Password Expiration"}),
            ("SUSPICIOUS_LINK_HOVERED", "email_simulation", "auth_link", random.randint(1200, 3500), {"target_url": "http://secure-internal-auth.net/portal/login"})
        ]

        if reported:
            events_timeline.append(("REPORT_PHISH_CLICKED", "email_simulation", "report_security_button", random.randint(2000, 4000), {"action": "phishing_flagged"}))
        elif clicked:
            events_timeline.append(("SUSPICIOUS_LINK_CLICKED", "email_simulation", "auth_link", random.randint(1500, 3000), {"warning": "link_traversed"}))
            events_timeline.append(("LOGIN_PAGE_VIEWED", "login_trap", "login_form", random.randint(2000, 6000), {"domain": "fake-auth-portal.com"}))
            if creds:
                events_timeline.append(("CREDENTIAL_ATTEMPTED", "login_trap", "submit_button", random.randint(3000, 7000), {"input_length": 12, "captured": False}))
                events_timeline.append(("AWARENESS_ALERT_TRIGGERED", "login_trap", "alert_banner", random.randint(2500, 5000), {"message": "Never enter password on unverified portal"}))

        events_timeline.append(("LESSON_ACCESSED", "awareness_lesson", "lesson_container", random.randint(8000, 22000), {"rules_reviewed": 5}))
        events_timeline.append(("QUIZ_STARTED", "quiz", "quiz_card", random.randint(2000, 4000), {}))
        events_timeline.append(("QUIZ_SUBMITTED", "quiz", "submit_button", random.randint(5000, 15000), {"score": q1_ok + q2_ok}))

        event_time = start_ts
        for ev_type, stage, elem, dwell, meta in events_timeline:
            event_time += timedelta(milliseconds=dwell + 500)
            cur.execute("""
                INSERT INTO interaction_events (
                    session_id, session_uuid, event_type, stage, target_element, dwell_time_ms, metadata_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (sess_id, s_uuid, ev_type, stage, elem, dwell, json.dumps(meta), event_time.isoformat()))

        # Seed quiz result
        score = q1_ok + q2_ok
        pct = (score / 2.0) * 100.0
        passed = 1 if pct >= 80.0 else 0
        fb = "Demonstrated strong password hygiene." if passed else "Needs refresher on phishing red flags and OTP secrecy."

        cur.execute("""
            INSERT INTO quiz_results (
                session_id, session_uuid, q1_answer, q1_is_correct,
                q2_answer, q2_is_correct, total_questions, score, percentage,
                passed, time_taken_seconds, feedback, submitted_at
            ) VALUES (?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?)
        """, (
            sess_id, s_uuid, q1_val, q1_ok, q2_val, q2_ok, score, pct, passed,
            random.randint(25, 80), fb, end_ts.isoformat()
        ))

    conn.commit()
    conn.close()
    return session_count

if __name__ == "__main__":
    count = run_seed()
    print(f"Successfully seeded {count} benchmark simulation sessions with events and quiz evaluations.")
