"""
Data models and security evaluation logic for PhishShield.
Provides serialization, answer validation, and cybersecurity risk scoring.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
import uuid
import json
from datetime import datetime


@dataclass
class SimulationSession:
    id: Optional[int]
    session_uuid: str
    participant_id: str
    department: str = "General"
    ip_address: str = "127.0.0.1"
    user_agent: str = "Unknown Browser"
    current_step: str = "intro"
    status: str = "in_progress"
    risk_rating: str = "unassessed"
    compromised_status: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    @classmethod
    def create_new(cls, participant_id: str, department: str = "General", ip: str = "127.0.0.1", user_agent: str = ""):
        return cls(
            id=None,
            session_uuid=str(uuid.uuid4()),
            participant_id=participant_id,
            department=department,
            ip_address=ip,
            user_agent=user_agent,
            current_step="intro",
            status="in_progress",
            risk_rating="unassessed",
            compromised_status=0,
            started_at=datetime.utcnow().isoformat()
        )


@dataclass
class InteractionEvent:
    id: Optional[int]
    session_id: int
    session_uuid: str
    event_type: str
    stage: str
    target_element: Optional[str] = None
    dwell_time_ms: int = 0
    metadata_json: str = "{}"
    timestamp: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], session_id: int, session_uuid: str):
        metadata = data.get("metadata", {})
        if isinstance(metadata, dict):
            meta_str = json.dumps(metadata)
        else:
            meta_str = str(metadata)

        return cls(
            id=None,
            session_id=session_id,
            session_uuid=session_uuid,
            event_type=data.get("event_type", "GENERIC_EVENT"),
            stage=data.get("stage", "simulation"),
            target_element=data.get("target_element"),
            dwell_time_ms=int(data.get("dwell_time_ms", 0)),
            metadata_json=meta_str
        )


@dataclass
class QuizSubmission:
    q1_answer: str
    q2_answer: str
    q3_answer: Optional[str] = None
    time_taken_seconds: int = 0

    def evaluate(self) -> Dict[str, Any]:
        """Evaluates quiz responses and generates educational score."""
        q1_correct = (self.q1_answer.strip().lower() in ["never share the otp", "correct", "never_share"])
        q2_correct = (self.q2_answer.strip().lower() in ["verify the url", "correct", "verify_url"])
        
        has_q3 = self.q3_answer is not None
        q3_correct = False
        total_questions = 2
        score = 0

        if q1_correct:
            score += 1
        if q2_correct:
            score += 1

        if has_q3:
            total_questions = 3
            q3_correct = (self.q3_answer.strip().lower() in ["artificial urgency / threats", "urgency", "correct"])
            if q3_correct:
                score += 1

        percentage = round((score / total_questions) * 100, 1)
        passed = 1 if percentage >= 80.0 else 0

        feedback = []
        if not q1_correct:
            feedback.append("Never disclose One-Time Passwords (OTPs) under any circumstance. Legitimate security teams never ask for your OTP.")
        else:
            feedback.append("Great job recognizing that OTPs must remain strictly confidential.")

        if not q2_correct:
            feedback.append("Always verify the full sender domain and URL destination before clicking unfamiliar links.")
        else:
            feedback.append("Excellent habit of verifying website URLs before interacting with links.")

        return {
            "q1_is_correct": 1 if q1_correct else 0,
            "q2_is_correct": 1 if q2_correct else 0,
            "q3_is_correct": 1 if q3_correct else 0 if has_q3 else None,
            "total_questions": total_questions,
            "score": score,
            "percentage": percentage,
            "passed": passed,
            "feedback": " ".join(feedback)
        }


def calculate_risk_rating(compromised_status: int, quiz_passed: int, reported_phish: bool) -> str:
    """
    Determines overall user cybersecurity vulnerability profile:
    - Low: Did not compromise credentials + passed quiz (or reported phishing)
    - Medium: Clicked link but did not attempt credentials + passed quiz
    - High: Attempted credentials or failed quiz
    - Critical: Attempted credentials AND failed quiz
    """
    if compromised_status == 1 and quiz_passed == 0:
        return "critical"
    elif compromised_status == 1 and quiz_passed == 1:
        return "high"
    elif compromised_status == 0 and quiz_passed == 0:
        return "medium"
    elif reported_phish:
        return "low"
    else:
        return "low"
