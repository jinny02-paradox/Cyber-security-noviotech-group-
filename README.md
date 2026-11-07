# Phishing Awareness Simulation Using Social Engineering Techniques

## 1. Project Introduction

Phishing is one of the most common cybersecurity threats. Attackers use social engineering techniques such as urgency, fear, and fake account notifications to trick users into sharing sensitive information.

The **Phishing Awareness Simulation Using Social Engineering Techniques** project is an educational platform designed to demonstrate how phishing attacks work in a safe and controlled environment.

The system simulates a phishing email, provides a harmless demonstration webpage, educates users about phishing prevention, and evaluates their awareness through a quiz. An admin dashboard helps analyze participant interactions and quiz results.

## 2. Problem Statement

Phishing attacks exploit human psychology to obtain sensitive information. Many users cannot identify suspicious emails, fake websites, and malicious links.

This project aims to create a controlled phishing awareness simulation to understand user behaviour, improve cybersecurity awareness, and recommend preventive measures.

## 3. Project Objectives

- Understand common phishing and social engineering techniques.
- Design realistic but harmless simulated phishing emails.
- Demonstrate phishing scenarios using a safe webpage.
- Measure participant awareness through permitted interaction tracking.
- Conduct an awareness quiz.
- Analyze quiz performance and simulation statistics.
- Recommend effective phishing prevention practices.

## 4. Main Features

### Participant Module
- Home page
- Simulated phishing email
- Harmless login demonstration page
- Phishing awareness lessons
- Interactive awareness quiz
- Quiz score and feedback

### Backend Module
- Flask-based backend
- API integration
- Database management
- Simulation session management
- Interaction event storage
- Quiz result storage

### Simulation Tracking Module
- Email viewed tracking
- Demonstration link click tracking
- Quiz completion tracking
- Consent-based event collection

### Admin Dashboard
- Total participant sessions
- Email interaction statistics
- Demonstration link click statistics
- Quiz attempts
- Average quiz scores
- Awareness analysis and recommendations

## 5. Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, Flask |
| Database | As configured in the backend |
| API Communication | HTTP / REST API |
| Development Environment | Visual Studio Code |
| Version Control | Git and GitHub |

## 6. Project Workflow

1. Participant opens the project website.
2. Participant starts the awareness simulation.
3. A simulated phishing email is displayed.
4. Participant clicks the demonstration link.
5. A harmless login demonstration page is displayed.
6. The backend records permitted interaction events.
7. Participant views phishing awareness lessons.
8. Participant completes the awareness quiz.
9. Quiz results are validated and stored.
10. Admin views aggregate statistics and awareness results.

## 7. Team Responsibilities

| Team Member | Responsibility |
|---|---|
| Member 1 | Frontend development using HTML, CSS and JavaScript |
| Member 2 | Backend development using Python and Flask |
| Member 3 | Simulation tracking and quiz result integration |
| Member 4 | Admin dashboard, analytics and result presentation |

## 8. Frontend Project Structure

```text
Phishing-Awareness-Simulation/
│
├── frontend/
│   ├── index.html
│   ├── email.html
│   ├── simulation.html
│   ├── awareness.html
│   ├── quiz.html
│   │
│   └── css/
│       └── style.css
│
├── backend/
│   └── Backend files
│
├── README.md
└── requirements.txt
```

Note: The backend folder structure should be updated according to the actual Flask implementation.

## 9. Installation and Execution

### Prerequisites
- Python installed
- Visual Studio Code
- Git
- Modern web browser

### Frontend Execution

1. Clone or download the project repository.
2. Open the project folder in Visual Studio Code.
3. Open the `frontend` folder.
4. Run `index.html` using the Live Server extension.
5. Navigate through the simulation pages.

### Backend Execution

Follow the setup instructions provided by the backend developer.

A typical Flask setup may use:

```bash
python -m venv venv
```

Activate the environment on Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the Flask application using the actual entry-point filename and instructions provided by the backend developer.

## 10. Privacy and Ethical Considerations

This project is developed strictly for educational and cybersecurity awareness purposes.

- Obtain participant consent before conducting simulations and tracking interactions.
- Do not collect real passwords, OTPs or sensitive credentials.
- Use harmless demonstration pages.
- Collect only the minimum information required.
- Protect participant data.
- Restrict admin dashboard access to authorized users.
- Use the simulation only in an approved and controlled environment.

## 11. Expected Results

The project is expected to:

- Demonstrate how social engineering techniques influence users.
- Help users recognize suspicious emails and links.
- Measure phishing awareness through quiz performance.
- Present simulation statistics through an admin dashboard.
- Improve cybersecurity awareness through preventive recommendations.

## 12. Future Scope

- More phishing email scenarios.
- Advanced awareness quizzes.
- Additional phishing detection techniques.
- Detailed analytics and reporting.
- Multi-language awareness lessons.
- Automated cybersecurity awareness training.

## 13. Conclusion

The Phishing Awareness Simulation project provides a practical approach to understanding phishing attacks and social engineering techniques. By combining simulated emails, a harmless demonstration webpage, awareness lessons, quizzes, and an admin dashboard, the system helps users understand phishing risks and adopt safer online practices.

---

**Project Title:** Phishing Awareness Simulation Using Social Engineering Techniques

**Project Type:** Major Project – Cyber Security

**Development Approach:** Team-Based Development
