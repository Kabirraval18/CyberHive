# Non-Functional Requirements

## Introduction

Non-functional requirements define the quality standards and operational characteristics of CyberHive AI. These requirements ensure that the system is secure, reliable, efficient, and easy to use while meeting the needs of its intended users.

---

# NFR-01: Performance

### Requirement

The system should process attack logs efficiently and display updated information on the dashboard without noticeable delay.

### Expected Outcome

- Process new log entries within a few seconds.
- Display dashboard data quickly.
- Support smooth navigation between dashboard pages.

---

# NFR-02: Reliability

### Requirement

The system should continue operating even if individual attack sessions contain incomplete or unexpected data.

### Expected Outcome

- Handle invalid log entries without crashing.
- Continue processing remaining log files.
- Prevent data corruption in the database.

---

# NFR-03: Security

### Requirement

The platform should protect sensitive information and prevent unauthorized access.

### Expected Outcome

- Administrator login should require authentication.
- Passwords should be stored securely using hashing.
- API keys should not be stored directly in source code.
- User input should be validated before processing.

---

# NFR-04: Usability

### Requirement

The dashboard should be simple to understand and easy to navigate.

### Expected Outcome

- Clean and modern interface.
- Easy-to-read charts and tables.
- Simple navigation menu.
- Important alerts should be clearly visible.

---

# NFR-05: Maintainability

### Requirement

The project should be organized so that future modifications can be made easily.

### Expected Outcome

- Modular project structure.
- Well-commented source code.
- Separate backend, frontend, and database modules.
- Clear project documentation.

---

# NFR-06: Scalability

### Requirement

The system should allow future enhancements without major changes to the existing architecture.

### Expected Outcome

Future versions should support:

- Additional honeypots
- Multiple databases
- Additional threat intelligence APIs
- More attack detection techniques
- Multi-user support

---

# NFR-07: Availability

### Requirement

The application should be available whenever the administrator needs to monitor attacks.

### Expected Outcome

- Stable execution during demonstrations.
- Recover gracefully after unexpected errors.
- Restart without losing stored attack data.

---

# NFR-08: Compatibility

### Requirement

The platform should run on commonly used development environments.

### Expected Outcome

- Kali Linux development environment.
- Python 3.x compatibility.
- Modern web browsers for dashboard access.
- SQLite database support.

---

# NFR-09: Portability

### Requirement

The project should be easy to move between different systems.

### Expected Outcome

- Source code managed using GitHub.
- Dependencies listed in requirements.txt.
- Easy installation using virtual environments.
- Simple project setup instructions.

---

# NFR-10: Documentation

### Requirement

The project should include complete technical documentation.

### Documentation Includes

- Software Requirements Specification (SRS)
- System Design
- Database Design
- API Documentation
- Installation Guide
- User Manual
- Testing Report
- Final Project Report

---

# NFR-11: Accuracy

### Requirement

The system should provide meaningful and consistent analysis of captured attack data.

### Expected Outcome

- Correct parsing of Cowrie logs.
- Consistent risk score calculation.
- Accurate MITRE ATT&CK mapping.
- Reliable behavioral clustering.
- Correct threat intelligence enrichment.

---

# NFR-12: Extensibility

### Requirement

The project should be designed so that new features can be added with minimal changes.

### Future Expansion

The architecture should support:

- AI-based threat prediction
- Additional machine learning models
- Real-time notifications
- Docker deployment
- Cloud hosting
- Integration with enterprise SIEM solutions
