# Technology Stack

## Introduction

CyberHive AI is built using open-source technologies that are widely used in cybersecurity and software development. The selected technologies provide a balance between performance, simplicity, and ease of development while remaining suitable for a semester-long academic project.

---

# Technology Overview

| Technology | Purpose |
|------------|---------|
| Kali Linux | Development and cybersecurity environment |
| Cowrie Honeypot | Capture SSH and Telnet attacks |
| Python | Backend development and log processing |
| Flask | Web application framework |
| SQLite | Database management |
| HTML | Dashboard structure |
| CSS | User interface styling |
| JavaScript | Interactive dashboard functionality |
| Chart.js | Data visualization |
| Git & GitHub | Version control and collaboration |
| VS Code | Code editor |

---

# Technology Details

## 1. Kali Linux

### Purpose

Kali Linux is used as the primary development environment because it includes many cybersecurity tools and provides excellent support for penetration testing and honeypot deployment.

### Why It Was Chosen

- Built for cybersecurity professionals.
- Excellent compatibility with Cowrie.
- Easy access to networking and security tools.
- Suitable for testing attack scenarios.

---

## 2. Cowrie Honeypot

### Purpose

Cowrie acts as a fake SSH and Telnet server that attracts attackers and records their activities.

### Why It Was Chosen

- Open source.
- Well-documented.
- Generates structured JSON logs.
- Widely used for cybersecurity research.
- Easy integration with Python.

---

## 3. Python

### Purpose

Python is used to build the backend of the application.

### Responsibilities

- Parse Cowrie logs.
- Process attack data.
- Calculate risk scores.
- Perform behavioral analysis.
- Connect with threat intelligence APIs.
- Generate reports.

### Why It Was Chosen

- Easy to learn and develop.
- Rich ecosystem of libraries.
- Excellent support for cybersecurity projects.
- Strong community support.

---

## 4. Flask

### Purpose

Flask is used to develop the web application and provide the dashboard interface.

### Responsibilities

- Display attack statistics.
- Serve web pages.
- Connect frontend with backend.
- Handle administrator login.

### Why It Was Chosen

- Lightweight.
- Simple to understand.
- Ideal for small and medium-sized projects.
- Easy integration with Python.

---

## 5. SQLite

### Purpose

SQLite stores processed attack information and analysis results.

### Why It Was Chosen

- No separate database server required.
- Easy setup.
- Lightweight.
- Suitable for academic projects.
- Works well with Flask.

---

## 6. HTML

### Purpose

Provides the structure of the web dashboard.

### Responsibilities

- Dashboard pages.
- Login page.
- Reports.
- Attack tables.

---

## 7. CSS

### Purpose

Designs the appearance of the dashboard.

### Responsibilities

- Layout.
- Colors.
- Responsive design.
- User interface improvements.

---

## 8. JavaScript

### Purpose

Adds interactivity to the dashboard.

### Responsibilities

- Dynamic updates.
- Search.
- Filtering.
- Table interaction.

---

## 9. Chart.js

### Purpose

Displays attack statistics using graphs.

### Planned Charts

- Attack timeline.
- Risk distribution.
- Country-wise attacks.
- Behavioral clusters.
- Attack categories.

### Why It Was Chosen

- Lightweight.
- Easy integration with Flask.
- Responsive charts.
- Open source.

---

## 10. Git and GitHub

### Purpose

Manage project versions and collaboration between team members.

### Responsibilities

- Source code management.
- Version history.
- Team collaboration.
- Backup.

---

## 11. Visual Studio Code

### Purpose

Primary code editor used for development.

### Why It Was Chosen

- Lightweight.
- Excellent Python support.
- Integrated Git.
- Large extension library.

---

# Python Libraries

The following Python libraries will be used during development.

| Library | Purpose |
|----------|---------|
| Flask | Web framework |
| Pandas | Data processing |
| SQLite3 | Database connectivity |
| Requests | API communication |
| Scikit-learn | Behavioral clustering |
| ReportLab | PDF report generation |
| python-dotenv | Environment variable management |
| GeoIP2 (Optional) | IP location lookup |

---

# External Services

The project will use the following external services:

| Service | Purpose |
|----------|---------|
| AbuseIPDB API | IP reputation lookup |
| MITRE ATT&CK Framework | Attack technique mapping |

---

# Development Tools

| Tool | Purpose |
|------|---------|
| Oracle VirtualBox | Virtual machine |
| Git | Version control |
| GitHub | Repository hosting |
| VS Code | Development |
| Kali Linux Terminal | Command-line operations |

---

# Summary

The selected technology stack provides a practical and reliable foundation for developing CyberHive AI. All chosen technologies are open source, well-documented, and widely used within the cybersecurity community. This makes the project easier to develop, maintain, and extend while ensuring that it remains suitable for both academic evaluation and real-world learning.
