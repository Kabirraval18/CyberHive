# User Requirements

## Introduction

This document describes the requirements of the users who will interact with CyberHive AI. It identifies the intended users of the system, the functions they should be able to perform, and the minimum hardware and software required to run the application.

---

# Intended Users

CyberHive AI is designed for users who need to monitor and analyze cyberattack activities in a simple and organized manner.

The primary users of the system include:

- Cybersecurity students
- Faculty members conducting cybersecurity demonstrations
- Security researchers
- Small organizations
- System administrators
- Anyone interested in learning about honeypots and threat intelligence

---

# User Roles

## Administrator

The Administrator is the primary user of the system.

The administrator can:

- Login securely to the dashboard.
- View live attack statistics.
- View attacker details.
- Search and filter attack records.
- Monitor behavioral analysis.
- View MITRE ATT&CK mappings.
- View threat intelligence information.
- Generate PDF reports.
- Review alerts and recommendations.

Currently, the system supports only one administrator account.

---

# Functional Requirements for Users

The user should be able to:

- Login to the application.
- View the dashboard.
- Monitor captured attacks.
- Search attack records.
- Filter attacks based on different criteria.
- View behavioral clusters.
- View attacker IP reputation.
- View calculated risk scores.
- Download reports.
- Logout securely.

---

# Hardware Requirements

## Minimum Requirements

| Component | Specification |
|----------|---------------|
| Processor | Intel Core i3 or equivalent |
| RAM | 4 GB |
| Storage | 30 GB free space |
| Internet | Required for API access |
| Virtualization | Oracle VirtualBox |

---

## Recommended Requirements

| Component | Specification |
|----------|---------------|
| Processor | Intel Core i5 or higher |
| RAM | 8 GB or more |
| Storage | 60 GB or more |
| Internet | Stable broadband connection |

---

# Software Requirements

The project requires the following software.

| Software | Purpose |
|----------|---------|
| Kali Linux | Development environment |
| Python 3.x | Backend development |
| Flask | Web framework |
| SQLite | Database |
| Cowrie Honeypot | Attack data collection |
| Git | Version control |
| GitHub | Repository hosting |
| Visual Studio Code | Code editor |
| Oracle VirtualBox | Virtual machine |

---

# Browser Requirements

The dashboard should work correctly on modern web browsers including:

- Google Chrome
- Microsoft Edge
- Mozilla Firefox

---

# Network Requirements

The system requires:

- Internet connection for threat intelligence API requests.
- Localhost communication between Flask and SQLite.
- Internet connectivity for receiving attacks on the honeypot during testing.

---

# User Permissions

The administrator is allowed to:

- Access the dashboard.
- View all attack logs.
- View behavioral analysis.
- View MITRE ATT&CK mappings.
- View threat intelligence information.
- Generate reports.

The administrator cannot:

- Modify raw attack logs.
- Delete attack records directly from the dashboard.
- Change database structure.

---

# Assumptions

The following assumptions are made during development:

- Cowrie Honeypot is properly configured.
- SQLite database is accessible.
- The system has internet access for API requests.
- The administrator has basic knowledge of cybersecurity concepts.
- The application is deployed in a secure environment.

---

# Summary

CyberHive AI is designed to be simple to use while providing meaningful cybersecurity insights. The system requires only commonly available hardware and free software, making it suitable for educational institutions, students, and small organizations interested in understanding cyberattacks through honeypot data.
