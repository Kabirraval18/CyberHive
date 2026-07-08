# Project Scope

## Overview

CyberHive AI is designed to capture, analyze, and visualize cyberattacks using a Cowrie SSH/Telnet Honeypot. The project focuses on collecting attack data, processing security logs, identifying attacker behavior, enriching attack information with external threat intelligence, and presenting the results through an interactive web dashboard.

The platform is intended for educational purposes, cybersecurity research, and small-scale security monitoring environments where administrators need a better understanding of attack activities without deploying complex enterprise security solutions.

---

## Scope of the Project

The project includes the following features:

### Honeypot Deployment

- Deploy and configure a Cowrie SSH/Telnet Honeypot.
- Capture real attack attempts from the internet.
- Generate structured JSON log files for every attack session.

---

### Log Collection and Processing

- Read and process Cowrie log files.
- Extract important information such as:
  - Attacker IP address
  - Username and password attempts
  - Session ID
  - Login status
  - Executed commands
  - Timestamp
- Store processed data in a SQLite database.

---

### Behavioral Analysis

- Analyze attacker behavior based on:
  - Number of failed login attempts
  - Commands executed
  - Session duration
  - Login frequency
  - Command patterns
- Group similar attack sessions using a lightweight machine learning algorithm.

---

### Threat Intelligence

- Retrieve reputation information for attacker IP addresses using external threat intelligence services.
- Display IP reputation, abuse reports, and geographical information alongside attack data.

---

### MITRE ATT&CK Mapping

- Analyze attacker commands and map them to relevant MITRE ATT&CK techniques.
- Help users understand the attacker's tactics instead of only viewing raw command history.

---

### Risk Scoring

- Calculate a risk score for every attack session.
- Generate risk levels such as Low, Medium, High, and Critical based on multiple factors.

---

### Security Recommendations

- Generate basic security recommendations based on detected attack patterns.
- Suggest actions such as blocking malicious IPs, disabling unused services, or enabling stronger authentication.

---

### Dashboard and Reports

The web dashboard will provide:

- Live attack monitoring
- Attack statistics
- Behavioral analysis
- Threat intelligence information
- MITRE ATT&CK mapping
- Alerts
- Reports
- Search and filtering options

---

## Project Limitations

The project has the following limitations:

- It focuses only on SSH and Telnet attacks captured by the Cowrie Honeypot.
- The platform does not actively block attackers or modify firewall rules.
- External threat intelligence depends on the availability and usage limits of free APIs.
- The behavioral analysis module is intended for educational purposes and is not designed to replace enterprise-grade Security Information and Event Management (SIEM) solutions.
- The system analyzes attacks only after they have been recorded by the honeypot.

---

## Out of Scope

The following features are not included in this project:

- Real-time malware analysis
- Full network intrusion detection
- Endpoint protection
- Firewall management
- Automated incident response
- Cloud security monitoring
- Multi-user role management
- Enterprise SIEM integration

These features may be considered as future enhancements.

---

## Future Scope

The project can be extended in the future by adding:

- Support for additional honeypots such as Dionaea and Honeytrap.
- AI-based attack prediction models.
- Real-time attack notifications through email or messaging platforms.
- Multi-user authentication and role-based access control.
- Cloud deployment using Docker and Kubernetes.
- Integration with SIEM platforms such as Splunk or Wazuh.
- Advanced machine learning models for attack classification.
- Support for multiple databases such as PostgreSQL or MySQL.
- Interactive network attack visualization.
- REST APIs for third-party security tools.
