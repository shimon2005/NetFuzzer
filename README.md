# NetFuzzer 🛡️

**NetFuzzer** is a powerful, modular network protocol fuzzing tool designed to detect vulnerabilities in network services. Built on top of the **Boofuzz** framework, it automates the process of stress-testing protocols like DNS and HTTP, providing detailed post-run analysis and visualization.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)

## 🚀 Key Features

* **Multi-Protocol Support:** Built-in fuzzing modules for **HTTP** and **DNS**.
* **Boofuzz Integration:** Leverages the industry-standard Boofuzz engine for state-aware fuzzing.
* **Automated Reporting:** Generates comprehensive HTML reports with graphs (failures by cause, top observations) to easily analyze crash data.
* **Containerized:** Fully dockerized environment for safe and isolated testing.
* **Live Monitoring:** Real-time statistics management during the fuzzing session.

## 🛠️ Technology Stack

* **Language:** Python 3
* **Fuzzing Engine:** Boofuzz
* **Packet Manipulation:** Scapy (implied usage for network interactions)
* **Infrastructure:** Docker & Docker Compose
* **Frontend/Reporting:** HTML/CSS Injection for visual logs

## 📂 Project Structure

```bash
NetFuzzer/
├── core/               # Core utilities and configuration
├── fuzzers/            # Protocol specific fuzzing scripts (DNS, HTTP)
├── analysis/           # Stats manager and data handling
├── frontend/           # Report generation logic
├── boofuzz-results/    # Database files from fuzzing runs
├── docker-compose.yml  # Container orchestration
└── main.py             # Entry point
