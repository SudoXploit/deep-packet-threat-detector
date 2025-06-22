# 🛡️ Deep Packet Threat Detector

> Passive DPI-based threat detection engine using Scapy + Wireshark

This project monitors HTTP, FTP, Telnet, and DNS traffic in real-time, identifying:
- Leaked credentials
- DNS tunneling attempts
- Other suspicious traffic patterns

## 📂 Project Structure

deep-packet-threat-detector/
├── sniffer/ # Python scripts for live sniffing
│ └── scapy_sniffer.py
├── captures/ # Saved PCAPs for Wireshark analysis
│ └── sample_capture.pcap
├── docs/ # Documentation + screenshots
│ ├── Project_Documentation.md
│ └── screenshots/
├── requirements.txt # Python dependencies
└── README.md # This file

---

## ⚙️ Features

- Real-time sniffing of HTTP, FTP, DNS, and Telnet
- Alerts on potential credential leaks
- DNS tunneling detection based on payload heuristics
- Export captured packets to PCAP for Wireshark analysis

---

## 🚀 Getting Started

### 🔹 Install Dependencies

```bash
pip install -r requirements.txt
