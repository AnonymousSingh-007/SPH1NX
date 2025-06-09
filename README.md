# SPH1NX

SPH1NX: A Python-based network scan detector for TCP Null/UDP scans with JARVIS-like voice alerts for critical ports (FTP, Telnet, etc.) and a real-time UI dashboard. Powered by Scapy for cybersecurity enthusiasts!

## How SPH1NX Works
SPH1NX is a powerful network security tool designed to detect and alert on malicious TCP Null and UDP scans:
- **Scan Detection**: Uses Scapy to sniff packets, identifying TCP Null scans (zero flags) and UDP scans (UDP packets or ICMP port-unreachable responses).
- **Voice Alerts**: Emits audio alerts via `pyttsx3` for scans targeting critical ports (e.g., 21/FTP, 23/Telnet, 445/SMB) or high-frequency scans (>10 packets in 5 seconds).
- **Real-Time UI**: Streams scan alerts to a web dashboard, displaying logs like “TCP NULL SCAN detected from 192.168.1.x.”
- **Logging**: Saves all detections to `scan_detection.log` for forensic analysis.

Perfect for cybersecurity enthusiasts, SPH1NX combines raw power with a sleek interface, making it ideal for monitoring networks or testing with Nmap.


File Descriptions

app.py: Server that runs the backend, streaming Tool_Code.py logs to the UI via WebSockets.
index.html: Front-end dashboard that connects to app.py, triggers SPH1NX, and displays real-time scan alerts.
Tool_Code.py: Core script using Scapy to detect TCP Null/UDP scans, with voice alerts and logging.

Sample Detection Log
From scan_detection.log:
2025-06-09 10:30:00,123 - INFO - Logging setup complete.
2025-06-09 10:30:05,456 - INFO - TCP NULL SCAN detected from 192.168.1.100 on port 21
2025-06-09 10:30:10,789 - INFO - UDP SCAN detected from 192.168.1.100 on port 445

Contributing
Got ideas to make SPH1NX even more badass? Fork the repo, add features (e.g., new scan types, enhanced UI), and submit a pull request!


Built with 💾 and ☕ by Samratth Singh. Hack the planet!```

