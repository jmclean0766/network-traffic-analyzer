# Network Traffic Analyzer

A Python-based network traffic analysis tool that processes PCAP files, extracts packet-level information, aggregates network communications, and identifies basic traffic patterns.

## Features

- Validates PCAP file input
- Extracts packet information using Scapy
- Identifies:
  - Source and destination IP addresses
  - TCP, UDP, ICMP, and non-IP traffic
  - Source and destination ports
  - Packet sizes
  - Packet timestamps
- Aggregates network communications between hosts
- Tracks:
  - Total packet counts
  - Protocol frequencies
  - Source and destination IP frequencies
  - Source and destination port frequencies
  - Communication packet counts
  - Total bytes exchanged
  - Communication duration
- Detects potential port asymmetry between communicating hosts
- Detects high-frequency traffic between host pairs
- Produces a terminal-based traffic analysis report

## Requirements

- Python 3
- Scapy

Install Scapy with:

```bash
pip install scapy
```

## Usage

```bash
python3 network_traffic_analyzer.py <pcap_file>
```

Example:

```bash
python3 network_traffic_analyzer.py sample.pcap
```

## How It Works

The analyzer processes the capture in several stages:

1. **Validation**  
   Checks that the specified file exists and can be read as a PCAP capture.

2. **Packet Extraction**  
   Reads packets from the capture and extracts relevant network information such as IP addresses, protocols, ports, packet size, and timestamps.

3. **Traffic Analysis**  
   Aggregates packet information to identify communication pairs, protocol distribution, port usage, packet counts, transferred bytes, and communication duration.

4. **Traffic Detection**  
   Examines the aggregated communications for:
   - **Port asymmetry:** differences in the number of observed ports between communicating hosts.
   - **High-frequency traffic:** host pairs generating multiple packets within a very short time period.

5. **Reporting**  
   Displays the resulting traffic statistics and findings in the terminal.

Scapy provides functionality for reading PCAP files and processing captured packets, including streaming packets through `PcapReader`.

## Output

The report contains three main sections:

### Network Traffic Summary

Displays:

- Total packets analyzed
- TCP packet count
- UDP packet count
- ICMP packet count
- Non-IP packet count

### Communication Analysis

For each observed communication, displays:

- Protocol
- Communicating endpoints
- Packet count
- Total bytes
- Communication duration

### Traffic Findings

Displays detected:

- Port-based asymmetry between hosts
- High-frequency traffic between host pairs

## Technologies

- Python 3
- Scapy
- PCAP
- TCP/IP networking
- Packet analysis
- Network traffic aggregation
- Dictionary-based data processing

## Project Purpose

This project was built to develop practical skills in:

- Network traffic analysis
- Packet parsing
- PCAP processing
- Network protocol identification
- Data aggregation
- Traffic-pattern detection
- Python data structures
- Security-oriented automation

The project is intended as an educational cybersecurity tool for analyzing authorized network traffic.