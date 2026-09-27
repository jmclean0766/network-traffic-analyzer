#Network Traffic Analyzer Project

import sys
import scapy.all
import scapy.utils
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pathlib


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: <program> <pcap_file>")

    traffic_file = sys.argv[1]
    valid_pcap = validate(traffic_file)
    packets = extract(valid_pcap)
    analysis = analyze(packets)
    port_findings = port_asymmetry_detection(analysis)
    frequency_findings = frequency_detection(analysis)
    report(analysis, port_findings, frequency_findings)


def validate(traffic_file):
    if not pathlib.Path(traffic_file).is_file():
        sys.exit("File does not exist")

    try:
        scapy.all.rdpcap(traffic_file)
    except scapy.error.Scapy_Exception:
        sys.exit("Not a valid PCAP file")

    return traffic_file


def extract(valid_pcap):
    with scapy.utils.PcapReader(valid_pcap) as packets:
        for packet in packets:
            packet_size = len(packet)
            timestamp = packet.time
            packet_data = {
                "source_ip": None,
                "destination_ip": None,
                "protocol": "non-IP",
                "destination_port": None,
                "source_port": None,
                "packet_size": packet_size,
                "timestamp": timestamp
                }

            if packet.haslayer(IP):
                packet_data["source_ip"] = packet[IP].src
                packet_data["destination_ip"] = packet[IP].dst

                if packet.haslayer(TCP):
                    packet_data["protocol"] = "TCP"
                    packet_data["destination_port"] = packet[TCP].dport
                    packet_data["source_port"] = packet[TCP].sport
                elif packet.haslayer(UDP):
                    packet_data["protocol"] = "UDP"
                    packet_data["destination_port"] = packet[UDP].dport
                    packet_data["source_port"] = packet[UDP].sport
                elif packet.haslayer(ICMP):
                    packet_data["protocol"] = "ICMP"

            yield packet_data


def analyze(packets):
    total_packet_count = 0
    protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "non-IP": 0}
    source_ips = {}
    destination_ips = {}
    destination_ports = {}
    source_ports = {}
    communications = {}

    for packet_data in packets:
        total_packet_count += 1

        protocol = packet_data["protocol"]
        protocols[protocol] += 1
        
        source_ip = packet_data["source_ip"]
        if source_ip is None:
            pass
        elif source_ip not in source_ips:
            source_ips[source_ip] = 1
        else:
            source_ips[source_ip] += 1

        destination_ip = packet_data["destination_ip"]
        if destination_ip is None:
            pass
        elif destination_ip not in destination_ips:
            destination_ips[destination_ip] = 1
        else:
            destination_ips[destination_ip] += 1

        destination_port = packet_data["destination_port"]
        if destination_port is None:
            pass
        elif destination_port not in destination_ports:
            destination_ports[destination_port] = 1
        else:
            destination_ports[destination_port] += 1

        source_port = packet_data["source_port"]
        if source_port is None:
            pass
        elif source_port not in source_ports:
            source_ports[source_port] = 1
        else:
            source_ports[source_port] += 1

        packet_size = packet_data["packet_size"]
        timestamp = packet_data["timestamp"]

        source_endpoint = (source_ip, source_port)
        destination_endpoint = (destination_ip, destination_port)
        endpoints = (source_endpoint, destination_endpoint)
    
        sorted_endpoints = tuple(sorted(endpoints))
        communication_key = (protocol, sorted_endpoints)

        if communication_key not in communications:
            communications[communication_key] = {
            "packet_count": 1,
            "total_bytes": packet_size,
            "first_timestamp": timestamp,
            "last_timestamp": timestamp
            }
        else:
            communications[communication_key]["packet_count"] += 1
            communications[communication_key]["total_bytes"] += packet_size
            communications[communication_key]["last_timestamp"] = timestamp


    analysis = {
        "total_packet_count": total_packet_count,
        "protocols": protocols,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "destination_ports": destination_ports,
        "source_ports": source_ports,
        "communications": communications
        }

    return analysis


def port_asymmetry_detection(analysis):
    communications = analysis["communications"]
    port_findings = {}
    port_threshold = 3

    for communication_key, communication_data in communications.items():
        protocol, (host_a, host_b) = communication_key
        host_a_ip, host_a_port = host_a
        host_b_ip, host_b_port = host_b
    
        host_pair = (protocol, host_a_ip, host_b_ip)

        if host_pair not in port_findings:
            port_findings[host_pair] = {
                "counter": 1,
                "host_a_ports": {host_a_port},
                "host_b_ports": {host_b_port},
                "port_asymmetry": False
                }
        else:
            port_findings[host_pair]["counter"] += 1
            port_findings[host_pair]["host_a_ports"].add(host_a_port)
            port_findings[host_pair]["host_b_ports"].add(host_b_port)

        total_a_ports = port_findings[host_pair]["host_a_ports"]
        total_b_ports = port_findings[host_pair]["host_b_ports"]

        if abs(len(total_a_ports) - len(total_b_ports)) >= port_threshold:
            port_findings[host_pair]["port_asymmetry"] = True        

    return port_findings


def frequency_detection(analysis):
    communications = analysis["communications"]
    frequency_findings = {}
    packet_threshold = 3
    duration_threshold = 0.01

    for communication_key, communication_data in communications.items():
        protocol, (host_a, host_b) = communication_key
        host_a_ip = host_a[0]
        host_b_ip = host_b[0]
        host_pair = (protocol, host_a_ip, host_b_ip)

        packet_count = communication_data["packet_count"]
        first_timestamp = communication_data["first_timestamp"]
        last_timestamp = communication_data["last_timestamp"]

        if host_pair not in frequency_findings:
            frequency_findings[host_pair] = {
                "pair_packet_count": packet_count,
                "first_timestamp": first_timestamp,
                "last_timestamp": last_timestamp,
                "high_traffic": False,
                "duration": None
                }
        else:
            frequency_findings[host_pair]["pair_packet_count"] += packet_count
            if first_timestamp < frequency_findings[host_pair]["first_timestamp"]:
                frequency_findings[host_pair]["first_timestamp"] = first_timestamp
            if last_timestamp > frequency_findings[host_pair]["last_timestamp"]:
                frequency_findings[host_pair]["last_timestamp"] = last_timestamp

        duration = frequency_findings[host_pair]["last_timestamp"] - frequency_findings[host_pair]["first_timestamp"]
        frequency_findings[host_pair]["duration"] = duration

        if frequency_findings[host_pair]["pair_packet_count"] >= packet_threshold and duration <= duration_threshold:
            frequency_findings[host_pair]["high_traffic"] = True

    return frequency_findings
        

def report(analysis, port_findings, frequency_findings):
    total_packet_count = analysis["total_packet_count"]
    protocols = analysis["protocols"]
    communications = analysis["communications"]

    print("\nNetwork Traffic Summary\n--------------------------------")
    print(f" Total Packets Analyzed: {total_packet_count}\n")
    print(f" TCP: {protocols['TCP']} | UDP: {protocols['UDP']} | ICMP: {protocols['ICMP']} | Non-IP: {protocols['non-IP']}\n")


    print("\nCommunication Analysis\n--------------------------------")
    for communication_key, communication_data in communications.items():
        protocol, endpoints = communication_key
        source_endpoint, destination_endpoint = endpoints
        packet_count = communication_data["packet_count"]
        total_bytes = communication_data["total_bytes"]
        first_timestamp = communication_data["first_timestamp"]
        last_timestamp = communication_data["last_timestamp"]
        duration = last_timestamp - first_timestamp

        print(f"{protocol}: {source_endpoint[0]}:{source_endpoint[1]} ↔ {destination_endpoint[0]}:{destination_endpoint[1]}")
        print(f"      {packet_count} packets | {total_bytes} bytes | {duration:.3f} sec\n")

    print("\nPort-Based Traffic Findings\n--------------------------------")
    for host_pair, communication_data in port_findings.items():
        if communication_data["port_asymmetry"]:
            counter = communication_data["counter"]
            a_ports = communication_data["host_a_ports"]
            b_ports = communication_data["host_b_ports"]
            
            print(f"{host_pair[0]}   {host_pair[1]} ↔ {host_pair[2]}")
            print(f"      {counter} communications  |  Host A Ports: {len(a_ports)}  |  Host B Ports: {len(b_ports)}\n")

    print("\nHost-Pair Traffic Findings\n--------------------------------")
    for host_pair, finding in frequency_findings.items():
        protocol, host_a_ip, host_b_ip = host_pair

        print(f"{protocol}   {host_a_ip} ↔ {host_b_ip}")
        print(f"      Packets: {finding['pair_packet_count']} | Duration: {finding['duration']:.3f} sec | High Traffic: {finding['high_traffic']}\n")


if __name__ == "__main__":
    main()
