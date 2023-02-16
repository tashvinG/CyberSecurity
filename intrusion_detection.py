import re
import sys
import smtplib
from datetime import datetime

def parse_log_data(log_file):
    """Parses log data into a list of dictionaries, where each dictionary
    represents a log entry with relevant fields such as IP address,
    timestamp, and type of intrusion attempt.
    """
    log_entries = []
    with open(log_file, "r") as f:
        for line in f:
            fields = line.strip().split()
            if len(fields) < 3:
                continue
            log_entry = {
                "ip_address": fields[-1],
                "timestamp": fields[0] + " " + fields[1],
            }
            if "Failed Login" in line:
                log_entry["attempt_type"] = "Failed Login"
            elif "Port scanning" in line:
                log_entry["attempt_type"] = "Port scanning"
            elif "Request" in line:
                log_entry["attempt_type"] = "Request"
            log_entries.append(log_entry)
    return log_entries


def detect_intrusion(log_entries):
    """Checks each log entry against a set of intrusion detection rules
    and returns a list of dictionaries representing intrusion attempts.
    """
    intrusion_attempts = set()
    records = {}
    date_format = '%Y-%m-%d %H:%M:%S'
    for entry in log_entries:
        if entry.get("attempt_type") == "Failed Login":
            # Check if more than 10 failed login attempts from the same IP address
            # have occurred in the last hour
            if entry["ip_address"] in records and records[entry["ip_address"]]["pattern"] == "Brute Force":
                timediff = datetime.strptime(entry["timestamp"], date_format) - datetime.strptime(records[entry["ip_address"]]["timestamp"], date_format)
                if timediff.total_seconds() // 3600 < 1:
                    records[entry["ip_address"]]["count"] += 1
                    if records[entry["ip_address"]]["count"] >= 10:
                        intrusion_attempts.add((entry["ip_address"], "Brute Force pattern detected"))
                        records[entry["ip_address"]]["count"] = 0
                else:
                    records[entry["ip_address"]]["count"] = 1
                records[entry["ip_address"]]["timestamp"] = entry["timestamp"]
            else:
                records[entry["ip_address"]] = {"timestamp": entry["timestamp"], "count": 1, "pattern": "Brute Force"}

        elif entry.get("attempt_type") == "Port scanning":
            # Check if more than 20 port scanning attempts from the same IP address
            # have occurred in the last day
            if entry["ip_address"] in records and records[entry["ip_address"]]["pattern"] == "Port Scanning":
                timediff = datetime.strptime(entry["timestamp"], date_format) - datetime.strptime(records[entry["ip_address"]]["timestamp"], date_format)
                if timediff.total_seconds() // 86400 < 1:
                    records[entry["ip_address"]]["count"] += 1
                    if records[entry["ip_address"]]["count"] >= 20:
                        intrusion_attempts.add((entry["ip_address"], "Port Scanning pattern detected"))
                        records[entry["ip_address"]]["count"] = 0
                else:
                    records[entry["ip_address"]]["count"] = 1
                records[entry["ip_address"]]["timestamp"] = entry["timestamp"]
            else:
                records[entry["ip_address"]] = {"timestamp": entry["timestamp"], "count": 1, "pattern": "Port Scanning"}

        elif entry.get("attempt_type") == "Request":
            # Check if more than 20 requests from the same IP address
            # have occurred in the last minute
            if entry["ip_address"] in records and records[entry["ip_address"]]["pattern"] == "Request":
                timediff = datetime.strptime(entry["timestamp"], date_format) - datetime.strptime(records[entry["ip_address"]]["timestamp"], date_format)
                if timediff.total_seconds() // 60 < 1:
                    records[entry["ip_address"]]["count"] += 1
                    if records[entry["ip_address"]]["count"] >= 20:
                        intrusion_attempts.add((entry["ip_address"], "DDoS pattern detected"))
                        records[entry["ip_address"]]["count"] = 0
                else:
                    records[entry["ip_address"]]["count"] = 1
                records[entry["ip_address"]]["timestamp"] = entry["timestamp"]
            else:
                records[entry["ip_address"]] = {"timestamp": entry["timestamp"], "count": 1, "pattern": "Request"}
    return intrusion_attempts


def main():
  
    ans=detect_intrusion(parse_log_data(sys.argv[1]))
    for data in ans:
        print("IP:" + data[0])
        print("Intrusion Detected:" + data[1])

if __name__ == '__main__':
    main()
