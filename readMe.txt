This is a sample project which function as a simple intrusion detection system using Python:

A sample log file is provided named as log_file.log and you can execute the program by inserting this command in your terminal. "python intrusion_detection.py log_file.log"

You can also provide log data in log file or text file format from your network devices such as routers or firewalls.(The format of the log data used in this project is in this format "2023-02-16 09:01:23 INFO: Failed Login attempt from 10.0.0.2") 

After log.file is given the Python script will read the log data and parse it into relevant fields such as IP addresses, timestamps, and type of intrusion attempts.

By following a set of intrusion detection rules based on commonly known attack patterns and malicious behavior such as brute force attempts, port scanning, and DDoS attacks then it will compare each log entry against the set of rules and flag any entries that match a rule as an intrusion attempt.

The result to be expected is 
Ip:The Ip that against the set of rules 
Intrusion Detected: Brute Force/DDoS/Port scanning
