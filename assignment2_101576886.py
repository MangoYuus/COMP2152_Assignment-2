"""
Author: <Yuqing.Lin>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {platform.system()}")

#This dictionary is used to store port numbers and their service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target
# Q3: What is the benefit of using @property and @target.setter?
# TODO: Your 2-4 sentence answer here... (Part 2, Q3)
# 'self.__target' is a private property.
# Using '@property' and '@target.setter' can ensure the encapsulation of the property and provide a secure access interface,
# thereby ensuring code security.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# TODO: Your 2-4 sentence answer here... (Part 2, Q1)
# 'PortScanner' class inherits from the parent class 'NetWorkTool' [ class PortScanner(NetWorkTool) ],
# so it can directly reuse code without redefining the same methods or properties.
# For example, in the destructor, 'PortScanner' can use 'super().__del__()' to directly call the '__del__' method in the parent class to print "NetworkTool instance destroyed".
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
#     Q4: What would happen without try-except here?
#     TODO: Your 2-4 sentence answer here... (Part 2, Q4)
#     The try-except block is used to catch errors and prevent the program from crashing due to socket errors.
#     Removing all blocks and then scanning ports on inaccessible machines will cause the program to report errors and crash,
#     preventing further scanning of the remaining ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

#     Q2: Why do we use threading instead of scanning one port at a time?
#     TODO: Your 2-4 sentence answer here... (Part 2, Q2)
#     Because we have multiple ports that can be scanned simultaneously,
#     using threading to scan the ports in a multi-threaded manner instead of scanning them one by one can save a significant amount of time.
#     If we don't use multi-threading, we need to wait for the ports to be scanned sequentially, which could take up to 1024 seconds. [settimeout(1)]
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS scans  (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")

        for port, status, service in results:
            cursor.execute("INSERT INTO scans (target,port,status,service,scan_date) VALUES (?,?,?,?,?)",
                            (target, port, status, service, datetime.datetime.now()))
        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Error scanning port {port}: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target = input("Please Enter Target IP: ")
        if target == "":
            target = "127.0.0.1"
        start_port = int(input("Please Enter Starting Port (1-1024):"))
        end_port = int(input("Please Enter Ending Port (1-1024, >= start port):"))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
            exit()

        if start_port > end_port:
            print("End Port must be Greater than or Equal to Start Port")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
    port_results = scanner.get_open_ports()
    print(f"--- Scan Results for {target} ---")
    for port, status, service in port_results:
        print(f"Port {port}: {status} ({service})")
    print(f"------\nTotal open ports found: {len(port_results)}")

    save_results(target, port_results)
    choose = input("Would you like to see past scan history? (yes/no): ")
    if choose == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# TODO: Your 2-3 sentence description here... (Part 2, Q5)
# Diagram: See diagram_101576886.png in the repository root
# Based on the provided reference examples and my learning in week 11 lab,
# I want to add a feature to categorize open ports by service type
# and use nested if statements to group and display the scanned ports according to common service types.

