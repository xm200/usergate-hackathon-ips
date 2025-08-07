#!/usr/bin/env python3

import socket
import time
import random
import threading
from urllib.parse import quote

class TrafficGenerator:
    def __init__(self, target_host='127.0.0.1', target_port=8000):
        self.target_host = target_host
        self.target_port = target_port
        self.running = False
        self.idt = 0
        self.idu = 0

    def send_http_request(self, method='GET', path='/', headers=None, body=''):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, self.target_port))

            if headers is None:
                headers = {'Host': self.target_host, 'User-Agent': 'TrafficGen/1.0'}

            request = f"{method} {path} HTTP/1.1\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"

            if body:
                request += body

            sock.send(request.encode())
            response = sock.recv(1024)
            sock.close()
            return True
        except Exception as e:
            return False

    def send_tcp_data(self, data, port=None):
        try:
            if port is None:
                port = self.target_port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, port))
            sock.send(data.encode() if isinstance(data, str) else data)
            sock.close()
            return True
        except Exception as e:
            return False

    def send_udp_data(self, data, port=53):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data.encode() if isinstance(data, str) else data, (self.target_host, port))
            sock.close()
            return True
        except Exception as e:
            return False

    def generate_benign_traffic(self):
        benign_requests = [
            ('GET', '/', {'User-Agent': 'Mozilla/5.0'}),
            ('GET', '/index.html', {'User-Agent': 'Chrome/91.0'}),
            ('POST', '/api/data', {'Content-Type': 'application/json'}, '{"user": "test"}'),
            ('GET', '/images/logo.png', {'Accept': 'image/*'}),
            ('GET', '/styles/main.css', {'Accept': 'text/css'}),
        ]

        method, path, headers, *body = random.choice(benign_requests)
        body = body[0] if body else ''
        return self.send_http_request(method, path, headers, body)

    def generate_malicious_traffic(self):
        malicious_patterns = [
            ('GET', '/test.php?id=1 UNION SELECT * FROM users', {}),
            ('POST', '/upload', {'Content-Type': 'text/plain'}, 'This payload contains malware signatures'),
            ('GET', '/admin', {'X-Attack-Vector': 'backdoor access attempt'}, ''),
            ('POST', '/comment', {'Content-Type': 'application/x-www-form-urlencoded'},
             'content=<script>alert("xss")</script>&submit=1'),
            ('GET', '/search?q=attack%20vector', {'User-Agent': 'AttackBot/1.0'}),
        ]

        method, path, headers, body = malicious_patterns[self.idt]
        self.idt = (self.idt + 1) % len(malicious_patterns)
        return self.send_http_request(method, path, headers, body)

    def generate_tcp_malicious(self):
        tcp_payloads = [
            b"CONNECT backdoor.example.com:4444 HTTP/1.1\r\nHost: backdoor.example.com\r\n\r\n",
            b"POST /cmd.php HTTP/1.1\r\nHost: target.com\r\n\r\nUNION SELECT password FROM admin",
            b"GET /shell.php?cmd=cat /etc/passwd HTTP/1.1\r\n\r\n",
            b"This is a malware signature embedded in TCP stream",
            b"attack vector with embedded payload data",
        ]

        payload = random.choice(tcp_payloads)
        return self.send_tcp_data(payload, 5252)

    def generate_udp_traffic(self):
        udp_payloads = [
            b"DNS query with malware domain",
            b"UDP flood attack pattern",
            b"Backdoor communication over UDP",
            b"Normal DNS query for example.com",
            b"DHCP discover packet simulation",
        ]

        payload = random.choice(udp_payloads)
        return self.send_udp_data(payload, 5353)

    def worker_thread(self, traffic_type, rate_per_second):
        while self.running:
            try:
                if traffic_type == 'benign':
                    self.generate_benign_traffic()
                elif traffic_type == 'malicious':
                    self.generate_malicious_traffic()
                elif traffic_type == 'tcp_malicious':
                    self.generate_tcp_malicious()
                elif traffic_type == 'udp':
                    self.generate_udp_traffic()

                time.sleep(1.0 / rate_per_second)
            except Exception as e:
                time.sleep(0.1)

    def start_generation(self, benign_rate=5, malicious_rate=2, tcp_rate=1, udp_rate=1):
        print(f"Starting traffic generation to {self.target_host}:{self.target_port}")
        print(f"Rates: Benign={benign_rate}/s, Malicious={malicious_rate}/s, TCP={tcp_rate}/s, UDP={udp_rate}/s")

        self.running = True

        threads = []

        if benign_rate > 0:
            t = threading.Thread(target=self.worker_thread, args=('benign', benign_rate))
            t.daemon = True
            t.start()
            threads.append(t)

        if malicious_rate > 0:
            t = threading.Thread(target=self.worker_thread, args=('malicious', malicious_rate))
            t.daemon = True
            t.start()
            threads.append(t)

        if tcp_rate > 0:
            t = threading.Thread(target=self.worker_thread, args=('tcp_malicious', tcp_rate))
            t.daemon = True
            t.start()
            threads.append(t)

        if udp_rate > 0:
            t = threading.Thread(target=self.worker_thread, args=('udp', udp_rate))
            t.daemon = True
            t.start()
            threads.append(t)

        return threads

    def stop_generation(self):
        print("Stopping traffic generation...")
        self.running = False

def main():
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser(description='Generate test traffic for IDS/IPS testing')
    parser.add_argument('--host', default='127.0.0.1', help='Target host')
    parser.add_argument('--port', type=int, default=80, help='Target port')
    parser.add_argument('--benign-rate', type=int, default=5, help='Benign requests per second')
    parser.add_argument('--malicious-rate', type=int, default=2, help='Malicious requests per second')
    parser.add_argument('--tcp-rate', type=int, default=1, help='TCP malicious packets per second')
    parser.add_argument('--udp-rate', type=int, default=1, help='UDP packets per second')
    parser.add_argument('--duration', type=int, default=0, help='Duration in seconds (0 = infinite)')

    args = parser.parse_args()

    generator = TrafficGenerator(args.host, args.port)

    def signal_handler(sig, frame):
        generator.stop_generation()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Traffic Generator for GoIDA IPS Testing")
    print("=" * 40)
    print(f"Target: {args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    print()

    threads = generator.start_generation(
        benign_rate=args.benign_rate,
        malicious_rate=args.malicious_rate,
        tcp_rate=args.tcp_rate,
        udp_rate=args.udp_rate
    )

    try:
        if args.duration > 0:
            time.sleep(args.duration)
            generator.stop_generation()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        generator.stop_generation()

if __name__ == '__main__':
    main()
