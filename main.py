#!/usr/bin/env python3

import os
import sys
import yaml
import time
import signal
import multiprocessing as mp
from matcher import MatcherEngine
from worker import PacketWorker
from metrics import MetricsServer

class IDSIPSSystem:
    def __init__(self, config_file='config.yaml'):
        self.config = self.load_config(config_file)
        self.matcher = MatcherEngine()
        self.workers = []
        self.metrics_server = None
        self.metrics_process = None
        self.running = True

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    def build_matcher(self):
        rules = self.config.get('rules', [])
        print(rules)

        for rule in rules:
            rule_id = rule['id']
            pattern = rule['pattern']
            protocol = rule.get('protocol', 'any')
            action = rule.get('action', 'drop')
            rule_type = rule['type']

            if rule_type == 'literal':
                self.matcher.add_literal_rule(rule_id, pattern, protocol, action)
            elif rule_type == 'regex':
                self.matcher.add_regex_rule(rule_id, pattern, protocol, action)

        self.matcher.build()
        print(f"Built matcher with {len(rules)} rules")

    def start_metrics_server(self):
        self.metrics_server = MetricsServer(self.config)
        self.metrics_process = mp.Process(target=self.metrics_server.run)
        self.metrics_process.start()
        print(f"Started metrics server on {self.config.get('http_metrics', {}).get('host', '127.0.0.1')}:{self.config.get('http_metrics', {}).get('port', 8080)}")

    def start_workers(self):
        queue_count = self.config.get('queues', 4)
        shared_stats = self.metrics_server.get_shared_stats() if self.metrics_server else None

        for queue_id in range(queue_count):
            worker_process = mp.Process(
                target=self.worker_main,
                args=(queue_id, self.config, shared_stats)
            )
            worker_process.start()
            self.workers.append(worker_process)
            os.system(f"iptables -I INPUT -j NFQUEUE --queue-num {queue_id}")
            os.system(f"iptables -I OUTPUT -j NFQUEUE --queue-num {queue_id}")
            print(f"Started worker for queue {queue_id} (PID: {worker_process.pid})")

    def worker_main(self, queue_id, config, shared_stats):
        matcher = MatcherEngine()
        rules = config.get('rules', [])

        for rule in rules:
            rule_id = rule['id']
            pattern = rule['pattern']
            protocol = rule.get('protocol', 'any')
            action = rule.get('action', 'drop')
            rule_type = rule['type']

            if rule_type == 'literal':
                matcher.add_literal_rule(rule_id, pattern, protocol, action)
            elif rule_type == 'regex':
                matcher.add_regex_rule(rule_id, pattern, protocol, action)

        matcher.build()

        worker = PacketWorker(queue_id, matcher, config)

        def update_stats():
            if shared_stats is not None:
                shared_stats[queue_id] = worker.get_stats()

        last_stats_update = time.time()

        def stats_updater():
            nonlocal last_stats_update
            current_time = time.time()
            if current_time - last_stats_update > 5:
                update_stats()
                last_stats_update = current_time

        original_callback = worker.packet_callback
        def enhanced_callback(packet):
            result = original_callback(packet)
            stats_updater()
            return result

        worker.packet_callback = enhanced_callback
        worker.run()

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False
        self.shutdown()

    def shutdown(self):
        print("Shutting down workers...")
        for worker in self.workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()

        if self.metrics_process and self.metrics_process.is_alive():
            print("Shutting down metrics server...")
            self.metrics_process.terminate()
            self.metrics_process.join(timeout=5)
            if self.metrics_process.is_alive():
                self.metrics_process.kill()

        print("Shutdown complete")

    def check_privileges(self):
        if os.geteuid() != 0:
            print("ERROR: This program must be run as root to access NFQUEUE")
            print("Please run with: sudo python3 main.py")
            sys.exit(1)

    def run(self):
        self.check_privileges()

        print("Starting GOIDA IPS...")
        print(f"Process ID: {os.getpid()}")

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.build_matcher()
        self.start_metrics_server()

        time.sleep(1)

        self.start_workers()

        print(f"System started with {len(self.workers)} workers")
        print("Press Ctrl+C to stop")

        try:
            while self.running:
                time.sleep(1)

                alive_workers = [w for w in self.workers if w.is_alive()]
                if len(alive_workers) != len(self.workers):
                    print(f"Warning: {len(self.workers) - len(alive_workers)} workers died")

        except KeyboardInterrupt:
            pass
        finally:
            for i in range(self.config.get("queues", 4)):
                os.system(f"iptables -D INPUT -j NFQUEUE --queue-num {i}")
                os.system(f"iptables -D OUTPUT -j NFQUEUE --queue-num {i}")
            self.shutdown()

def main():
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = 'config.yaml'

    system = IDSIPSSystem(config_file)
    system.run()

if __name__ == '__main__':
    main()
