import time
import json
from flask import Flask, jsonify
from multiprocessing import Manager

class MetricsServer:
    def __init__(self, config):
        self.app = Flask(__name__)
        self.config = config
        self.manager = Manager()
        self.shared_stats = self.manager.dict()
        self.start_time = time.time()

        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'ok', 'uptime': time.time() - self.start_time})

        @self.app.route('/stats')
        def stats():
            total_stats = {
                'packets_processed': 0,
                'matches_found': 0,
                'packets_dropped': 0,
                'packets_accepted': 0,
                'active_flows': 0,
                'total_buffer_size': 0,
                'pending_alerts': 0,
                'uptime': time.time() - self.start_time,
                'workers': {}
            }

            for queue_id, worker_stats in self.shared_stats.items():
                total_stats['packets_processed'] += worker_stats.get('packets_processed', 0)
                total_stats['matches_found'] += worker_stats.get('matches_found', 0)
                total_stats['packets_dropped'] += worker_stats.get('packets_dropped', 0)
                total_stats['packets_accepted'] += worker_stats.get('packets_accepted', 0)
                total_stats['active_flows'] += worker_stats.get('active_flows', 0)
                total_stats['total_buffer_size'] += worker_stats.get('total_buffer_size', 0)
                total_stats['pending_alerts'] += worker_stats.get('pending_alerts', 0)
                total_stats['workers'][f'queue_{queue_id}'] = worker_stats

            return jsonify(total_stats)

        @self.app.route('/stats/<int:queue_id>')
        def worker_stats(queue_id):
            if queue_id in self.shared_stats:
                stats = dict(self.shared_stats[queue_id])
                stats['uptime'] = time.time() - self.start_time
                return jsonify(stats)
            return jsonify({'error': 'Worker not found'}), 404

    def update_worker_stats(self, queue_id, stats):
        self.shared_stats[queue_id] = stats

    def run(self):
        host = self.config.get('http_metrics', {}).get('host', '127.0.0.1')
        port = self.config.get('http_metrics', {}).get('port', 8080)
        self.app.run(host=host, port=port, debug=False, use_reloader=False)

    def get_shared_stats(self):
        return self.shared_stats
