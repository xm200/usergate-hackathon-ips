import time
from collections import defaultdict, deque

class StreamReassembler:
    def __init__(self, max_buffer_size=65536, flow_timeout=60):
        self.flows = defaultdict(lambda: {
            'buffer': bytearray(),
            'last_seen': time.time(),
            'state': 'active'
        })
        self.max_buffer_size = max_buffer_size
        self.flow_timeout = flow_timeout

    def get_flow_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        return (src_ip, src_port, dst_ip, dst_port, protocol)

    def add_tcp_segment(self, flow_key, data):
        flow = self.flows[flow_key]
        flow['last_seen'] = time.time()

        if len(flow['buffer']) + len(data) > self.max_buffer_size:
            overflow = len(flow['buffer']) + len(data) - self.max_buffer_size
            flow['buffer'] = flow['buffer'][overflow:]

        flow['buffer'].extend(data)
        return flow['buffer']

    def add_udp_datagram(self, flow_key, data):
        flow = self.flows[flow_key]
        flow['last_seen'] = time.time()
        flow['buffer'] = bytearray(data)
        return flow['buffer']

    def get_buffer(self, flow_key, max_scan_window=8192):
        if flow_key not in self.flows:
            return bytearray()

        buffer = self.flows[flow_key]['buffer']
        if len(buffer) > max_scan_window:
            return buffer[-max_scan_window:]
        return buffer

    def close_flow(self, flow_key):
        if flow_key in self.flows:
            self.flows[flow_key]['state'] = 'closed'

    def prune_flows(self):
        current_time = time.time()
        expired_flows = []

        for flow_key, flow in self.flows.items():
            if (current_time - flow['last_seen'] > self.flow_timeout or
                flow['state'] == 'closed'):
                expired_flows.append(flow_key)

        for flow_key in expired_flows:
            del self.flows[flow_key]

    def get_stats(self):
        return {
            'active_flows': len(self.flows),
            'total_buffer_size': sum(len(f['buffer']) for f in self.flows.values())
        }
