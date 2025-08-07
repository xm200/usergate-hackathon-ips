import os
import gc
import time
import socket
import os
import dpkt
from netfilterqueue import NetfilterQueue
import syslog
from reassembler import StreamReassembler

class PacketWorker:
    def __init__(self, queue_id, matcher_engine, config):
        self.queue_id = queue_id
        self.matcher = matcher_engine
        self.config = config
        self.reassembler = StreamReassembler(
            max_buffer_size=config.get('max_buffer_size', 65536),
            flow_timeout=config.get('flow_timeout', 60)
        )
        self.nfqueue = NetfilterQueue()
        self.stats = {
            'packets_processed': 0,
            'matches_found': 0,
            'packets_dropped': 0,
            'packets_accepted': 0
        }
        self.alerts = []
        self.last_prune = time.time()
        self.last_log_flush = time.time()
        

    def setup(self):
        self.nfqueue.bind(self.queue_id, self.packet_callback)
        gc.disable()
        try:
            os.sched_setaffinity(0, {self.queue_id % os.cpu_count()})
        except:
            pass

    def packet_callback(self, packet):
        try:
            self.stats['packets_processed'] += 1
            raw_data = packet.get_payload()

            try:
                ip = dpkt.ip.IP(raw_data)
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)

                protocol = None
                src_port = dst_port = 0
                payload = b''


                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    protocol = 'tcp'
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    payload = tcp.data

                    flow_key = self.reassembler.get_flow_key(
                        src_ip, src_port, dst_ip, dst_port, protocol
                    )

                    buffer = self.reassembler.add_tcp_segment(flow_key, payload)
                    scan_data = self.reassembler.get_buffer(
                        flow_key, self.config.get('max_scan_window', 8192)
                    )

                    if tcp.flags & dpkt.tcp.TH_FIN or tcp.flags & dpkt.tcp.TH_RST:
                        self.reassembler.close_flow(flow_key)

                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    scan_data = bytearray(bytes(ip.data.data))
                    if len(scan_data) != 60:
                        packet.drop()
                        self.stats['packets_dropped'] += 1

                elif ip.p == dpkt.ip.IP_PROTO_UDP: 
                    udp = ip.data
                    protocol = 'udp'
                    src_port = udp.sport
                    dst_port = udp.dport
                    payload = udp.data

                    flow_key = self.reassembler.get_flow_key(
                        src_ip, src_port, dst_ip, dst_port, protocol
                    )

                    scan_data = self.reassembler.add_udp_datagram(flow_key, payload)

                else:
                    packet.accept()
                    self.stats['packets_accepted'] += 1
                    syslog.syslog(1, f"[ACCEPT] {src_ip} -> {dst_ip} proto: {protocol}; Uncheckable protocol")
                    return "1" + ip.get_proto(ip.p)
                

                if not scan_data:
                    packet.accept()
                    self.stats['packets_accepted'] += 1
                    syslog.syslog(1, f"[ACCEPT] {src_ip} -> {dst_ip}; proto: {protocol}; No scan data present")
                    return "2" + ip.get_proto(ip.p)

                matches = self.matcher.match(scan_data, protocol)
                if len(matches) > 0:
                    for match in matches:
                        if match['action'] == 'drop' and len(match['matches']) > 0:
                            #self.log_match(match, flow_key, src_ip, dst_ip, src_port, dst_port, protocol)
                            packet.drop()
                            syslog.syslog(f"[DROP] {src_ip} -> {dst_ip}; proto: {protocol}; Found matches: {matches}")
                            self.stats['packets_dropped'] += 1
                            self.stats['matches_found'] += 1
                            return
                

                packet.accept()
                self.stats['packets_accepted'] += 1

            except Exception as e:
                packet.accept()
                self.stats['packets_accepted'] += 1
                syslog.syslog(f"[ERROR] {src_ip} -> {dst_ip}; Error: {str(e)}")
                return

        except Exception as e:
            try:
                packet.accept()
                self.stats['packets_accepted'] += 1
                syslog.syslog(f"[ERROR] {src_ip} -> {dst_ip}; Error: {str(e)}")
                return 
            except:
                pass

        current_time = time.time()
        if current_time - self.last_prune > 30:
            self.reassembler.prune_flows()
            self.last_prune = current_time


        if current_time - self.last_log_flush > self.config.get('log_flush_interval', 60):
            self.flush_logs()
            self.last_log_flush = current_time


    def log_match(self, match, flow_key, src_ip, dst_ip, src_port, dst_port, protocol):
        alert = {
            'timestamp': time.time(),
            'rule_id': match['rule_id'],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'offset': match['offset'],
            'action': match['action'],
            'type': match['type']
        }
        self.alerts.append(alert)


    def flush_logs(self):
        if not self.alerts:
            return

        timestamp = int(time.time())
        filename = f"alerts_{timestamp}_q{self.queue_id}.csv"

        try:
            with open(filename, 'w') as f:
                f.write("timestamp,rule_id,src_ip,dst_ip,src_port,dst_port,protocol,offset,action,type\n")
                for alert in self.alerts:
                    f.write(f"{alert['timestamp']},{alert['rule_id']},{alert['src_ip']},{alert['dst_ip']},{alert['src_port']},{alert['dst_port']},{alert['protocol']},{alert['offset']},{alert['action']},{alert['type']}\n")
            self.alerts.clear()
        except Exception as e:
            pass


    def run(self):
        self.setup()
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.flush_logs()
            self.nfqueue.unbind()
            

    def get_stats(self):
        stats = self.stats.copy()
        stats.update(self.reassembler.get_stats())
        stats['queue_id'] = self.queue_id
        stats['pending_alerts'] = len(self.alerts)
        return stats
