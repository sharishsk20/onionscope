"""
OnionScope - PCAP Flow Analyser
Extracts timing signatures and flow features from PCAP files.
Works on both suspect-side and destination-side captures.
"""

import os
import json
import hashlib
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

# Try scapy, fall back to dpkt if unavailable
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    print("[Analyser] Scapy not available, using synthetic mode.")


class FlowSignature:
    """Represents the timing/size signature of a network flow."""

    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, protocol: str):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.timestamps: List[float] = []
        self.sizes: List[int] = []
        self.directions: List[int] = []  # 1 = outbound, -1 = inbound

    def add_packet(self, timestamp: float, size: int, direction: int = 1):
        self.timestamps.append(timestamp)
        self.sizes.append(size)
        self.directions.append(direction)

    def get_inter_arrival_times(self) -> np.ndarray:
        if len(self.timestamps) < 2:
            return np.array([])
        ts = np.array(sorted(self.timestamps))
        return np.diff(ts)

    def get_burst_pattern(self, window: float = 1.0) -> np.ndarray:
        """Count packets per time window — creates a fingerprint."""
        if not self.timestamps:
            return np.array([])
        ts = np.array(self.timestamps)
        start = ts.min()
        end = ts.max()
        if end == start:
            return np.array([len(ts)])
        bins = np.arange(start, end + window, window)
        counts, _ = np.histogram(ts, bins=bins)
        return counts

    def get_volume_series(self, window: float = 1.0) -> np.ndarray:
        """Total bytes per time window."""
        if not self.timestamps:
            return np.array([])
        ts = np.array(self.timestamps)
        sizes = np.array(self.sizes)
        start = ts.min()
        end = ts.max()
        if end == start:
            return np.array([sizes.sum()])
        bins = np.arange(start, end + window, window)
        volumes = np.zeros(len(bins) - 1)
        for i, (t, s) in enumerate(zip(ts, sizes)):
            idx = int((t - start) / window)
            if idx < len(volumes):
                volumes[idx] += s
        return volumes

    def to_dict(self) -> Dict:
        iats = self.get_inter_arrival_times()
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "packet_count": len(self.timestamps),
            "duration": (max(self.timestamps) - min(self.timestamps)) if len(self.timestamps) > 1 else 0,
            "total_bytes": sum(self.sizes),
            "mean_iat": float(iats.mean()) if len(iats) > 0 else 0,
            "std_iat": float(iats.std()) if len(iats) > 0 else 0,
            "mean_size": float(np.mean(self.sizes)) if self.sizes else 0,
            "burst_pattern": self.get_burst_pattern().tolist(),
            "volume_series": self.get_volume_series().tolist(),
            "timestamps": self.timestamps[:100],  # cap for JSON
        }


def parse_pcap(filepath: str) -> List[FlowSignature]:
    """Parse a PCAP file and extract per-flow signatures."""
    if not SCAPY_AVAILABLE:
        print(f"[Analyser] Scapy unavailable — generating synthetic flows for demo.")
        return generate_synthetic_flows(filepath)

    if not os.path.exists(filepath):
        print(f"[Analyser] File not found: {filepath}")
        return []

    print(f"[Analyser] Parsing {filepath}...")
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[Analyser] Failed to read PCAP: {e}")
        return []

    flows: Dict[str, FlowSignature] = {}

    for pkt in packets:
        try:
            if IP not in pkt:
                continue
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
            size = len(pkt)
            ts = float(pkt.time)

            # Create bidirectional flow key
            key = tuple(sorted([src, dst])) + (proto,)
            flow_id = hashlib.md5(str(key).encode()).hexdigest()[:12]

            if flow_id not in flows:
                flows[flow_id] = FlowSignature(flow_id, src, dst, proto)

            direction = 1 if src < dst else -1
            flows[flow_id].add_packet(ts, size, direction)

        except Exception:
            continue

    result = list(flows.values())
    print(f"[Analyser] Extracted {len(result)} flows from PCAP.")
    return result


def generate_synthetic_flows(label: str = "synthetic") -> List[FlowSignature]:
    """
    Generate realistic synthetic TOR flow data for demo purposes.
    Simulates two correlated flows (entry + exit side of same circuit).
    """
    np.random.seed(42)
    base_time = 1700000000.0
    flows = []

    # Simulate 3 TOR circuits
    for i in range(3):
        circuit_seed = i * 1000
        np.random.seed(circuit_seed)

        # Entry side flow (what ISP would see going TO guard node)
        entry = FlowSignature(
            flow_id=f"entry_{i}",
            src_ip=f"192.168.1.{10+i}",
            dst_ip=f"185.{i+100}.{i+50}.{i+1}",
            protocol="TCP"
        )

        # Exit side flow (what destination sees FROM exit node) — correlated timing
        exit_flow = FlowSignature(
            flow_id=f"exit_{i}",
            src_ip=f"77.{i+20}.{i+30}.{i+5}",
            dst_ip=f"10.0.0.{i+1}",
            protocol="TCP"
        )

        # Generate correlated packet bursts (same pattern, ~50ms delay)
        n_bursts = 15
        for burst in range(n_bursts):
            burst_time = base_time + burst * 2.0 + np.random.uniform(0, 0.1)
            n_pkts = np.random.poisson(5) + 1
            for p in range(n_pkts):
                t_offset = np.random.exponential(0.05)
                size = np.random.choice([512, 1024, 1448], p=[0.3, 0.4, 0.3])
                entry.add_packet(burst_time + t_offset, size)
                # Exit side: same burst, ~50ms latency added
                exit_flow.add_packet(burst_time + t_offset + 0.05 + np.random.normal(0, 0.005), size)

        flows.extend([entry, exit_flow])

    # Add some noise flows (unrelated traffic)
    for i in range(4):
        noise = FlowSignature(
            flow_id=f"noise_{i}",
            src_ip=f"10.0.{i}.1",
            dst_ip=f"8.8.{i}.{i}",
            protocol="TCP"
        )
        np.random.seed(9999 + i)
        for _ in range(np.random.randint(5, 30)):
            noise.add_packet(
                base_time + np.random.uniform(0, 30),
                np.random.randint(64, 1500)
            )
        flows.append(noise)

    print(f"[Analyser] Generated {len(flows)} synthetic flows (3 correlated TOR circuits + noise).")
    return flows


def analyse_file(filepath: str) -> Dict:
    """Analyse a PCAP file and return structured result."""
    flows = parse_pcap(filepath)
    return {
        "source": filepath,
        "flow_count": len(flows),
        "flows": [f.to_dict() for f in flows],
        "analysed_at": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    print("=== OnionScope PCAP Analyser ===")
    # Demo with synthetic data
    result = analyse_file("demo_synthetic")
    print(f"\nFlows extracted: {result['flow_count']}")
    for f in result['flows'][:3]:
        print(f"\n  Flow: {f['flow_id']} | {f['src_ip']} → {f['dst_ip']}")
        print(f"    Packets: {f['packet_count']} | Bytes: {f['total_bytes']}")
        print(f"    Mean IAT: {f['mean_iat']:.4f}s | Std IAT: {f['std_iat']:.4f}s")
