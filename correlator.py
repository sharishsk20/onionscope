"""
OnionScope - Traffic Correlation Engine
Core algorithm: correlates entry-side and exit-side traffic flows
to identify if they belong to the same TOR circuit.

Techniques used:
1. Cross-correlation of packet inter-arrival time series
2. Volume burst pattern matching
3. Statistical feature similarity (KL divergence, cosine similarity)
4. Combined confidence scoring

Reference: DeepCorr (Nasr et al., 2018) — simplified reimplementation
"""

import numpy as np
from scipy import signal, stats
from sklearn.preprocessing import normalize
from typing import List, Dict, Tuple, Optional
import json
import sqlite3
import os
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onionscope.db")


def cross_correlate_series(a: np.ndarray, b: np.ndarray, max_lag: int = 10) -> Tuple[float, int]:
    """
    Compute normalized cross-correlation between two time series.
    Returns (max_correlation, best_lag).
    
    This is the core timing attack — if entry and exit flows are correlated,
    they likely belong to the same circuit.
    """
    if len(a) == 0 or len(b) == 0:
        return 0.0, 0

    # Normalize both series
    a = (a - a.mean()) / (a.std() + 1e-10)
    b = (b - b.mean()) / (b.std() + 1e-10)

    # Pad shorter series
    max_len = max(len(a), len(b))
    a = np.pad(a, (0, max_len - len(a)))
    b = np.pad(b, (0, max_len - len(b)))

    # Full cross-correlation
    corr = signal.correlate(a, b, mode='full')
    lags = signal.correlation_lags(len(a), len(b), mode='full')

    # Normalize
    norm_corr = corr / (len(a) * 1.0)

    # Find best lag within bounds
    mid = len(norm_corr) // 2
    window = min(max_lag, mid)
    search_range = norm_corr[mid - window: mid + window]
    search_lags = lags[mid - window: mid + window]

    if len(search_range) == 0:
        return 0.0, 0

    best_idx = np.argmax(np.abs(search_range))
    return float(search_range[best_idx]), int(search_lags[best_idx])


def iat_similarity(flow_a: Dict, flow_b: Dict) -> float:
    """
    Compare inter-arrival time distributions using KL divergence.
    Lower divergence = more similar = higher score.
    """
    def get_iat_hist(flow: Dict):
        ts = flow.get("timestamps", [])
        if len(ts) < 2:
            return None
        iats = np.diff(sorted(ts))
        iats = iats[iats > 0]  # remove zeros
        if len(iats) == 0:
            return None
        # Bin into histogram
        hist, _ = np.histogram(iats, bins=20, range=(0, min(iats.max(), 2.0)))
        hist = hist + 1  # Laplace smoothing
        return hist / hist.sum()

    hist_a = get_iat_hist(flow_a)
    hist_b = get_iat_hist(flow_b)

    if hist_a is None or hist_b is None:
        return 0.0

    # KL divergence (symmetric)
    kl = stats.entropy(hist_a, hist_b) + stats.entropy(hist_b, hist_a)
    # Convert to similarity score 0-1
    similarity = 1.0 / (1.0 + kl)
    return float(similarity)


def burst_pattern_similarity(flow_a: Dict, flow_b: Dict) -> Tuple[float, int]:
    """
    Cross-correlate burst patterns (packets per second).
    Returns (similarity, lag_seconds).
    """
    burst_a = np.array(flow_a.get("burst_pattern", []))
    burst_b = np.array(flow_b.get("burst_pattern", []))

    if len(burst_a) < 3 or len(burst_b) < 3:
        return 0.0, 0

    corr, lag = cross_correlate_series(burst_a, burst_b)
    # Normalize correlation to 0-1
    score = (corr + 1.0) / 2.0
    return float(np.clip(score, 0, 1)), lag


def volume_similarity(flow_a: Dict, flow_b: Dict) -> float:
    """Cosine similarity of volume time series."""
    vol_a = np.array(flow_a.get("volume_series", []))
    vol_b = np.array(flow_b.get("volume_series", []))

    if len(vol_a) == 0 or len(vol_b) == 0:
        return 0.0

    # Pad to same length
    max_len = max(len(vol_a), len(vol_b))
    vol_a = np.pad(vol_a.astype(float), (0, max_len - len(vol_a)))
    vol_b = np.pad(vol_b.astype(float), (0, max_len - len(vol_b)))

    # Cosine similarity
    dot = np.dot(vol_a, vol_b)
    norm = (np.linalg.norm(vol_a) * np.linalg.norm(vol_b)) + 1e-10
    return float(np.clip(dot / norm, 0, 1))


def packet_count_score(flow_a: Dict, flow_b: Dict) -> float:
    """Penalize large differences in packet count."""
    cnt_a = flow_a.get("packet_count", 0)
    cnt_b = flow_b.get("packet_count", 0)
    if cnt_a == 0 or cnt_b == 0:
        return 0.0
    ratio = min(cnt_a, cnt_b) / max(cnt_a, cnt_b)
    return float(ratio)


def duration_score(flow_a: Dict, flow_b: Dict) -> float:
    """Penalize large differences in flow duration."""
    dur_a = flow_a.get("duration", 0)
    dur_b = flow_b.get("duration", 0)
    if dur_a == 0 or dur_b == 0:
        return 0.0
    ratio = min(dur_a, dur_b) / (max(dur_a, dur_b) + 1e-10)
    return float(ratio)


def compute_confidence(flow_a: Dict, flow_b: Dict) -> Dict:
    """
    Master confidence scorer combining all techniques.
    Returns a detailed breakdown + final confidence %.
    """

    # Individual scores
    burst_score, lag = burst_pattern_similarity(flow_a, flow_b)
    vol_score = volume_similarity(flow_a, flow_b)
    iat_score = iat_similarity(flow_a, flow_b)
    pkt_score = packet_count_score(flow_a, flow_b)
    dur_score = duration_score(flow_a, flow_b)

    # Weighted combination (weights based on DeepCorr paper findings)
    weights = {
        "burst_correlation": 0.35,
        "volume_similarity": 0.25,
        "iat_similarity": 0.20,
        "packet_count": 0.10,
        "duration": 0.10,
    }

    scores = {
        "burst_correlation": burst_score,
        "volume_similarity": vol_score,
        "iat_similarity": iat_score,
        "packet_count": pkt_score,
        "duration": dur_score,
    }

    confidence = sum(scores[k] * weights[k] for k in weights)
    confidence = float(np.clip(confidence, 0, 1))

    return {
        "confidence": round(confidence * 100, 1),
        "lag_seconds": lag,
        "scores": {k: round(v * 100, 1) for k, v in scores.items()},
        "verdict": classify_confidence(confidence)
    }


def classify_confidence(conf: float) -> str:
    if conf >= 0.80:
        return "HIGH - Strong correlation detected"
    elif conf >= 0.55:
        return "MEDIUM - Possible correlation, needs more evidence"
    elif conf >= 0.30:
        return "LOW - Weak signal, inconclusive"
    else:
        return "NONE - No correlation detected"


def correlate_flows(entry_flows: List[Dict], exit_flows: List[Dict]) -> List[Dict]:
    """
    Cross-correlate all entry-side flows against all exit-side flows.
    Returns ranked list of likely circuit matches.
    """
    results = []

    print(f"[Correlator] Comparing {len(entry_flows)} entry flows × {len(exit_flows)} exit flows...")

    for ef in entry_flows:
        for xf in exit_flows:
            # Skip self-comparison or same-IP
            if ef.get("src_ip") == xf.get("src_ip"):
                continue
            if ef.get("packet_count", 0) < 5 or xf.get("packet_count", 0) < 5:
                continue

            result = compute_confidence(ef, xf)
            results.append({
                "entry_flow": ef["flow_id"],
                "entry_src": ef["src_ip"],
                "entry_dst": ef["dst_ip"],
                "exit_flow": xf["flow_id"],
                "exit_src": xf["src_ip"],
                "exit_dst": xf["dst_ip"],
                **result
            })

    # Sort by confidence descending
    results.sort(key=lambda x: x["confidence"], reverse=True)
    print(f"[Correlator] {len(results)} flow pairs evaluated. Top match: {results[0]['confidence']}% confidence" if results else "[Correlator] No results.")
    return results


def save_circuit_hypothesis(session_id: str, match: Dict, relay_db_result: Optional[Dict] = None):
    """Save a high-confidence match as a suspected circuit."""
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS suspected_circuits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                guard_fp TEXT,
                middle_fp TEXT,
                exit_fp TEXT,
                confidence REAL,
                evidence TEXT,
                created_at TEXT
            )
        """)
        c.execute("""
            INSERT INTO suspected_circuits (session_id, guard_fp, middle_fp, exit_fp, confidence, evidence, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (
            session_id,
            relay_db_result.get("guard_fp", "") if relay_db_result else "",
            "",
            relay_db_result.get("exit_fp", "") if relay_db_result else "",
            match["confidence"],
            json.dumps(match),
            datetime.utcnow().isoformat()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Correlator] DB save error: {e}")


def run_demo_correlation():
    """Run a demo correlation on synthetic data."""
    # Import here to avoid circular imports
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from analyser.pcap_analyser import generate_synthetic_flows

    flows = generate_synthetic_flows("demo")
    flow_dicts = [f.to_dict() for f in flows]

    # Split: entry flows = even indices, exit flows = odd indices (they're paired)
    entry_flows = flow_dicts[::2]
    exit_flows = flow_dicts[1::2]

    results = correlate_flows(entry_flows, exit_flows)

    print("\n=== Top Correlation Results ===")
    for r in results[:5]:
        print(f"\n  Entry: {r['entry_src']} → {r['entry_dst']}")
        print(f"  Exit:  {r['exit_src']} → {r['exit_dst']}")
        print(f"  Confidence: {r['confidence']}% | {r['verdict']}")
        print(f"  Lag: {r['lag_seconds']}s | Scores: {r['scores']}")

    return results


if __name__ == "__main__":
    print("=== OnionScope Correlation Engine ===")
    run_demo_correlation()