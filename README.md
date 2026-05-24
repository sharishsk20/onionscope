# 🧅 OnionScope — TOR Forensic Analysis System
### TN Police Hackathon 2025 | Problem: TOR – Unveil : Peel the Onion

---

## Quick Start (Demo Mode — no PCAP needed)

```bash
# 1. Install dependencies
pip install stem requests scapy numpy scipy scikit-learn fastapi uvicorn python-multipart

# 2. Run backend API
cd backend
uvicorn api.main:app --host 0.0.0.0 --port 8000

# 3. Test demo analysis
curl -X POST http://localhost:8000/api/analyse/demo

# 4. Check relay stats
curl http://localhost:8000/api/relays/stats
```

## Docker (Full Stack)

```bash
cd docker
docker-compose up
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | /api/relays/stats   | TOR relay summary stats |
| GET    | /api/relays/guards  | All guard nodes |
| GET    | /api/relays/exits   | All exit nodes |
| GET    | /api/relays/search?ip=X | Check if IP is TOR relay |
| POST   | /api/harvest        | Trigger fresh relay harvest |
| POST   | /api/analyse/demo   | Run demo correlation |
| POST   | /api/analyse/pcap   | Upload + analyse PCAP files |
| GET    | /api/circuits       | List suspected circuits |
| GET    | /api/report/{id}    | Generate forensic report |

## Architecture

```
TOR Onionoo API
      │
      ▼
tor_harvester.py    ← Fetches 7000+ relay details every hour
      │
      ▼
onionscope.db       ← SQLite (relay fingerprints, guard/exit flags, countries)
      │
pcap_analyser.py    ← Parses PCAP files → extracts flow signatures
      │
correlator.py       ← Cross-correlates entry ↔ exit flows → confidence score
      │
main.py (FastAPI)   ← REST API serving all above
      │
OnionScope.jsx      ← React dashboard (4 tabs: dashboard, correlator, relays, report)
```

## Correlation Algorithm

The core innovation is multi-signal traffic correlation:

1. **Burst Cross-Correlation** (35% weight)  
   Sliding-window cross-correlation of packet-per-second time series.
   Matches burst patterns between entry and exit side.

2. **Volume Similarity** (25% weight)  
   Cosine similarity of bytes-per-second series.

3. **IAT Distribution** (20% weight)  
   KL divergence between inter-arrival time histograms.

4. **Packet Count Ratio** (10% weight)  
   Penalizes large differences in packet count.

5. **Duration Match** (10% weight)  
   Penalizes large differences in flow duration.

**Reference:** DeepCorr: Strong Flow Correlation Attacks on Tor (Nasr et al., CCS 2018)

## Disclaimer

This system produces probabilistic results. Confidence scores indicate
statistical likelihood, NOT legal proof. All findings must be validated
through lawful investigative procedures.
