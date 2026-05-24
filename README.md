# OnionScope 🧅

A forensic traffic analysis tool for investigating TOR network activity. OnionScope correlates entry-side and exit-side network traffic to probabilistically identify the origin IP behind TOR-based sessions.

> **Disclaimer:** This tool produces probabilistic results only. Confidence scores reflect statistical likelihood, not legal proof. Use responsibly and only on networks you are authorised to analyse.

---

## What it does

TOR anonymises users by routing traffic through 3 relay nodes (guard → middle → exit), wrapping each hop in encryption. OnionScope attacks this by comparing traffic *patterns* — timing, burst shape, volume — on both ends of the circuit. If the patterns match, the flows likely belong to the same circuit.

Techniques used:
- **Burst cross-correlation** — sliding-window comparison of packets-per-second series
- **Volume fingerprinting** — cosine similarity of bytes-per-second series
- **IAT distribution matching** — KL divergence between inter-arrival time histograms
- **Combined confidence scoring** — weighted fusion of all signals

Reference: [DeepCorr (Nasr et al., CCS 2018)](https://arxiv.org/abs/1808.07285)

---

## Project Structure

```
unveil/
├── main.py              # FastAPI backend — REST API
├── tor_harvester.py     # Fetches live TOR relay data from Onionoo API
├── pcap_analyser.py     # Parses PCAP files, extracts flow signatures
├── correlator.py        # Core correlation engine + confidence scoring
├── onionscope-ui/       # React frontend dashboard
└── README.md
```

---

## Getting Started

### Backend

```bash
# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # Linux/Mac

# Install dependencies
pip install fastapi uvicorn python-multipart scapy numpy scipy scikit-learn requests stem

# Run the API
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API will be live at `http://localhost:8000`  
Interactive docs at `http://localhost:8000/docs`

### Frontend

```bash
cd onionscope-ui
npm install
npm start
```

Dashboard will open at `http://localhost:3000`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | System status |
| GET | `/api/relays/stats` | TOR relay summary |
| GET | `/api/relays/guards` | All guard nodes |
| GET | `/api/relays/exits` | All exit nodes |
| GET | `/api/relays/search?ip=X` | Check if IP is a TOR relay |
| POST | `/api/harvest` | Trigger fresh relay harvest |
| POST | `/api/analyse/demo` | Run demo correlation (no PCAP needed) |
| POST | `/api/analyse/pcap` | Upload and analyse real PCAP files |
| GET | `/api/circuits` | List suspected circuits |
| GET | `/api/report/{id}` | Get forensic report for a session |

---

## Demo Mode

No PCAP files needed to see the system working. The demo endpoint generates synthetic correlated TOR flows and runs the full correlation pipeline:

```bash
curl -X POST http://localhost:8000/api/analyse/demo
```

Expected output — 3 correctly identified circuits at 98–99% confidence.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, Uvicorn |
| Traffic analysis | Scapy, NumPy, SciPy |
| TOR relay data | Stem, Onionoo API |
| Database | SQLite |
| Frontend | React, D3.js |

---

## Author

**Sharish SK** — [github.com/sharishsk20](https://github.com/sharishsk20)
