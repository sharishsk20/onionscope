# OnionScope - FastAPI Backend (Flat Folder Version for E:\unveil)
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import uuid
import sqlite3
import shutil
from datetime import datetime
from typing import Optional

from tor_harvester import harvest, get_relay_stats, get_guards, get_exits, search_relay, init_db
from pcap_analyser import analyse_file, generate_synthetic_flows
from correlator import correlate_flows, save_circuit_hypothesis

DB_PATH = os.path.join(BASE_DIR, "onionscope.db")

app = FastAPI(title="OnionScope API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


@app.get("/")
def root():
    return {"system": "OnionScope", "status": "online", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/relays/stats")
def relay_stats():
    try:
        return get_relay_stats()
    except Exception as e:
        return {"error": str(e), "total_relays": 0, "guard_nodes": 0, "exit_nodes": 0}


@app.get("/api/relays/guards")
def relay_guards():
    return {"guards": get_guards()}


@app.get("/api/relays/exits")
def relay_exits():
    return {"exits": get_exits()}


@app.get("/api/relays/search")
def relay_search(ip: str):
    result = search_relay(ip)
    if result:
        return {"found": True, "relay": result}
    return {"found": False, "ip": ip}


@app.post("/api/harvest")
def trigger_harvest(background_tasks: BackgroundTasks):
    background_tasks.add_task(harvest)
    return {"status": "harvesting", "message": "Harvest started. Check /api/relays/stats in 30s."}


@app.post("/api/analyse/demo")
def analyse_demo():
    flows = generate_synthetic_flows("demo")
    flow_dicts = [f.to_dict() for f in flows]
    entry_flows = flow_dicts[::2]
    exit_flows = flow_dicts[1::2]
    results = correlate_flows(entry_flows, exit_flows)
    return {
        "session_id": str(uuid.uuid4())[:8],
        "mode": "synthetic_demo",
        "total_flows": len(flow_dicts),
        "entry_flows": len(entry_flows),
        "exit_flows": len(exit_flows),
        "correlation_pairs": len(results),
        "top_matches": results[:5],
        "analysed_at": datetime.utcnow().isoformat()
    }


@app.post("/api/analyse/pcap")
async def analyse_pcap(
    entry_pcap: UploadFile = File(...),
    exit_pcap: Optional[UploadFile] = File(None)
):
    session_id = str(uuid.uuid4())[:8]
    tmp_dir = tempfile.mkdtemp()
    try:
        entry_path = os.path.join(tmp_dir, "entry.pcap")
        with open(entry_path, "wb") as f:
            f.write(await entry_pcap.read())
        entry_flows = analyse_file(entry_path)["flows"]

        if exit_pcap:
            exit_path = os.path.join(tmp_dir, "exit.pcap")
            with open(exit_path, "wb") as f:
                f.write(await exit_pcap.read())
            exit_flows = analyse_file(exit_path)["flows"]
        else:
            half = len(entry_flows) // 2
            exit_flows = entry_flows[half:]
            entry_flows = entry_flows[:half]

        results = correlate_flows(entry_flows, exit_flows)
        for match in results[:3]:
            if match["confidence"] >= 60:
                save_circuit_hypothesis(session_id, match)

        return {
            "session_id": session_id,
            "mode": "real_pcap",
            "entry_flows": len(entry_flows),
            "exit_flows": len(exit_flows),
            "top_matches": results[:10],
            "analysed_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/api/circuits")
def get_circuits():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM suspected_circuits ORDER BY id DESC LIMIT 50")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return {"circuits": rows}
    except Exception as e:
        return {"circuits": [], "error": str(e)}


@app.get("/api/report/{session_id}")
def generate_report(session_id: str):
    return {
        "report": {
            "session_id": session_id,
            "generated_at": datetime.utcnow().isoformat(),
            "system": "OnionScope v1.0",
            "disclaimer": "Probabilistic results only. Not legal proof.",
            "chain_of_custody": {
                "analyst": "OnionScope Automated System",
                "method": "Traffic timing correlation + TOR relay mapping",
                "references": [
                    "DeepCorr: Strong Flow Correlation Attacks on Tor (Nasr et al., 2018)",
                    "TOR Onionoo API (metrics.torproject.org)"
                ]
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)