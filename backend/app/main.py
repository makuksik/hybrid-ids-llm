import asyncio
import threading
import json
import subprocess
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
from sniffer import start_sniffer

event_queue = None
loop = None

class BlockRequest(BaseModel):
    ip: str

def sniffer_callback(data):
    if loop and event_queue:
        loop.call_soon_threadsafe(event_queue.put_nowait, data)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global event_queue, loop
    event_queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    thread = threading.Thread(target=start_sniffer, args=(sniffer_callback,), daemon=True)
    thread.start()
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def event_generator():
    while True:
        data = await event_queue.get()
        yield f"data: {json.dumps(data)}\n\n"

@app.post("/block-ip")
async def block_ip(req: BlockRequest):
    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f'name="NetSentinel_Block_{req.ip}"',
            "dir=in", "action=block", f"remoteip={req.ip}"
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return {"status": "success", "message": f"Zablokowano IP: {req.ip}"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": "Brak uprawnień administratora."}

@app.get("/alerts/stream")
async def stream_alerts():
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/alerts/count")
async def get_alerts_count():
    try:
        conn = sqlite3.connect("net_sentinel.db")
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")

        total_count = cursor.fetchone()[0]

        conn.close()
        return {"status": "success", "total_saved_alerts": total_count}
    except Exception as e:
        return {"status": "error", "message": str(e)}
