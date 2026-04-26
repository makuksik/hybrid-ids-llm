import asyncio
import threading
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from .sniffer import start_sniffer

event_queue = None
loop = None

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

async def event_generator():
    while True:
        data = await event_queue.get()
        yield f"data: {json.dumps(data)}\n\n"

@app.get("/alerts/stream")
async def stream_alerts():
    return StreamingResponse(event_generator(), media_type="text/event-stream")
