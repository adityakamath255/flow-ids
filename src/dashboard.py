from pathlib import Path
import asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager

import json
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

from .ids import ClassifiedFlow


class Dashboard:
    def __init__(self, log_dir: Path):
        self._clients: list[asyncio.Queue] = []
        self._log_dir = log_dir
        self._loop = None

        @asynccontextmanager
        async def lifespan(_):
            self._loop = asyncio.get_event_loop()
            yield

        self.app = FastAPI(lifespan=lifespan)

        self._register_routes()

    def push(self, classified_flow: ClassifiedFlow):
        data = json.dumps(
            {
                "flow": classified_flow.flow,
                "prediction": classified_flow.prediction
            },
            default=float
        )

        if self._loop is None:
            return

        else:
            for q in list(self._clients):
                self._loop.call_soon_threadsafe(q.put_nowait, data)

    def _register_routes(self):
        app = self.app

        @app.get("/", response_class=HTMLResponse)
        async def index():
            html_path = Path(__file__).parent / "dashboard.html"
            return html_path.read_text()

        @app.get("/api/events")
        async def events():
            q = asyncio.Queue()
            self._clients.append(q)

            async def stream():
                try:
                    while True:
                        data = await q.get()
                        yield {"data": data}
                except asyncio.CancelledError:
                    pass
                finally:
                    self._clients.remove(q)

            return EventSourceResponse(stream())

        @app.get("/api/sessions")
        async def sessions():
            files = sorted(
                self._log_dir.glob("*.jsonl"),
                reverse=True
            )
            return [f.name for f in files]

        @app.get("/api/history")
        async def history(session: str):
            path = self._log_dir / session
            if not path.exists() or not path.is_relative_to(self._log_dir):
                return []
            else:
                return [
                    json.loads(line)
                    for line in path.read_text().splitlines()
                ]
