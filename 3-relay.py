#!/usr/bin/env python3
"""ini-pc relay - ponte de sessao entre o app Ini no PC e a operacao da Ini.

Somente memoria: nada e persistido. O PC inicia a sessao (POST /api/session),
mostra um codigo de 6 digitos ao dono, e faz long-poll por comandos.
A operacao entra na sessao com o codigo (POST /api/join) e enfileira comandos.
A politica do que pode executar e aplicada no PC, nunca aqui.

Stdlib only. Bind 0.0.0.0:$PORT (Render) ou 127.0.0.1 em testes.
"""
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_TTL_MIN = 240
POLL_WAIT_S = 25
MAX_BODY = 256 * 1024
MAX_QUEUE = 100
MAX_RESULTS = 500
MAX_KIND_LEN = 32
MAX_PAYLOAD_BYTES = 96 * 1024
JOIN_FAIL_LIMIT = 5
JOIN_FAIL_WINDOW_S = 600
RATE_WINDOW_S = 60
RATE_MAX_PER_WINDOW = 600

ALLOWED_KINDS = {
    "echo", "system_info", "list_dir", "read_file", "write_file",
    "move_path", "delete_path", "run_program", "search_files", "chat",
}

lock = threading.RLock()
sessions = {}          # sid -> Session
codes = {}             # 6-digit code -> sid
join_fails = {}        # ip -> [ts,...]
rate_hits = {}         # ip -> [ts,...]


def now():
    return time.time()


class Session:
    __slots__ = ("sid", "code", "pc_secret", "join_token", "created", "ends_at",
                 "cmd_seq", "commands", "res_seq", "results", "cond", "closed")

    def __init__(self, sid, code, pc_secret, ttl_min):
        self.sid = sid
        self.code = code
        self.pc_secret = pc_secret
        self.join_token = None
        self.created = now()
        self.ends_at = self.created + min(ttl_min, MAX_TTL_MIN) * 60
        self.cmd_seq = 0
        self.commands = deque()
        self.res_seq = 0
        self.results = deque()
        self.cond = threading.Condition()
        self.closed = False

    def expired(self):
        return self.closed or now() > self.ends_at


def prune():
    with lock:
        dead = [sid for sid, s in sessions.items() if s.expired()]
        for sid in dead:
            s = sessions.pop(sid, None)
            if s:
                codes.pop(s.code, None)
                with s.cond:
                    s.cond.notify_all()
        cutoff = now() - RATE_WINDOW_S
        for table in (join_fails, rate_hits):
            for ip in list(table):
                table[ip] = [t for t in table[ip] if t > cutoff]
                if not table[ip]:
                    del table[ip]


def rate_ok(ip):
    with lock:
        hits = rate_hits.setdefault(ip, [])
        if len(hits) >= RATE_MAX_PER_WINDOW:
            return False
        hits.append(now())
        return True


def join_blocked(ip):
    with lock:
        fails = join_fails.get(ip, [])
        return len(fails) >= JOIN_FAIL_LIMIT


def join_fail(ip):
    with lock:
        join_fails.setdefault(ip, []).append(now())


def join_ok(ip):
    with lock:
        join_fails.pop(ip, None)


def sweeper():
    while True:
        time.sleep(30)
        prune()


class Handler(BaseHTTPRequestHandler):
    server_version = "inipc-relay/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet: no request bodies in logs
        pass

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _get_session(self, data, with_secret=True):
        sid = str(data.get("session_id", ""))[:64]
        secret = str(data.get("pc_secret", ""))[:128]
        with lock:
            s = sessions.get(sid)
        if not s or s.expired():
            return None
        if with_secret and not hmac.compare_digest(secret, s.pc_secret):
            return None
        return s

    def do_GET(self):
        prune()
        if self.path in ("/", "/healthz"):
            self._send(200, {"ok": True, "service": "ini-pc-relay",
                             "sessions": len(sessions)})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        prune()
        ip = self._client_ip()
        if not rate_ok(ip):
            self._send(429, {"error": "rate_limited"})
            return
        route = self.path.split("?")[0]
        if route not in ("/api/session", "/api/join", "/api/poll", "/api/result",
                         "/api/enqueue", "/api/state", "/api/extend", "/api/close"):
            self._send(404, {"error": "not_found"})
            return
        data = self._read_json()
        if data is None:
            self._send(400, {"error": "bad_json"})
            return
        handler = getattr(self, "r_" + route.rsplit("/", 1)[1])
        handler(data, ip)

    # --- lado do PC ----------------------------------------------------
    def r_session(self, data, ip):
        try:
            ttl = int(data.get("ttl_minutes", 30))
        except (TypeError, ValueError):
            ttl = 30
        ttl = max(1, min(ttl, MAX_TTL_MIN))
        with lock:
            while True:
                code = "".join(secrets.choice("0123456789") for _ in range(6))
                if code not in codes:
                    break
            sid = secrets.token_urlsafe(18)
            pc_secret = secrets.token_urlsafe(24)
            s = Session(sid, code, pc_secret, ttl)
            sessions[sid] = s
            codes[code] = sid
        self._send(200, {"session_id": sid, "pc_secret": pc_secret, "code": code,
                         "session_ends_at": s.ends_at})

    def r_poll(self, data, ip):
        s = self._get_session(data)
        if not s:
            self._send(401, {"error": "invalid_session"})
            return
        try:
            since = int(data.get("since", 0))
        except (TypeError, ValueError):
            since = 0
        deadline = now() + POLL_WAIT_S
        with s.cond:
            while True:
                cmds = [c for c in s.commands if c["seq"] > since]
                if cmds or s.expired() or now() >= deadline:
                    break
                s.cond.wait(timeout=max(0.1, deadline - now()))
        cmds = [c for c in s.commands if c["seq"] > since]
        self._send(200, {"commands": cmds, "session_expired": s.expired(),
                         "session_ends_at": s.ends_at})

    def r_result(self, data, ip):
        s = self._get_session(data)
        if not s:
            self._send(401, {"error": "invalid_session"})
            return
        results = data.get("results", [])
        if not isinstance(results, list):
            results = []
        accepted = 0
        with s.cond:
            for r in results[:50]:
                if not isinstance(r, dict):
                    continue
                blob = json.dumps(r, ensure_ascii=False)
                if len(blob) > 200 * 1024:
                    r = {"command_id": r.get("command_id"), "status": "error",
                         "output": "resultado grande demais, truncado no relay"}
                s.res_seq += 1
                r = dict(r)
                r["seq"] = s.res_seq
                s.results.append(r)
                while len(s.results) > MAX_RESULTS:
                    s.results.popleft()
                accepted += 1
            s.cond.notify_all()
        self._send(200, {"accepted": accepted})

    def r_extend(self, data, ip):
        s = self._get_session(data)
        if not s:
            self._send(401, {"error": "invalid_session"})
            return
        try:
            add = int(data.get("add_minutes", 15))
        except (TypeError, ValueError):
            add = 15
        add = max(1, min(add, MAX_TTL_MIN))
        with lock:
            s.ends_at = min(now() + add * 60, s.created + MAX_TTL_MIN * 60 * 24)
            s.ends_at = min(s.ends_at, now() + MAX_TTL_MIN * 60)
            ends = s.ends_at
        with s.cond:
            s.cond.notify_all()
        self._send(200, {"session_ends_at": ends})

    def r_close(self, data, ip):
        s = self._get_session(data)
        if not s:
            self._send(200, {"closed": True})
            return
        with lock:
            s.closed = True
        with s.cond:
            s.cond.notify_all()
        prune()
        self._send(200, {"closed": True})

    # --- lado da Ini ---------------------------------------------------
    def r_join(self, data, ip):
        if join_blocked(ip):
            self._send(429, {"error": "join_blocked"})
            return
        code = str(data.get("code", "")).strip()[:8]
        with lock:
            sid = codes.get(code)
            s = sessions.get(sid) if sid else None
        if not s or s.expired():
            join_fail(ip)
            self._send(401, {"error": "invalid_code"})
            return
        join_ok(ip)
        with lock:
            if not s.join_token:
                s.join_token = secrets.token_urlsafe(24)
            token = s.join_token
        self._send(200, {"join_token": token, "session_id": s.sid,
                         "session_ends_at": s.ends_at})

    def _get_joined(self, data):
        token = str(data.get("join_token", ""))[:128]
        sid = str(data.get("session_id", ""))[:64]
        with lock:
            s = sessions.get(sid)
        if not s or s.expired() or not s.join_token:
            return None
        if not hmac.compare_digest(token, s.join_token):
            return None
        return s

    def r_enqueue(self, data, ip):
        s = self._get_joined(data)
        if not s:
            self._send(401, {"error": "invalid_join"})
            return
        kind = str(data.get("kind", ""))[:MAX_KIND_LEN]
        payload = data.get("payload", {})
        if kind not in ALLOWED_KINDS or not isinstance(payload, dict):
            self._send(400, {"error": "bad_command"})
            return
        if len(json.dumps(payload, ensure_ascii=False)) > MAX_PAYLOAD_BYTES:
            self._send(400, {"error": "payload_too_big"})
            return
        note = str(data.get("note", ""))[:500]
        with s.cond:
            pending = [c for c in s.commands if not c.get("done")]
            if len(pending) >= MAX_QUEUE:
                self._send(429, {"error": "queue_full"})
                return
            s.cmd_seq += 1
            cmd = {"id": secrets.token_urlsafe(8), "seq": s.cmd_seq,
                   "kind": kind, "payload": payload, "note": note,
                   "queued_at": now()}
            s.commands.append(cmd)
            while len(s.commands) > MAX_QUEUE:
                s.commands.popleft()
            s.cond.notify_all()
        self._send(200, {"command_id": cmd["id"], "seq": cmd["seq"]})

    def r_state(self, data, ip):
        s = self._get_joined(data)
        if not s:
            self._send(401, {"error": "invalid_join"})
            return
        try:
            since = int(data.get("since", 0))
        except (TypeError, ValueError):
            since = 0
        deadline = now() + POLL_WAIT_S
        with s.cond:
            while True:
                res = [r for r in s.results if r["seq"] > since]
                if res or s.expired() or now() >= deadline:
                    break
                s.cond.wait(timeout=max(0.1, deadline - now()))
        res = [r for r in s.results if r["seq"] > since]
        self._send(200, {"results": res, "session_expired": s.expired(),
                         "session_ends_at": s.ends_at})


def main():
    port = int(os.environ.get("PORT", "8787"))
    host = os.environ.get("BIND", "0.0.0.0")
    threading.Thread(target=sweeper, daemon=True).start()
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"ini-pc-relay listening on {host}:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
