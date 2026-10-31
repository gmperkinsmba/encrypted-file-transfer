#!/usr/bin/env python3
"""Loopback-only, resumable file handoff with verified local receipt."""
import hashlib, json, os, secrets, shutil, socketserver, sys, threading, time
import struct
from relay_core import RelayError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote

ROOT = Path(__file__).resolve().parent
if os.environ.get("TELEPORT_DATA"):
    DATA = Path(os.environ["TELEPORT_DATA"]).expanduser()
elif sys.platform == "darwin":
    DATA = Path.home() / "Library" / "Application Support" / "Teleport"
else:
    DATA = Path.home() / ".local" / "share" / "teleport"
MAX_FILE = 128 * 1024**2
MAX_BODY = 2 * 1024**2 + 4096
MAX_RELAY_BODY = 32 * 1024**2 + 65536
CHUNK = 1024**2
PORT = int(os.environ.get("TELEPORT_PORT", "8311"))
if DATA.is_symlink(): raise RuntimeError("Teleport runtime directory must not be a symlink")
try: DATA.resolve().relative_to(ROOT)
except ValueError: pass
else: raise RuntimeError("Teleport runtime must be outside the application folder")
DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
if DATA.is_symlink() or not DATA.is_dir(): raise RuntimeError("Teleport runtime must be a real directory")
os.chmod(DATA, 0o700)
LOCK = threading.RLock()
SESSION = secrets.token_urlsafe(32)

def safe_dir(tid):
    if len(tid) != 32 or any(c not in "0123456789abcdef" for c in tid):
        raise ValueError("Invalid transfer ID")
    return DATA / tid

def read_manifest(tid):
    d = safe_dir(tid)
    p = d / "manifest.json"
    if not p.is_file(): raise FileNotFoundError
    return json.loads(p.read_text())

def save_manifest(tid, m):
    d=safe_dir(tid); p=d/"manifest.json"; tmp=d/"manifest.tmp"
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,"w") as out: out.write(json.dumps(m)); out.flush(); os.fsync(out.fileno())
    tmp.replace(p)

class Handler(BaseHTTPRequestHandler):
    server_version = "Teleport/1"
    def log_message(self, *_): pass
    def send_json(self, status, obj):
        b=json.dumps(obj).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(b)
    def valid_origin(self):
        port=self.server.server_port
        host=self.headers.get("Host","")
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"): return False
        origin=self.headers.get("Origin")
        return origin in (f"http://127.0.0.1:{port}", f"http://localhost:{port}") and secrets.compare_digest(self.headers.get("X-Teleport-Request",""),SESSION)
    def valid_get_boundary(self):
        port=self.server.server_port
        host=self.headers.get("Host",""); origin=self.headers.get("Origin")
        hosts=(f"127.0.0.1:{port}",f"localhost:{port}")
        origins=(f"http://127.0.0.1:{port}",f"http://localhost:{port}")
        return host in hosts and (origin is None or origin in origins) and self.headers.get("Sec-Fetch-Site") in ("same-origin","none") and secrets.compare_digest(self.headers.get("X-Teleport-Request",""),SESSION)
    def body(self, limit=MAX_BODY):
        n=int(self.headers.get("Content-Length","-1"))
        if n < 0 or n > limit: raise ValueError("Request body is too large")
        raw=self.rfile.read(n)
        if len(raw)!=n: raise ValueError("Incomplete request body")
        return raw
    def do_GET(self):
        port=self.server.server_port
        if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"): return self.send_json(403,{"error":"Host check failed"})
        path=self.path.split("?",1)[0]
        if path == "/":
            b=(ROOT/"index.html").read_bytes(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Content-Security-Policy","default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"); self.send_header("Referrer-Policy","no-referrer"); self.end_headers(); self.wfile.write(b); return
        if path == "/app.css" or path == "/app.js":
            p=ROOT/path[1:]; b=p.read_bytes(); self.send_response(200); self.send_header("Content-Type","text/css" if p.suffix==".css" else "text/javascript"); self.send_header("Content-Length",str(len(b))); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Cache-Control","no-cache"); self.end_headers(); self.wfile.write(b); return
        if path=="/api/session": return self.send_json(200,{"token":SESSION})
        if path=="/api/relay/status":
            if not self.valid_get_boundary(): return self.send_json(403,{"error":"Request boundary check failed"})
            from remote_service import settings_status
            return self.send_json(200,settings_status())
        try:
            parts=path.strip("/").split("/"); tid=parts[2]; m=read_manifest(tid)
            if m["expires"] < time.time(): return self.send_json(410,{"error":"Transfer expired"})
            if len(parts)==5 and parts[3]=="download":
                if not self.valid_get_boundary(): return self.send_json(403,{"error":"Request boundary check failed"})
                code=self.headers.get("X-Recipient-Code",""); label=unquote(self.headers.get("X-Recipient-Name","")).strip().casefold()
                if label!=m["recipient"].casefold() or not secrets.compare_digest(hashlib.sha256(code.encode()).hexdigest(),m["code_hash"]): return self.send_json(403,{"error":"Recipient authentication failed"})
                i=int(parts[4]); f=m["files"][i]
                if not m.get("verified"): return self.send_json(409,{"error":"Transfer is not verified"})
                self.send_response(200); self.send_header("Content-Type","application/octet-stream"); fallback=''.join(c if 32<=ord(c)<127 and c not in '"\\' else '_' for c in f["name"]); self.send_header("Content-Disposition","attachment; filename=\""+fallback+"\"; filename*=UTF-8''"+quote(f["name"],safe="")); self.send_header("Content-Length",str(f["size"])); self.end_headers()
                for n in range(f["chunks"]): self.wfile.write((safe_dir(tid)/f"{i}.{n}.part").read_bytes())
                return
            return self.send_json(404,{"error":"Not found"})
        except FileNotFoundError: return self.send_json(404,{"error":"Transfer not found"})
        except Exception: return self.send_json(400,{"error":"Invalid request"})
        self.send_json(404,{"error":"Not found"})
    def do_POST(self):
        with LOCK: return self._do_post()
    def _do_post(self):
        if not self.valid_origin(): return self.send_json(403,{"error":"Request boundary check failed"})
        try:
            if self.path=="/api/relay/configure":
                data=json.loads(self.body(65536))
                if not isinstance(data,dict): raise ValueError("Invalid settings")
                from remote_service import configure
                result=configure(data.get("owner",""),data.get("repo",""),data.get("channel",""),data.get("recipient",""),data.get("auth_mode",""),data.get("token"),data.get("pairing_key"))
                return self.send_json(200,result)
            if self.path=="/api/relay/remove-settings":
                self.body(1024)
                from remote_service import remove_settings
                return self.send_json(200,remove_settings())
            if self.path=="/api/relay/remove-pairing-key":
                self.body(1024)
                from remote_service import remove_pairing_key
                return self.send_json(200,remove_pairing_key())
            if self.path=="/api/relay/send":
                raw=self.body(MAX_RELAY_BODY)
                if len(raw)<4: raise ValueError("Invalid selected files")
                hlen=struct.unpack(">I",raw[:4])[0]
                if hlen>65536 or len(raw)<4+hlen: raise ValueError("Invalid selected files")
                metadata=json.loads(raw[4:4+hlen])
                if not isinstance(metadata,dict): raise ValueError("Invalid selected files")
                from remote_service import send_selected
                return self.send_json(201,send_selected(metadata,raw[4+hlen:]))
            if self.path=="/api/relay/receive":
                data=json.loads(self.body(8192))
                if not isinstance(data,dict): raise ValueError("Invalid receive request")
                from remote_service import receive_once
                result=receive_once(data.get("transfer_id",""),data.get("asset",""),data.get("recipient"))
                return self.send_json(200,result)
            if self.path=="/api/relay/available":
                data=json.loads(self.body(8192))
                if not isinstance(data,dict): raise ValueError("Invalid availability request")
                from remote_service import transfer_available
                return self.send_json(200,{"available":transfer_available(data.get("transfer_id",""),data.get("asset",""))})
            if self.path=="/api/relay/receipt":
                data=json.loads(self.body(8192))
                if not isinstance(data,dict): raise ValueError("Invalid receipt request")
                from remote_service import check_receipt
                return self.send_json(200,check_receipt(data.get("transfer_id",""),data.get("asset","")))
            if self.path=="/api/relay/cleanup":
                data=json.loads(self.body(8192))
                if not isinstance(data,dict): raise ValueError("Invalid cleanup request")
                from remote_service import relay
                result=relay().cleanup(data.get("transfer_id",""),data.get("asset",""))
                return self.send_json(200,result)
            if self.path=="/api/transfers":
                x=json.loads(self.body())
                if not isinstance(x,dict): raise ValueError("Invalid transfer details")
                recipient=x.get("recipient",""); hours=x.get("hours")
                if not isinstance(recipient,str): raise ValueError("Invalid recipient")
                recipient=recipient.strip()
                if not 1<=len(recipient)<=160 or type(hours) is not int or not 1<=hours<=168: raise ValueError("Enter a recipient and expiry from 1 to 168 hours")
                files=x.get("files",[])
                if not isinstance(files,list) or not files or len(files)>100: raise ValueError("Choose 1 to 100 files")
                tid=secrets.token_hex(16); code=secrets.token_urlsafe(18); d=safe_dir(tid); d.mkdir(mode=0o700)
                normalized=[]; total=0
                for f in files:
                    if not isinstance(f,dict): raise ValueError("Invalid file details")
                    raw_name=f.get("name","")
                    if not isinstance(raw_name,str): raise ValueError("Invalid file name")
                    name=Path(raw_name.replace("\\","/")).name
                    size=f.get("size"); sha=f.get("sha256","")
                    if not name or len(name)>240 or any(ord(c)<32 for c in name) or type(size) is not int or size<0 or size>MAX_FILE or not isinstance(sha,str) or len(sha)!=64 or any(c not in "0123456789abcdef" for c in sha): raise ValueError("Invalid file details")
                    total+=size
                    normalized.append({"name":name,"size":size,"sha256":sha,"chunks":(size+CHUNK-1)//CHUNK,"received":[]})
                if total>MAX_FILE: raise ValueError("Transfer total exceeds 128 MiB")
                m={"recipient":recipient,"code_hash":hashlib.sha256(code.encode()).hexdigest(),"expires":time.time()+hours*3600,"files":normalized,"received":False,"receipt":None}
                save_manifest(tid,m); return self.send_json(201,{"id":tid,"code":code,"recipient":recipient,"expires":m["expires"],"files":normalized})
            parts=self.path.strip("/").split("/"); tid=parts[2]; m=read_manifest(tid)
            if len(parts)==4 and parts[3]=="details":
                if m["expires"]<time.time(): return self.send_json(410,{"error":"Transfer expired"})
                data=json.loads(self.body())
                if not isinstance(data,dict) or not isinstance(data.get("recipient"),str) or not isinstance(data.get("code"),str): raise ValueError("Invalid recipient details")
                code=data["code"]; label=data["recipient"].strip().casefold()
                if label!=m["recipient"].casefold() or not secrets.compare_digest(hashlib.sha256(code.encode()).hexdigest(),m["code_hash"]): return self.send_json(403,{"error":"Recipient authentication failed"})
                return self.send_json(200,{k:m.get(k) for k in ("recipient","expires","files","received","receipt","verified")})
            if m["expires"]<time.time(): return self.send_json(410,{"error":"Transfer expired"})
            data=json.loads(self.body()) if self.path.endswith("/verify") or self.path.endswith("/receive") or self.path.endswith("/cleanup") else None
            if data is not None and not isinstance(data,dict): raise ValueError("Invalid request")
            code=data.get("code","") if data else self.headers.get("X-Recipient-Code","")
            if not isinstance(code,str): raise ValueError("Invalid recipient code")
            if not secrets.compare_digest(hashlib.sha256(code.encode()).hexdigest(),m["code_hash"]): return self.send_json(403,{"error":"Recipient code is incorrect"})
            label=data.get("recipient","") if data else unquote(self.headers.get("X-Recipient-Name",""))
            if not isinstance(label,str): raise ValueError("Invalid recipient name")
            label=label.strip().casefold()
            if label!=m["recipient"].casefold(): return self.send_json(403,{"error":"Recipient name does not match"})
            if len(parts)==5 and parts[3]=="file" and parts[4].isdigit():
                i=int(parts[4]); f=m["files"][i]; idx=int(self.headers.get("X-Chunk-Index","-1")); raw=self.body(CHUNK)
                if idx<0 or idx>=f["chunks"] or len(raw)>CHUNK: raise ValueError("Invalid chunk")
                expected=min(CHUNK,f["size"]-idx*CHUNK)
                if len(raw)!=expected: raise ValueError("Chunk size does not match")
                sha=hashlib.sha256(raw).hexdigest(); claimed=self.headers.get("X-Chunk-SHA256","")
                if not secrets.compare_digest(sha,claimed): return self.send_json(422,{"error":"Chunk hash mismatch"})
                fp=safe_dir(tid)/f"{i}.{idx}.part"
                if idx in f["received"]:
                    if hashlib.sha256(fp.read_bytes()).hexdigest()!=sha: return self.send_json(409,{"error":"Stored chunk differs; transfer blocked"})
                else:
                    tmp=fp.with_suffix(".tmp"); fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
                    with os.fdopen(fd,"wb") as out: out.write(raw); out.flush(); os.fsync(out.fileno())
                    tmp.replace(fp); f["received"].append(idx); save_manifest(tid,m)
                return self.send_json(200,{"received":sorted(f["received"])})
            if len(parts)==4 and parts[3]=="verify":
                for i,f in enumerate(m["files"]):
                    if len(f["received"])!=f["chunks"]: return self.send_json(409,{"error":"Upload is incomplete"})
                    h=hashlib.sha256()
                    for n in range(f["chunks"]): h.update((safe_dir(tid)/f"{i}.{n}.part").read_bytes())
                    if h.hexdigest()!=f["sha256"]: return self.send_json(422,{"error":"File hash mismatch; receipt blocked"})
                m["verified"]=True; save_manifest(tid,m); return self.send_json(200,{"verified":True})
            if len(parts)==4 and parts[3]=="receive":
                if not m.get("verified"): return self.send_json(409,{"error":"Verify the transfer first"})
                received=data.get("hashes",[])
                if not isinstance(received,list) or len(received)!=len(m["files"]) or any(not isinstance(h,str) for h in received): return self.send_json(422,{"error":"Browser receipt is incomplete"})
                for i,f in enumerate(m["files"]):
                    h=hashlib.sha256()
                    for n in range(f["chunks"]): h.update((safe_dir(tid)/f"{i}.{n}.part").read_bytes())
                    if h.hexdigest()!=f["sha256"] or received[i]!=f["sha256"]: return self.send_json(422,{"error":"Received bytes do not match; receipt blocked"})
                m["received"]=True; m["receipt"]={"recipient":m["recipient"],"received_at":time.time(),"files":[{"name":f["name"],"size":f["size"],"expected_sha256":f["sha256"],"received_sha256":received[i]} for i,f in enumerate(m["files"])]}; save_manifest(tid,m); return self.send_json(200,{"receipt":m["receipt"]})
            if len(parts)==4 and parts[3]=="cleanup":
                if not m.get("received") or not m.get("receipt"): return self.send_json(409,{"error":"Verified receipt is required before cleanup"})
                for i,f in enumerate(m["files"]):
                    h=hashlib.sha256()
                    for n in range(f["chunks"]): h.update((safe_dir(tid)/f"{i}.{n}.part").read_bytes())
                    if h.hexdigest()!=f["sha256"]: return self.send_json(422,{"error":"Stored bytes changed; cleanup blocked"})
                shutil.rmtree(safe_dir(tid)); return self.send_json(200,{"cleaned":True})
            return self.send_json(404,{"error":"Not found"})
        except RelayError as exc: return self.send_json(400,{"error":str(exc)})
        except (ValueError,KeyError,IndexError,json.JSONDecodeError,RecursionError): return self.send_json(400,{"error":"Invalid request"})
        except FileNotFoundError: return self.send_json(404,{"error":"Transfer not found"})
        except Exception: return self.send_json(500,{"error":"Request could not be completed"})
    def _method_not_allowed(self):
        if self.headers.get("Host") not in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"):
            self.send_response(403); self.end_headers(); return
        self.send_response(405); self.end_headers()
    do_HEAD = _method_not_allowed
    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_OPTIONS = _method_not_allowed
    do_CONNECT = _method_not_allowed
    do_TRACE = _method_not_allowed

class LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # Bind a numeric loopback address directly; do not resolve a hostname.
        socketserver.TCPServer.server_bind(self)
        self.server_port = self.server_address[1]


def make_server(port: int = 0, data_dir: str | Path | None = None):
    """Build the bounded loopback HTTP server used by the desktop host."""
    global DATA
    if data_dir is not None:
        DATA = Path(data_dir).expanduser()
        if DATA.is_symlink(): raise ValueError("Teleport runtime directory must not be a symlink")
        try: DATA.resolve().relative_to(ROOT)
        except ValueError: pass
        else: raise ValueError("Teleport runtime must be outside the application folder")
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        if DATA.is_symlink() or not DATA.is_dir(): raise ValueError("Teleport runtime must be a real directory")
        os.chmod(DATA, 0o700)
        os.environ["TELEPORT_DATA"] = str(DATA)
    return LoopbackHTTPServer(("127.0.0.1", int(port)), Handler)


if __name__=="__main__":
    app=make_server(PORT)
    print(f"Teleport listening at http://127.0.0.1:{app.server_port}",flush=True)
    app.serve_forever()
