import hashlib, http.client, importlib.util, json, os, tempfile, threading, time, unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
TEMP=tempfile.TemporaryDirectory(); os.environ["TELEPORT_DATA"]=TEMP.name
spec=importlib.util.spec_from_file_location("teleport_server",BASE/"server.py"); app=importlib.util.module_from_spec(spec); spec.loader.exec_module(app)

class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=app.ThreadingHTTPServer(("127.0.0.1",0),app.Handler); cls.port=cls.server.server_port; app.PORT=cls.port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close(); TEMP.cleanup()
    def call(self,path,method="GET",body=None,headers=None):
        h={"Host":f"127.0.0.1:{self.port}","Origin":f"http://127.0.0.1:{self.port}","Sec-Fetch-Site":"same-origin","X-Teleport-Request":app.SESSION}; h.update(headers or {})
        c=http.client.HTTPConnection("127.0.0.1",self.port); payload=body
        if isinstance(body,(dict,list)): payload=json.dumps(body); h["Content-Type"]="application/json"
        c.request(method,path,body=payload,headers=h); r=c.getresponse(); data=r.read(); c.close()
        try: return r.status,json.loads(data)
        except Exception:return r.status,data
    def create(self,data=b"hello transfer",hours=24,name="bundle.bin",recipient="Riley"):
        sha=hashlib.sha256(data).hexdigest(); status,t=self.call("/api/transfers","POST",{"recipient":recipient,"hours":hours,"files":[{"name":name,"size":len(data),"sha256":sha}]})
        self.assertEqual(status,201); return t,data
    def send_chunk(self,t,data,claimed=None):
        h=claimed or hashlib.sha256(data).hexdigest(); return self.call(f"/api/transfers/{t['id']}/file/0","POST",data,{"X-Chunk-Index":"0","X-Chunk-SHA256":h,"X-Recipient-Code":t["code"],"X-Recipient-Name":"Riley","Content-Type":"application/octet-stream"})
    def authbody(self,t,**extra):return {"code":t["code"],"recipient":"Riley",**extra}
    def test_changed_chunk_is_rejected_and_cannot_verify_or_cleanup(self):
        t,data=self.create(); bad=data[:-1]+b"X"
        self.assertEqual(self.send_chunk(t,bad,hashlib.sha256(data).hexdigest())[0],422)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))[0],409)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/cleanup","POST",self.authbody(t))[0],409)
    def test_resume_is_idempotent_without_duplicate_chunks(self):
        t,data=self.create(); self.assertEqual(self.send_chunk(t,data)[0],200); self.assertEqual(self.send_chunk(t,data)[0],200)
        status,m=self.call(f"/api/transfers/{t['id']}/details","POST",self.authbody(t)); self.assertEqual(status,200); self.assertEqual(m["files"][0]["received"],[0])
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))[0],200)
    def test_recipient_authentication_and_receipt_hash_gate_cleanup(self):
        t,data=self.create(); self.send_chunk(t,data); self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/details","POST",{"code":t["code"],"recipient":"Wrong"})[0],403)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/receive","POST",self.authbody(t,hashes=["0"*64]))[0],422)
        status,result=self.call(f"/api/transfers/{t['id']}/receive","POST",self.authbody(t,hashes=[hashlib.sha256(data).hexdigest()]))
        self.assertEqual(status,200); self.assertEqual(result["receipt"]["files"][0]["expected_sha256"],result["receipt"]["files"][0]["received_sha256"])
        d=app.safe_dir(t["id"])/"0.0.part"; d.write_bytes(b"changed after receive")
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/cleanup","POST",self.authbody(t))[0],422)
        self.assertTrue(d.exists())
    def test_cleanup_succeeds_only_after_verified_browser_receipt(self):
        t,data=self.create(); self.send_chunk(t,data); self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/cleanup","POST",self.authbody(t))[0],409)
        digest=hashlib.sha256(data).hexdigest()
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/receive","POST",self.authbody(t,hashes=[digest]))[0],200)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/cleanup","POST",self.authbody(t))[0],200)
        self.assertFalse(app.safe_dir(t["id"]).exists())
    def test_stored_byte_change_after_verify_blocks_receipt_and_cleanup(self):
        t,data=self.create(); self.send_chunk(t,data); self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))
        chunk=app.safe_dir(t["id"])/"0.0.part"; chunk.write_bytes(b"tampered")
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/receive","POST",self.authbody(t,hashes=[hashlib.sha256(data).hexdigest()]))[0],422)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/cleanup","POST",self.authbody(t))[0],409)
        self.assertTrue(chunk.exists())
    def test_download_requires_authenticated_same_origin_and_returns_exact_bytes(self):
        t,data=self.create(); self.send_chunk(t,data); self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))
        h={"X-Recipient-Code":t["code"],"X-Recipient-Name":"Riley"}
        status,payload=self.call(f"/api/transfers/{t['id']}/download/0","GET",headers=h)
        self.assertEqual(status,200); self.assertEqual(payload,data)
        status,_=self.call(f"/api/transfers/{t['id']}/download/0","GET",headers={**h,"Sec-Fetch-Site":"cross-site"})
        self.assertEqual(status,403)
    def test_unicode_filename_is_encoded_safely(self):
        t,data=self.create(name="résumé_日本.txt"); self.send_chunk(t,data); self.call(f"/api/transfers/{t['id']}/verify","POST",self.authbody(t))
        h={"X-Recipient-Code":t["code"],"X-Recipient-Name":"Riley"}
        status,payload=self.call(f"/api/transfers/{t['id']}/download/0","GET",headers=h)
        self.assertEqual(status,200); self.assertEqual(payload,data)
    def test_unicode_recipient_header_is_encoded_and_authenticated(self):
        t,data=self.create(recipient="李"); headers={"X-Chunk-Index":"0","X-Chunk-SHA256":hashlib.sha256(data).hexdigest(),"X-Recipient-Code":t["code"],"X-Recipient-Name":"%E6%9D%8E","Content-Type":"application/octet-stream"}
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/file/0","POST",data,headers)[0],200)
    def test_expiry_and_origin_boundary(self):
        t,data=self.create(hours=1); m=app.read_manifest(t["id"]); m["expires"]=time.time()-1; app.save_manifest(t["id"],m)
        self.assertEqual(self.call(f"/api/transfers/{t['id']}/details","POST",self.authbody(t))[0],410)
        status,_=self.call("/api/transfers","POST",{"recipient":"Riley","hours":24,"files":[]},{"Origin":"https://attacker.invalid"}); self.assertEqual(status,403)

if __name__=="__main__":unittest.main()
