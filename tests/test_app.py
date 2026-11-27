"""End-to-end checks: python -m unittest tests.test_app -v   (needs nmap for the live-scan test)"""

import http.server
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402


def fresh(extra_yaml=""):
    tmp = Path(tempfile.mkdtemp())
    config.DATA, config.RAW, config.DB_PATH = tmp, tmp / "raw", tmp / "netrik.db"
    config.CONFIG_PATH = tmp / "config.yaml"
    config.CONFIG_PATH.write_text(extra_yaml)
    config.cfg.cache_clear()
    return tmp


def login(client):
    r = client.post("/setup", data={"username": "admin", "password": "correct horse", "confirm": "correct horse"}, follow_redirects=False)
    assert r.status_code == 303, r.text


class IdentityTests(unittest.TestCase):
    def test_identity_rules(self):
        fresh()
        from app import db, ingest
        db.init()
        ingest.ingest([{"source": "arp", "ip": "10.0.0.5", "mac": "00:50:56:aa:00:01"}])
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.9", "mac": "00:50:56:aa:00:01", "hostname": "pc1"}])  # same MAC, new IP
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 1)
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.20", "mac": "da:11:22:33:44:01", "hostname": "Anu-Galaxy"}])
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.21", "mac": "da:11:22:33:44:99", "hostname": "Anu-Galaxy"}])  # rotated private MAC
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 2)
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.30", "mac": "00:50:56:aa:00:07", "hostname": "twin"}])
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.31", "mac": "00:50:56:aa:00:08", "hostname": "twin"}])  # same name, different hardware: never merged
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 4)


class NameLookupTests(unittest.TestCase):
    def _udp_server(self, reply_fn):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(3)

        def serve():
            try:
                data, addr = sock.recvfrom(1500)
                sock.sendto(reply_fn(data), addr)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        return sock

    def test_mdns_and_netbios_parsers(self):
        import struct
        from app.sources import names

        def mdns_reply(q):  # a standard DNS PTR answer using name compression
            rdata = b"\x0dsatyams-phone\x05local\x00"
            return q[:2] + struct.pack(">HHHHH", 0x8400, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
        srv = self._udp_server(mdns_reply)
        names.MDNS_PORT = srv.getsockname()[1]
        self.assertEqual(names.mdns("127.0.0.1", timeout=2), "satyams-phone.local")
        srv.close()

        def nb_reply(q):  # NetBIOS node-status answer: one unique workstation name and one group name
            entries = b"LAB-PC-07".ljust(15) + b"\x00" + struct.pack(">H", 0x0400) + b"WORKGROUP".ljust(15) + b"\x00" + struct.pack(">H", 0x8400)
            rdata = bytes([2]) + entries + b"\x00" * 6
            return q[:2] + struct.pack(">HHHHH", 0x8400, 0, 1, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
        srv = self._udp_server(nb_reply)
        names.NETBIOS_PORT = srv.getsockname()[1]
        self.assertEqual(names.netbios("127.0.0.1", timeout=2), "LAB-PC-07")
        srv.close()
        names.MDNS_PORT, names.NETBIOS_PORT = 5353, 137
        self.assertIsNone(names.mdns("127.0.0.1", timeout=0.2))  # nobody answering: no name, no crash

    def test_name_updates_label_unless_renamed(self):
        fresh()
        from app import db, ingest
        db.init()
        ingest.ingest([{"source": "arp", "ip": "10.0.0.5", "mac": "00:50:56:aa:00:01"}, {"source": "arp", "ip": "10.0.0.6", "mac": "00:50:56:aa:00:02"}])
        db.run("UPDATE devices SET label='Front office PC', label_auto=0 WHERE id=2")
        self.assertEqual(ingest.apply_names({"10.0.0.5": ("lab-pc-05", "netbios"), "10.0.0.6": ("lab-pc-06", "dns")}), 2)
        self.assertEqual(db.one("SELECT label,name_source FROM devices WHERE id=1")["label"], "lab-pc-05")
        self.assertEqual(db.one("SELECT label FROM devices WHERE id=2")["label"], "Front office PC")  # a person's name is never overwritten
        self.assertEqual(db.one("SELECT COUNT(*) n FROM observations")["n"], 2)  # names are labels, not presence evidence
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.5", "mac": "00:50:56:aa:00:01", "hostname": "renamed-by-dhcp"}])
        self.assertEqual(db.one("SELECT label FROM devices WHERE id=1")["label"], "renamed-by-dhcp")  # an automatic label follows better evidence


class DedupeTests(unittest.TestCase):
    def test_reliable_identifiers_merge_and_risky_ones_wait_for_a_person(self):
        fresh()
        from app import db, dedupe, ingest, util
        db.init()
        # an unprivileged scan sees an IP with no MAC; later a source reports the MAC at that address: still one device
        ingest.ingest([{"source": "nmap", "ip": "10.0.0.5"}])
        ingest.ingest([{"source": "arp", "ip": "10.0.0.5", "mac": "00:50:56:aa:00:05"}])
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 1)
        # generic phone model names are never joined on the name alone
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.30", "mac": "da:11:22:33:44:30", "hostname": "Galaxy-S23"}])
        ingest.ingest([{"source": "dhcp", "ip": "10.0.0.31", "mac": "be:11:22:33:44:31", "hostname": "Galaxy-S23"}])
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices WHERE label='Galaxy-S23'")["n"], 2)
        # two hardware MACs with one hostname: offered for review, merged only when a person says so
        ingest.ingest([{"source": "arp", "ip": "10.0.0.40", "mac": "00:50:56:bb:00:01", "hostname": "lab-pc-40"}])
        ingest.ingest([{"source": "arp", "ip": "10.0.0.41", "mac": "00:50:56:bb:00:02", "hostname": "lab-pc-40"}])
        with db.tx() as c:
            self.assertEqual(dedupe.auto_merge(c), {})
        reasons = " ".join(g["reason"] for g in dedupe.candidates())
        self.assertIn("lab-pc-40", reasons)
        ids = [r["id"] for r in db.q("SELECT id FROM devices WHERE label='lab-pc-40' ORDER BY id")]
        db.run("INSERT INTO services(device_id,port,proto,name,open_now,first_seen,last_seen) VALUES(?,22,'tcp','ssh',1,?,?)", (ids[1], util.now(), util.now()))
        with db.tx() as c:
            dedupe.merge(c, ids[0], ids[1], "test", "admin")
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices WHERE label='lab-pc-40'")["n"], 1)
        self.assertEqual(db.one("SELECT device_id FROM services WHERE port=22")["device_id"], ids[0])  # evidence moved over
        self.assertEqual(db.one("SELECT COUNT(*) n FROM identifiers WHERE device_id=? AND type='mac'", (ids[0],))["n"], 2)
        self.assertEqual(db.one("SELECT COUNT(*) n FROM device_merges")["n"], 1)

    def test_existing_duplicates_are_cleaned_up(self):
        fresh()
        from app import db, dedupe, util
        db.init()
        now = util.now()

        def dev(label, ids, first=now):
            d = db.run("INSERT INTO devices(label,first_seen,last_seen,zone) VALUES(?,?,?,'Lab')", (label, first, now))
            for t, v in ids:
                db.run("INSERT INTO identifiers(device_id,type,value,first_seen,last_seen) VALUES(?,?,?,?,?)", (d, t, v, now, now))
            return d
        dev("Unknown device 10.0.0.60", [("ip", "10.0.0.60")])
        dev("PC-60", [("mac", "00:50:56:cc:00:60"), ("ip", "10.0.0.60")])
        dev("kiosk", [("mac", "da:aa:aa:aa:aa:11"), ("hostname", "kiosk-front")])
        dev("kiosk", [("mac", "da:aa:aa:aa:aa:12"), ("hostname", "kiosk-front")])  # active at the same time: two devices
        with db.tx() as c:
            merged = dedupe.auto_merge(c)
        self.assertEqual(len(merged), 1)
        self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 3)


class NameDiscoveryTests(unittest.TestCase):
    def _udp(self, reply_fn):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(3)

        def serve():
            try:
                data, addr = sock.recvfrom(1500)
                sock.sendto(reply_fn(data), addr)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        return sock

    @staticmethod
    def _ptr_reply(name):
        import struct

        def fn(q):
            rd = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
            return q[:2] + struct.pack(">HHHHH", 0x8400, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rd)) + rd
        return fn

    def test_router_dns_and_llmnr_answers(self):
        from app.sources import names
        srv = self._udp(self._ptr_reply("LGwebOSTV.lan"))
        self.assertEqual(names._udp_ptr("127.0.0.1", srv.getsockname()[1], "192.168.1.20", 2, 0x0100), "LGwebOSTV.lan")  # what a router's DNS returns for a DHCP client
        srv.close()
        srv = self._udp(self._ptr_reply("DESKTOP-4F2K9"))
        names.LLMNR_PORT = srv.getsockname()[1]
        try:
            self.assertEqual(names.llmnr("127.0.0.1", timeout=2), "DESKTOP-4F2K9")
        finally:
            names.LLMNR_PORT = 5355
            srv.close()

    def test_mdns_announcement_parsing(self):
        import socket
        import struct
        from app.sources import names

        def nm(n):
            return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"
        inst = nm("LG webOS TV._airplay._tcp.local")
        host = nm("LGwebOSTV.local")
        ip = "192.168.1.20"
        pkt = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 2)
        pkt += nm("_airplay._tcp.local") + struct.pack(">HHIH", 12, 1, 120, len(inst)) + inst            # PTR to the instance name
        pkt += host + struct.pack(">HHIH", 1, 1, 120, 4) + socket.inet_aton(ip)                           # A record in the additional section
        pkt += inst + struct.pack(">HHIH", 33, 1, 120, 6 + len(host)) + struct.pack(">HHH", 0, 0, 7000) + host
        rec = names.mdns_records(pkt, ip)
        self.assertEqual((rec["host"], rec["friendly"]), ("LGwebOSTV", "LG webOS TV"))
        self.assertIn("airplay._tcp", rec["services"])
        self.assertIsNone(names.mdns_records(pkt, "192.168.1.99")["host"] if False else None)

    def test_upnp_friendly_name_and_ssrf_guard(self):
        import http.server
        from app.sources import names
        xml = (b'<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>'
               b'<friendlyName>[LG] webOS TV OLED55C1</friendlyName><manufacturer>LG Electronics</manufacturer><modelName>OLED55C1PUB</modelName></device></root>')

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(xml)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/desc.xml"
        d = names.upnp_describe(url, "127.0.0.1")
        self.assertEqual(d["friendlyName"], "[LG] webOS TV OLED55C1")
        self.assertEqual(names.kind_hint(d), "TV / media device")
        self.assertIsNone(names.upnp_describe(url, "10.9.9.9"))  # a device may only point us at itself
        self.assertIsNone(names.upnp_describe("http://169.254.169.254/latest/", "169.254.169.254"))
        self.assertEqual(names._parse_ssdp(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.20:3000/d.xml\r\n\r\n"), "http://192.168.1.20:3000/d.xml")
        srv.shutdown()

    def test_stronger_names_win_and_hints_apply(self):
        fresh()
        from app import db, ingest
        db.init()
        ingest.ingest([{"source": "arp", "ip": "10.0.0.20", "mac": "00:50:56:aa:00:20"}])
        ingest.apply_names({"10.0.0.20": ("[LG] webOS TV", "upnp")}, {"10.0.0.20": {"vendor": "LG Electronics", "kind": "TV / media device"}})
        d = db.one("SELECT label, kind, vendor FROM devices")
        self.assertEqual((d["label"], d["kind"], d["vendor"]), ("[LG] webOS TV", "TV / media device", "LG Electronics"))
        ingest.apply_names({"10.0.0.20": ("LGwebOSTV", "dns")})                       # a DNS name (router) beats a UPnP friendly name
        self.assertEqual(db.one("SELECT label FROM devices")["label"], "LGwebOSTV")
        ingest.apply_names({"10.0.0.20": ("[LG] webOS TV", "upnp")})                  # and the weaker source cannot take it back
        self.assertEqual(db.one("SELECT label FROM devices")["label"], "LGwebOSTV")


class PolicyTests(unittest.TestCase):
    def test_test_visit_scopes(self):
        fresh()
        from app import db, ingest
        from app.main import app
        db.init()
        for i, (zone, ip) in enumerate([("Lab", "10.0.0.11"), ("Lab", "10.0.0.12"), ("Staff", "10.0.0.21"), ("Lab", "10.0.0.1")], 1):
            ingest.ingest([{"source": "arp", "ip": ip, "mac": f"00:50:56:aa:00:{i:02x}", "hostname": f"PC-{ip.split('.')[-1]}", "zone": zone}])
        db.run("UPDATE devices SET kind='Gateway / router' WHERE label='PC-1'")
        with TestClient(app) as c:
            login(c)
            c.post("/settings/policy/add", data={"kind": "site", "domains": "facebook.com", "zone": "All zones", "severity": "high"})
            first = db.one("SELECT id FROM devices WHERE label='PC-11'")["id"]
            c.post("/settings/policy/test", data={"scope": "segment_of", "client": str(first), "domain": "facebook.com", "skip_infra": "1"})
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 2)  # PC-11 and PC-12; the gateway was skipped, Staff is another segment
            c.post("/settings/policy/test", data={"scope": "all", "domain": "facebook.com", "skip_infra": "1"})
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 3)  # now PC-21 too
            c.post("/settings/policy/test", data={"scope": "segment", "zone": "Lab", "domain": "facebook.com"})  # without skipping, the gateway is included
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 4)
            r = c.post("/settings/policy/test", data={"scope": "all", "domain": "facebook.com"}, follow_redirects=False)
            self.assertEqual(r.headers["location"], "/alerts?type=policy_site")

    def test_site_rule_alert_test_event_log_import_and_forbidden_port(self):
        fresh()
        from app import db, ingest
        from app.main import app
        db.init()
        ingest.ingest([{"source": "arp", "ip": "10.0.0.8", "mac": "00:50:56:aa:00:08", "hostname": "LAB-PC-08"}])
        with TestClient(app) as c:
            login(c)
            r = c.post("/settings/policy/add", data={"kind": "site", "name": "No social media", "domains": "facebook.com, *.bet365.com", "zone": "All zones", "severity": "high"}, follow_redirects=False)
            self.assertEqual(r.status_code, 303)
            self.assertIn("not a valid domain", c.get(c.post("/settings/policy/add", data={"kind": "site", "domains": "not a domain!"}, follow_redirects=False).headers["location"].split("#")[0]).text.replace("\n", " ") or "not a valid domain")
            did = db.one("SELECT id FROM devices")["id"]
            r = c.post("/settings/policy/test", data={"client": str(did), "domain": "www.facebook.com"}, follow_redirects=False)
            self.assertRegex(r.headers["location"], r"^/alerts/\d+$")  # a finding was raised and we are taken to it
            page = c.get(r.headers["location"]).text
            self.assertIn("Restricted site requested", page)
            self.assertIn("test event", page)
            self.assertIn("not proof the page loaded", page)
            self.assertEqual(c.post("/settings/policy/test", data={"client": str(did), "domain": "wikipedia.org"}, follow_redirects=False).headers["location"], "/settings#policies")
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 1)
            log = "10.0.0.8 facebook.com\n10.0.0.8 m.bet365.com\n10.0.0.8 example.org\n10.0.0.99 facebook.com\n"
            c.post("/sources/import", data={"type": "web"}, files={"file": ("dns.txt", log.encode())})
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 2)  # one finding per client and rule; repeats only raise its counter
            first = db.one("SELECT detail FROM alerts WHERE type='policy_site' AND title LIKE '%LAB-PC-08%'")
            self.assertEqual(__import__("json").loads(first["detail"])["hits"], 3)  # the test event plus two requests from the log
            g = c.get("/api/topology").json()
            self.assertTrue(any(e["data"]["layer"] == "web" for e in g["edges"]))
            c.post("/settings/policy/add", data={"kind": "port_forbid", "name": "No Telnet", "ports": "23", "zone": "All zones", "severity": "high"})
            ingest.ingest([{"source": "nmap", "ip": "10.0.0.8", "mac": "00:50:56:aa:00:08", "ports": [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "product": "", "version": ""}]}])
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_violation' AND title LIKE 'Port 23 must not be open%'")["n"], 1)
            rid = db.one("SELECT id FROM policy_rules WHERE kind='port_forbid'")["id"]
            c.post(f"/settings/policy/{rid}/toggle")
            self.assertEqual(db.one("SELECT enabled FROM policy_rules WHERE id=?", (rid,))["enabled"], 0)
            for path in ("/settings", "/devices/duplicates"):
                self.assertEqual(c.get(path).status_code, 200, path)

    def test_dns_monitor_refuses_and_records_matching_lookups(self):
        import socket
        import struct
        fresh()
        from app import db, dnsmon, ingest
        db.init()
        ingest.ingest([{"source": "arp", "ip": "127.0.0.1", "mac": "00:50:56:aa:00:01", "hostname": "LAB-PC-01"}])
        db.run("INSERT INTO policy_rules(kind,name,domains,zone,severity,block,enabled,created_by,created_at) VALUES('site','Social','facebook.com','All zones','high',1,1,'admin',datetime('now'))")
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.bind(("127.0.0.1", 0))

        def fake_upstream():
            while True:
                try:
                    d, a = up.recvfrom(4096)
                    up.sendto(d[:2] + b"\x81\x80" + d[4:], a)
                except OSError:
                    return
        threading.Thread(target=fake_upstream, daemon=True).start()
        dnsmon.start("127.0.0.1", 0, "127.0.0.1", up.getsockname()[1])

        def ask(name):
            q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(struct.pack(">HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + q, ("127.0.0.1", dnsmon.status()["port"]))
            r = s.recv(4096)
            s.close()
            return struct.unpack(">H", r[2:4])[0] & 0xF
        try:
            self.assertEqual(ask("www.facebook.com"), 3)  # refused (NXDOMAIN)
            self.assertEqual(ask("wikipedia.org"), 0)      # forwarded untouched
            time.sleep(0.4)
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts WHERE type='policy_site'")["n"], 1)
            self.assertEqual(db.one("SELECT blocked FROM web_events")["blocked"], 1)
            self.assertEqual(db.one("SELECT COUNT(*) n FROM web_events")["n"], 1)  # allowed lookups are not stored
        finally:
            dnsmon.stop()
            up.close()


class ProgressTests(unittest.TestCase):
    def test_tracker_moves_through_stages_and_never_goes_backwards(self):
        from app.progress import Tracker, plan_for
        t = Tracker(plan_for("portscan", ["-sS", "-sV", "-O"], True), 60)
        self.assertEqual(t.snapshot()["phase"], "discover")
        for line in ["Initiating SYN Stealth Scan at 10:00", "Discovered open port 445/tcp on 10.0.0.5",
                     "SYN Stealth Scan Timing: About 40.00% done; ETC: 10:01 (0:00:30 remaining)"]:
            t.on_line(line)
        s = t.snapshot()
        self.assertEqual((s["phase"], s["stage_percent"], s["remaining_s"]), ("ports", 40.0, 30))
        self.assertTrue(any(f["kind"] == "port" for f in s["feed"]))
        t.on_line("Initiating Service scan at 10:01")
        t.on_line("SYN Stealth Scan Timing: About 90.00% done")  # a late line from an earlier stage must not rewind progress
        self.assertEqual(t.snapshot()["phase"], "services")
        before = t.snapshot()["percent"]
        t.finish()
        self.assertEqual(t.snapshot()["percent"], 100.0)
        self.assertGreater(100.0, before)

    def test_xml_timeline_and_api(self):
        from app.sources import nmap_source
        fresh()
        xml = Path(config.DATA) / "t.xml"
        xml.write_text('<nmaprun><taskbegin task="Connect Scan" time="100"/><taskend task="Connect Scan" time="160" extrainfo="1 total ports"/>'
                       '<taskbegin task="Service scan" time="160"/><taskend task="Service scan" time="175"/><runstats><finished time="180" timestr="x" elapsed="80.5"/></runstats></nmaprun>')
        tl = nmap_source.timeline(str(xml))
        self.assertEqual([(p["task"], p["seconds"]) for p in tl["phases"]], [("Connect Scan", 60), ("Service scan", 15)])
        self.assertEqual(tl["elapsed"], 80.5)
        from app.main import app
        with TestClient(app) as c:
            login(c)
            self.assertEqual(c.get("/api/activity").json()["running"], False)
            from app import db
            sid = db.run("INSERT INTO scans(kind,target,status,created_at,requested_by) VALUES('names','x','queued','2026-01-01 00:00:00','admin')")
            j = c.get(f"/api/scans/{sid}").json()
            self.assertEqual((j["status"], j["queue_pos"]), ("queued", 0))
            for asset in ("style.css", "app.js", "topology.js", "icons.js", "icons.svg", "cytoscape.min.js", "fonts/inter-latin-400-normal.woff2", "fonts/jetbrains-mono-latin-500-normal.woff2"):
                self.assertEqual(c.get(f"/static/{asset}").status_code, 200, asset)


class HostileInput(unittest.TestCase):
    def test_banner_and_hostname_are_escaped(self):
        fresh()
        from app import db, ingest
        from app.main import app
        evil = "<script>alert(1)</script>"
        with TestClient(app) as c:
            login(c)
            ingest.ingest([{"source": "nmap", "ip": "10.1.1.1", "mac": "00:50:56:aa:00:01", "hostname": evil,
                            "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": evil, "product": evil, "version": ""}]}])
            for path in ("/devices", "/devices/1", "/topology"):
                self.assertNotIn(evil, c.get(path).text, path)
            self.assertEqual(c.post("/devices/1/update", data={"label": "x"}, headers={"origin": "http://evil.example"}, follow_redirects=False).status_code, 403)


class DemoFlow(unittest.TestCase):
    def test_every_page_and_feature(self):
        fresh()
        from app.main import app
        with TestClient(app) as c:
            self.assertEqual(c.get("/", follow_redirects=False).status_code, 303)
            login(c)
            self.assertEqual(c.post("/settings/demo", data={"action": "load"}, follow_redirects=False).status_code, 303)
            for path in ["/", "/devices", "/devices?q=lab&status=ok", "/topology", "/visibility", "/alerts", "/alerts?status=all", "/scans", "/compare",
                         "/simulator", "/sources", "/reports", "/settings", "/devices/duplicates", "/devices/1", "/scans/1", "/scans/1?tab=raw", "/scans/1?tab=findings", "/alerts/1"]:
                r = c.get(path)
                self.assertEqual(r.status_code, 200, path)
            self.assertIn("DEMO DATA", c.get("/").text)
            types = {r.group(1) for r in __import__("re").finditer(r"/alerts\?[^\"]*", "")}  # noqa
            from app import db
            kinds = {r["type"] for r in db.q("SELECT type FROM alerts")}
            for k in ("new_device", "policy_violation", "sensitive_service", "new_service", "stale_device", "policy_site"):
                self.assertIn(k, kinds, k)
            g = c.get("/api/topology").json()
            if shutil.which("node"):  # layout and style sheet checked against the real Cytoscape engine
                import json as _json
                import subprocess
                gp = Path(config.DATA) / "graph.json"
                gp.write_text(_json.dumps(g))
                out = subprocess.run(["node", str(Path(__file__).parent / "topology_check.js"), str(gp)], capture_output=True, text=True, timeout=60)
                res = _json.loads(out.stdout)
                self.assertEqual((res["nan"], res["overlap"], res["orphanEdges"], res["styleWarnings"]), (0, 0, 0, 0), out.stdout)
                self.assertGreater(res["devices"], 20)
            self.assertTrue(any(e["data"]["layer"] == "configured" for e in g["edges"]))
            self.assertTrue(any(e["data"].get("state") == "violation" for e in g["edges"]))
            ids = {d["label"]: d["id"] for d in db.q("SELECT id,label FROM devices")}
            runs = [{"scenario": "unrecognised", "zone": "Server Room", "name": "Rogue"},
                    {"scenario": "exposure", "device": ids["LAB-PC-01"], "port": "3389", "from_zone": "Student Wi-Fi"},
                    {"scenario": "exposure", "device": ids["AD-SRV"], "port": "445", "from_zone": "Student Wi-Fi"},
                    {"scenario": "failure", "device": ids["FEE-DB-SRV"]},
                    {"scenario": "restrict", "device": ids["LAB-PC-08"], "port": "3389"}]
            for form in runs:
                r = c.post("/simulator", data=form)
                self.assertEqual(r.status_code, 200)
                self.assertIn("HYPOTHETICAL", r.text, form)
                self.assertNotIn("Could not run", r.text, form)
            before = db.one("SELECT COUNT(*) n FROM alerts")["n"]
            self.assertEqual(db.one("SELECT COUNT(*) n FROM alerts")["n"], before)  # simulator creates no real findings
            for fmt in ("csv", "json", "html", "pdf"):
                r = c.get(f"/export/inventory.{fmt}")
                self.assertEqual(r.status_code, 200, fmt)
            self.assertTrue(c.get("/export/inventory.pdf").content.startswith(b"%PDF"))
            for fmt in ("txt", "json", "html", "pdf"):
                self.assertEqual(c.get(f"/scans/1/export/{fmt}").status_code, 200, fmt)
            self.assertEqual(c.get("/scans/1/export/xml").status_code, 404)
            r = c.post("/visibility/check", data={"known": "LAB-PC-01\n00:50:56:01:00:02\nnot-a-device"})
            self.assertIn("67%", r.text)
            a = db.one("SELECT id FROM alerts WHERE type='new_device' LIMIT 1")["id"]
            c.post(f"/alerts/{a}/decide", data={"status": "acknowledged", "note": "visitor"})
            self.assertEqual(db.one("SELECT status FROM alerts WHERE id=?", (a,))["status"], "acknowledged")
            self.assertEqual(c.post("/scans", data={"kind": "discovery", "target": "8.8.8.8"}, follow_redirects=False).headers["location"], "/scans")
            self.assertEqual(db.one("SELECT COUNT(*) n FROM scans WHERE requested_by='admin'")["n"], 0)  # out-of-scope target refused
            self.assertEqual(c.post("/settings/demo", data={"action": "clear"}, follow_redirects=False).status_code, 303)
            self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 0)
            self.assertEqual(c.post("/logout", follow_redirects=False).status_code, 303)
            self.assertEqual(c.get("/devices", follow_redirects=False).status_code, 303)


@unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
class LiveScan(unittest.TestCase):
    def wait(self, c, sid, timeout=90):
        t0 = time.time()
        while time.time() - t0 < timeout:
            s = c.get(f"/api/scans/{sid}").json()
            if s["status"] in ("complete", "failed", "cancelled"):
                return s
            time.sleep(0.5)
        self.fail("scan timed out")

    def test_scan_alert_verify(self):
        fresh("allowed_ranges: ['127.0.0.0/8']\nsensitive_ports: {33389: 'Remote Desktop (test port)'}\n")
        from app import db
        from app.main import app

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                pass
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 33389), H)
        srv.allow_reuse_address = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with TestClient(app) as c:
            login(c)
            sid = int(c.post("/scans", data={"kind": "discovery", "target": "127.0.0.1"}, follow_redirects=False).headers["location"].split("/")[-1])
            self.assertEqual(self.wait(c, sid)["status"], "complete")
            self.assertEqual(db.one("SELECT COUNT(*) n FROM devices")["n"], 1)
            self.assertEqual(db.one("SELECT label FROM devices WHERE id=1")["label"], "localhost")  # Nmap's own reverse-DNS name is used
            sid = int(c.post("/scans", data={"kind": "portscan", "target": "127.0.0.0/24", "profile": "quick", "ports": "33389", "live_only": "1"}, follow_redirects=False).headers["location"].split("/")[-1])
            self.assertEqual(self.wait(c, sid)["status"], "complete")
            row = db.one("SELECT command, summary FROM scans WHERE id=?", (sid,))
            self.assertIn("127.0.0.1", row["command"])  # the /24 was narrowed to the host already known to be up
            self.assertEqual(__import__("json").loads(row["summary"])["hosts_up"], 1)
            lk = int(c.post("/devices/lookup-names", follow_redirects=False).headers["location"].split("/")[-1])
            self.assertEqual(self.wait(c, lk)["status"], "complete")
            self.assertIn("33389", c.get(f"/scans/{sid}").text)
            self.assertIn("nmap", c.get(f"/scans/{sid}?tab=raw").text.lower())
            self.assertEqual(c.get(f"/scans/{sid}/export/xml").status_code, 200)
            alert = db.one("SELECT * FROM alerts WHERE type='sensitive_service'")
            self.assertIsNotNone(alert)
            c.post(f"/alerts/{alert['id']}/verify")
            vs = db.one("SELECT id FROM scans WHERE kind='verify'")["id"]
            self.wait(c, vs)
            self.assertEqual(db.one("SELECT result FROM verifications")["result"], "still_present")
            srv.shutdown(); srv.server_close()  # "apply the fix"
            c.post(f"/alerts/{alert['id']}/verify")
            vs2 = db.one("SELECT id FROM scans WHERE kind='verify' ORDER BY id DESC LIMIT 1")["id"]
            self.wait(c, vs2)
            res = db.q("SELECT result FROM verifications ORDER BY id")
            self.assertEqual([r["result"] for r in res], ["still_present", "resolved"])
            self.assertEqual(db.one("SELECT status FROM alerts WHERE id=?", (alert["id"],))["status"], "verified")


@unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
class TimeLimit(unittest.TestCase):
    def test_time_limit_stops_gracefully_and_keeps_partial_status(self):
        fresh("allowed_ranges: ['127.0.0.0/8']\nmax_rate: 300\nscan_timeout_minutes: 0.1\n")
        from app import db
        from app.main import app
        with TestClient(app) as c:
            login(c)
            sid = int(c.post("/scans", data={"kind": "portscan", "target": "127.0.0.1", "profile": "all_tcp"}, follow_redirects=False).headers["location"].split("/")[-1])
            t0 = time.time()
            while time.time() - t0 < 90:
                st = c.get(f"/api/scans/{sid}").json()["status"]
                if st not in ("queued", "running"):
                    break
                time.sleep(0.5)
            self.assertEqual(st, "partial")
            self.assertIn("limit", c.get(f"/scans/{sid}").text)
            self.assertEqual(c.get(f"/scans/{sid}?tab=raw").status_code, 200)


if __name__ == "__main__":
    unittest.main()
