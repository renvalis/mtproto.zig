#!/usr/bin/env python3
"""Offline Linux WSS integration checks. The test driver uses OpenSSL; the proxy is standalone.

python3 test/ws_transport_e2e.py --proxy zig-out/bin/mtproto-proxy
Generates a temporary CA with openssl, or accepts --cert/--key fixtures.
No connection to Telegram or any public network is made.
"""
import argparse
import base64
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("proxy_e2e", ROOT / "test/e2e/run.py")
e2e = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = e2e
spec.loader.exec_module(e2e)


class AesCtr:
    """Test-side streaming AES using libcrypto; no Python package dependencies."""
    lib = ctypes.CDLL("libcrypto.so.3")
    for name, args, result in [
        ("EVP_CIPHER_CTX_new", [], ctypes.c_void_p),
        ("EVP_aes_256_ctr", [], ctypes.c_void_p),
        ("EVP_EncryptInit_ex", [ctypes.c_void_p] * 5, ctypes.c_int),
        ("EVP_EncryptUpdate", [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        ("EVP_CIPHER_CTX_free", [ctypes.c_void_p], None),
    ]:
        getattr(lib, name).argtypes = args
        getattr(lib, name).restype = result

    def __init__(self, key, iv):
        self.ctx = self.lib.EVP_CIPHER_CTX_new()
        assert self.ctx and self.lib.EVP_EncryptInit_ex(self.ctx, self.lib.EVP_aes_256_ctr(), None, key, iv) == 1

    def apply(self, data):
        out = ctypes.create_string_buffer(len(data) + 16)
        count = ctypes.c_int()
        assert self.lib.EVP_EncryptUpdate(self.ctx, out, ctypes.byref(count), data, len(data)) == 1
        return out.raw[:count.value]

    def close(self):
        if self.ctx:
            self.lib.EVP_CIPHER_CTX_free(self.ctx)
            self.ctx = None

    def __del__(self):
        self.close()


def client_init(tag, dc, secret_hex=e2e.DEFAULT_SECRET_HEX):
    nonce = bytearray(os.urandom(64))
    nonce[0] = 0x42
    nonce[4:8] = b"\x01\x02\x03\x04"
    nonce[56:60] = struct.pack("<I", tag)
    nonce[60:62] = struct.pack("<h", dc)
    secret = bytes.fromhex(secret_hex)
    enc = AesCtr(hashlib.sha256(nonce[8:40] + secret).digest(), bytes(nonce[40:56]))
    reverse = bytes(nonce[8:56][::-1])
    dec = AesCtr(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    encrypted = enc.apply(bytes(nonce))
    return bytes(nonce[:56]) + encrypted[56:], enc, dec


def receive_frame(conn):
    first, second = e2e.recv_exact(conn, 2)
    assert second & 0x80, "unmasked client frame"
    n = second & 127
    if n == 126:
        n = struct.unpack(">H", e2e.recv_exact(conn, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", e2e.recv_exact(conn, 8))[0]
    assert n <= 4 * 1024 * 1024 + 4
    mask = e2e.recv_exact(conn, 4)
    data = e2e.recv_exact(conn, n)
    return first & 15, bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def server_frame(op, payload, fin=True):
    first = (128 if fin else 0) | op
    n = len(payload)
    prefix = bytes([first, n]) if n < 126 else bytes([first, 126]) + struct.pack(">H", n) if n < 65536 else bytes([first, 127]) + struct.pack(">Q", n)
    return prefix + payload


class Endpoint:
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.context.set_servername_callback(lambda conn, name, _: setattr(conn, "requested_sni", name))
        self.mode = "normal"
        self.errors = []
        self.routes = []
        self.connections = 0
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 443))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.stopped = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn, self.mode), daemon=True).start()

    def handle(self, raw, mode):
        try:
            raw.settimeout(5)
            with self.context.wrap_socket(raw, server_side=True) as conn:
                self.connections += 1
                if conn.selected_alpn_protocol() == "h2":
                    self.handle_h2(conn, mode)
                    return
                request = e2e.recv_until(conn, b"\r\n\r\n")
                headers = dict(line.split(b":", 1) for line in request.split(b"\r\n")[1:] if b":" in line)
                assert request.startswith(b"GET /apiws HTTP/1.1\r\n")
                self.routes.append((conn.requested_sni, headers[b"Host"].strip()))
                if mode == "redirect" and conn.requested_sni.startswith("kws"):
                    conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\n\r\n")
                    return
                key = headers[b"Sec-WebSocket-Key"].strip()
                accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                if mode == "bad_accept":
                    accept = b"wrong"
                response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                # Split HTTP response to exercise incremental Upgrade parsing.
                conn.sendall(response[:17])
                conn.sendall(response[17:])
                op, nonce = receive_frame(conn)
                assert op == 2 and len(nonce) == 64
                dec = AesCtr(nonce[8:40], nonce[40:56])
                decoded = dec.apply(nonce)
                tag = struct.unpack("<I", decoded[56:60])[0]
                reverse = nonce[8:56][::-1]
                enc = AesCtr(reverse[:32], reverse[32:])
                while True:
                    op, data = receive_frame(conn)
                    if op == 10:
                        assert data == b"probe"
                        continue
                    assert op == 2
                    plain = dec.apply(data)
                    if tag == 0xefefefef:
                        words = plain[0] & 127
                        size = (int.from_bytes(plain[1:4], "little") * 4 + 4) if words == 127 else words * 4 + 1
                        assert len(plain) == size
                    else:
                        assert len(plain) == 4 + (struct.unpack("<I", plain[:4])[0] & 0x7fffffff)
                    reply = enc.apply(plain)
                    # Fragmented binary with an interleaved control frame.
                    half = len(reply) // 2
                    conn.sendall(server_frame(2, reply[:half], False) + server_frame(9, b"probe") + server_frame(0, reply[half:]))
                    if mode == "close":
                        conn.sendall(server_frame(8, struct.pack(">H", 1000)))
                        return
        except (ConnectionError, OSError, ssl.SSLError):
            pass  # Cancellation, idle-pool retirement and negative TLS cases.
        except BaseException as error:
            self.errors.append(error)
        finally:
            raw.close()

    def handle_h2(self, conn, mode):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import RequestReceived, DataReceived, StreamEnded

        h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        h2.initiate_connection()
        conn.sendall(h2.data_to_send())
        requests, replies = {}, {}
        while True:
            wire = conn.recv(65536)
            if not wire:
                return
            for event in h2.receive_data(wire):
                if isinstance(event, RequestReceived):
                    headers = dict(event.headers)
                    assert headers[":path"] == "/api"
                    self.routes.append(("h2", headers[":authority"].encode()))
                    requests[event.stream_id] = (headers[":method"], bytearray())
                elif isinstance(event, DataReceived):
                    requests[event.stream_id][1].extend(event.data)
                    h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    method, body = requests.pop(event.stream_id)
                    if method == "HEAD":
                        h2.send_headers(event.stream_id, [(":status", "501")], end_stream=True)
                    else:
                        assert len(body) >= 24 and len(body) % 4 == 0
                        h2.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/octet-stream")])
                        replies[event.stream_id] = body
            for stream, body in list(replies.items()):
                while body and h2.local_flow_control_window(stream) > 0:
                    size = min(len(body), h2.local_flow_control_window(stream), h2.max_outbound_frame_size)
                    h2.send_data(stream, bytes(body[:size]), end_stream=size == len(body))
                    del body[:size]
                if not body:
                    del replies[stream]
            outgoing = h2.data_to_send()
            if outgoing:
                conn.sendall(outgoing)

    def close(self):
        self.stopped = True
        self.listener.close()
        self.thread.join(timeout=2)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.endpoint.mode = "normal"
        self.endpoint.errors.clear()
        self.endpoint.routes.clear()

    def start(self, *, pool=0, fronting=False, trust=True, sni="sprinthost.ru", verify_hostname=True, cf=False, h2_media=True, second_user=None):
        port = e2e.free_port()
        cfg = e2e.base_config(port=port, upstream_type="telegram_ws", fake_tls_only=False, fast_mode=True, max_connections=32)
        cfg = cfg.replace("allow_direct_fallback = true", "allow_direct_fallback = false").replace('log_level = "warn"', 'log_level = "debug"')
        if second_user:
            cfg = cfg.replace("[access.users]", f'[access.users]\nuser2 = "{second_user}"', 1)
        cfg += f'\n[upstream.telegram_ws]\npool_size = {pool}\nfronting = {str(fronting).lower()}\n'
        cfg += f'fronting_sni = "{sni}"\nfronting_verify_hostname = {str(verify_hostname).lower()}\n'
        cfg += f'cf_fallback = {str(cf).lower()}\n'
        if cf:
            cfg += f'cf_first = true\ncf_domains = "cf.test"\ncf_h2_media = {str(h2_media).lower()}\n'
        cfg += '\n'.join(f'dc{dc}_ip = "127.0.0.1"' for dc in [1, 2, 3, 4, 5, 203]) + '\n'
        previous = os.environ.get("SSL_CERT_FILE")
        if trust:
            os.environ["SSL_CERT_FILE"] = str(self.cert)
        else:
            os.environ.pop("SSL_CERT_FILE", None)
        try:
            proxy = e2e.start_proxy(cfg, port)
        finally:
            if previous is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous
        self.addCleanup(proxy.stop)
        return proxy

    def exchange(self, proxy, *, fake_tls=False, dc=2, tag=0xdddddddd, repeats=2, body_size=16384, secret_hex=e2e.DEFAULT_SECRET_HEX):
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as conn:
            conn.settimeout(5)
            if fake_tls:
                conn.sendall(e2e.build_tls_auth_client_hello(bytes.fromhex(secret_hex), e2e.DEFAULT_TLS_DOMAIN))
                e2e.read_proxy_records(conn, budget_sec=0.25)
            nonce, enc, dec = client_init(tag, dc, secret_hex)
            body = (bytes(range(256)) * (body_size // 256 + 1))[:body_size]
            prefix = b"\x7f" + (len(body) // 4).to_bytes(3, "little") if tag == 0xefefefef else struct.pack("<I", len(body))
            packet = prefix + body
            # Two packets, split inside both the header and body; pipeline with nonce.
            stream = enc.apply(packet * repeats)
            chunks = [nonce + stream[:2], stream[2:100], stream[100:]]
            for chunk in chunks:
                for offset in range(0, len(chunk), 16000):
                    part = chunk[offset:offset + 16000]
                    conn.sendall(e2e.build_tls_record(e2e.TLS_RECORD_APPLICATION, part) if fake_tls else part)
            output = bytearray()
            while len(output) < len(packet) * repeats:
                if fake_tls:
                    header = e2e.recv_exact(conn, 5)
                    data = e2e.recv_exact(conn, int.from_bytes(header[3:], "big"))
                    if header[0] != e2e.TLS_RECORD_APPLICATION:
                        continue
                else:
                    data = conn.recv(65536)
                    self.assertTrue(data, proxy.read_log_tail())
                output.extend(dec.apply(data))
            self.assertEqual(bytes(output), packet * repeats)
        self.assertFalse(self.endpoint.errors, self.endpoint.errors)

    def test_direct_obfuscated(self):
        self.exchange(self.start())

    def test_cf_wss_route(self):
        if not self.cf_tests:
            self.skipTest("pass --cf-tests with kwsN.cf.test mapped to loopback")
        self.exchange(self.start(cf=True), fake_tls=True, dc=2)
        self.assertIn(("kws2.cf.test", b"kws2.cf.test"), self.endpoint.routes)

    def test_cf_h2_media_flow_control_and_concurrency(self):
        if not self.cf_tests:
            self.skipTest("pass --cf-tests with kwsN.cf.test mapped to loopback")
        # More than eight requests, each larger than the HTTP/2 initial window.
        self.exchange(self.start(cf=True), fake_tls=True, dc=-2, tag=0xeeeeeeee, repeats=12, body_size=128*1024)
        self.assertIn(("h2", b"kws2.cf.test"), self.endpoint.routes)

    def test_cf_h2_padded_media(self):
        if not self.cf_tests:
            self.skipTest("pass --cf-tests with kwsN.cf.test mapped to loopback")
        proxy = self.start(cf=True)
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as conn:
            conn.settimeout(5)
            nonce, enc, dec = client_init(0xdddddddd, -2)
            # A valid unencrypted MTProto envelope plus three padding bytes.
            body = b"\0" * 16 + struct.pack("<I", 20) + bytes(range(20))
            conn.sendall(nonce + enc.apply(struct.pack("<I", len(body) + 3) + body + b"pad"))
            header = dec.apply(e2e.recv_exact(conn, 4))
            length = int.from_bytes(header, "little")
            reply = dec.apply(e2e.recv_exact(conn, length))
            self.assertEqual(reply[:len(body)], body)
            self.assertLessEqual(len(reply) - len(body), 3)
        self.assertFalse(self.endpoint.errors, self.endpoint.errors)

    def test_multiple_users_concurrent_cf_wss_and_h2(self):
        if not self.cf_tests:
            self.skipTest("pass --cf-tests with kwsN.cf.test mapped to loopback")
        from concurrent.futures import ThreadPoolExecutor
        other_secret = "ffeeddccbbaa99887766554433221100"
        proxy = self.start(cf=True, second_user=other_secret)
        with ThreadPoolExecutor(max_workers=4) as pool:
            checks = [pool.submit(self.exchange, proxy, fake_tls=True, dc=dc,
                                  tag=0xeeeeeeee, secret_hex=secret)
                      for secret in [e2e.DEFAULT_SECRET_HEX, other_secret]
                      for dc in [2, -2]]
            for check in checks:
                check.result()

    def test_fake_tls_media(self):
        self.exchange(self.start(), fake_tls=True, dc=-2, tag=0xeeeeeeee)
        self.assertIn(("kws2-1.web.telegram.org", b"kws2-1.web.telegram.org"), self.endpoint.routes)

    def test_abridged_transport(self):
        self.exchange(self.start(), fake_tls=True, tag=0xefefefef)

    def test_large_packet(self):
        self.exchange(self.start(), fake_tls=True, body_size=256 * 1024)

    def test_close_preserves_last_reply(self):
        self.endpoint.mode = "close"
        self.exchange(self.start(), repeats=1)

    def test_redirect_retries_alternate_sni(self):
        self.endpoint.mode = "redirect"
        self.exchange(self.start(fronting=True))
        self.assertIn(("sprinthost.ru", b"kws2.web.telegram.org"), self.endpoint.routes)

    def test_fronting_hostname_mismatch_fails_closed(self):
        self.endpoint.mode = "redirect"
        self.assert_closed(self.start(fronting=True, sni="other.example.com"))

    def test_explicit_chain_only_fronting(self):
        self.endpoint.mode = "redirect"
        self.exchange(self.start(fronting=True, sni="other.example.com", verify_hostname=False))
        self.assertIn(("other.example.com", b"kws2.web.telegram.org"), self.endpoint.routes)

    def test_bad_upgrade_fails_closed(self):
        self.endpoint.mode = "bad_accept"
        self.assert_closed(self.start())

    def test_untrusted_certificate_fails_closed(self):
        self.assert_closed(self.start(trust=False))

    def assert_closed(self, proxy):
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as conn:
            conn.settimeout(5)
            nonce, _, _ = client_init(0xdddddddd, 2)
            conn.sendall(nonce)
            self.assertEqual(conn.recv(1), b"", proxy.read_log_tail())

    def test_prewarmed_pool(self):
        proxy = self.start(pool=1)
        self.assertTrue(e2e.wait_for_condition(lambda: self.endpoint.connections >= self.pool_baseline + 12, timeout_sec=5))
        self.exchange(proxy)
        self.exchange(proxy)
        self.assertIn("Telegram WS pool hit", proxy.read_log_tail(200))

    def run(self, result=None):
        self.pool_baseline = self.endpoint.connections
        return super().run(result)



def assert_standalone_elf(path):
    """Reject an ELF interpreter or a shared-library dependency before isolation."""
    data = path.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01", "expected a little-endian ELF64 binary"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    for i in range(count):
        header = offset + i * size
        kind = struct.unpack_from("<I", data, header)[0]
        assert kind != 3, "proxy still needs a dynamic ELF interpreter"
        if kind == 2:
            start = struct.unpack_from("<Q", data, header + 8)[0]
            length = struct.unpack_from("<Q", data, header + 32)[0]
            for entry in range(start, start + length, 16):
                tag = struct.unpack_from("<Q", data, entry)[0]
                assert tag != 1, "proxy still has a DT_NEEDED shared library"


def isolated_launcher(folder, proxy):
    """Exec each proxy in an empty root, with only config and explicit test CA."""
    assert_standalone_elf(proxy)
    launcher = Path(folder) / "launch-isolated-proxy"
    launcher.write_text(f"#!{sys.executable}\n" + """import os, pathlib, shutil, sys
config = pathlib.Path(sys.argv[1])
root = config.parent / 'isolated-root'
root.mkdir()
shutil.copyfile(config, root / 'config.toml')
shutil.copyfile(PROXY, root / 'proxy')
(root / 'proxy').chmod(0o755)
if 'SSL_CERT_FILE' in os.environ:
    shutil.copyfile(os.environ['SSL_CERT_FILE'], root / 'test-ca.pem')
    os.environ['SSL_CERT_FILE'] = '/test-ca.pem'
os.chroot(root)
os.chdir('/')
os.execv('/proxy', ['/proxy', '/config.toml'])
""".replace("PROXY", repr(str(proxy))))
    launcher.chmod(0o755)
    return launcher


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", type=Path, default=ROOT / "zig-out/bin/mtproto-proxy")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--isolated-runtime", action="store_true", help="Run proxy in an empty chroot: no libssl, dynamic loader, system CAs or /proc (root required)")
    parser.add_argument("--cf-tests", action="store_true", help="Also test CF WSS/H2; map kws1..5.cf.test and kws203.cf.test to 127.0.0.1")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ws-transport-e2e-") as folder:
        cert, key = args.cert, args.key
        if cert is None:
            cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=ws-transport-test", "-addext", "subjectAltName=DNS:*.web.telegram.org,DNS:sprinthost.ru,DNS:*.cf.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        e2e.ACTIVE_PROXY_BIN = isolated_launcher(folder, args.proxy.resolve()) if args.isolated_runtime else args.proxy.resolve()
        TransportTests.cert = cert.resolve()
        TransportTests.cf_tests = args.cf_tests
        endpoint = Endpoint(cert, key)
        TransportTests.endpoint = endpoint
        try:
            result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests))
        finally:
            endpoint.close()
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
