#!/usr/bin/env python3
"""Tests the Python SDK against a local vseqd cluster.

Starts N vseqd nodes, then checks that the SDK:
  * computes the same leader schedule as the nodes
  * sends txs to leaders and sees them finalized (blocking send)
  * reads and verifies the whole chain from genesis
  * rejects tampered txs, forged or missing certs, and the wrong network
  * skips a lying node (an HTTP proxy that rewrites txs) and keeps going

Usage:
  test_sdk.py --vseqd PATH --lib PATH/libvseq_client.so [--nodes 4] [--dir DIR]
"""

import argparse
import dataclasses
import copy
import http.server
import os
import shutil
import signal
import subprocess
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vseq import (GENESIS, Network, VerificationError, Vseq, decode_blocks,  # noqa: E402
                  frame_txs, payload_hash, payload_txs)


def with_first_tx(r, tx):
    """RawBlock r with its first tx replaced (hash left as is)."""
    return dataclasses.replace(r, payload=frame_txs([tx] + payload_txs(r.payload)[1:]))


def encode_blocks(finalized, blocks):
    """The inverse of decode_blocks, to serve tampered blocks."""
    recs = []
    for b in blocks:
        body = struct.pack("<QQ32s32s64sI", b.slot, b.parent_slot, b.parent_hash, b.hash, b.sig, len(b.payload))
        body += b.payload + struct.pack("<I", len(b.proof)) + b.proof
        recs.append(struct.pack("<I", len(body)) + body)
    return struct.pack("<4sB3xQI", b"VSQB", 1, finalized, len(blocks)) + b"".join(recs)

results = []


def check(name, fn):
    try:
        fn()
        results.append((name, None))
        print(f"  ok    {name}")
    except Exception as e:  # report and continue with the other checks
        results.append((name, e))
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")


def expect_reject(fn, needle):
    try:
        fn()
    except VerificationError as e:
        if needle not in str(e):
            raise AssertionError(f"rejected for the wrong reason: {e}") from e
        return
    raise AssertionError("tampered data was accepted")


class LyingProxy(http.server.ThreadingHTTPServer):
    """Forwards to a real node but replaces the first tx of every block in /blocks."""

    def __init__(self, upstream):
        self.upstream = upstream
        self.lies = 0
        super().__init__(("127.0.0.1", 0), LyingHandler)


class LyingHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _relay(self, body=None):
        req = urllib.request.Request(self.server.upstream + self.path, data=body,
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        if self.path.startswith("/blocks?") and code == 200:
            finalized, blocks = decode_blocks(data)
            for i, b in enumerate(blocks):
                if payload_txs(b.payload):
                    blocks[i] = with_first_tx(b, b"evil")
                    self.server.lies += 1
            data = encode_blocks(finalized, blocks)
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._relay()

    def do_POST(self):
        self._relay(self.rfile.read(int(self.headers.get("Content-Length", 0))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vseqd", required=True)
    ap.add_argument("--lib", required=True)
    ap.add_argument("--nodes", type=int, default=4)
    ap.add_argument("--dir", default=None)
    ap.add_argument("--base-port", type=int, default=19100)
    ap.add_argument("--api-base-port", type=int, default=18100)
    ap.add_argument("--blocks-base-port", type=int, default=18200)
    args = ap.parse_args()

    d = args.dir or tempfile.mkdtemp(prefix="vseq-sdk-")
    if os.path.exists(d):
        shutil.rmtree(d)
    subprocess.run([args.vseqd, "gen-cluster", "--nodes", str(args.nodes), "--dir", d, "--base-port",
                    str(args.base_port), "--api-base-port", str(args.api_base_port),
                    "--blocks-base-port", str(args.blocks_base_port), "--log-path", ""],
                   check=True, capture_output=True)

    def new_key(name, *limits):
        out = subprocess.run([args.vseqd, "api-key", "--name", name, *limits, "--log-path", ""],
                             check=True, capture_output=True, text=True).stdout
        return out.splitlines()[1].lstrip("# "), out[out.index("[[dapp]]"):]
    key, entry = new_key("test")
    slow_key, slow_entry = new_key("slow", "--requests-per-s", "2")
    with open(f"{d}/api-keys.toml", "w") as f:
        f.write(entry + "\n" + slow_entry)
    procs = []
    for i in range(args.nodes):
        log = open(f"{d}/node-{i}.log", "w")
        procs.append(subprocess.Popen(
            [args.vseqd, "run", "--cluster", f"{d}/cluster.toml", "--key", f"{d}/node-{i}.toml",
             "--ledger", f"{d}/ledger-{i}", "--api-port", str(args.api_base_port + i), "--log-path", "",
             "--api-keys", f"{d}/api-keys.toml"],
            stdout=log, stderr=subprocess.STDOUT))
        procs.append(subprocess.Popen(
            [args.vseqd, "blocks", "--cluster", f"{d}/cluster.toml", "--ledger", f"{d}/ledger-{i}",
             "--port", str(args.blocks_base_port + i), "--api-keys", f"{d}/api-keys.toml", "--log-path", ""],
            stdout=open(f"{d}/blocks-{i}.log", "w"), stderr=subprocess.STDOUT))

    try:
        net = Network.from_toml(f"{d}/cluster.toml")
        vs = Vseq(net, api_key=key, lib_path=args.lib)

        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                st = [vs.status(v.api) for v in net.validators]
                if all(s["peers_connected"] == args.nodes - 1 and s.get("state") == "running" for s in st):
                    break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise SystemExit(f"cluster did not come up, logs in {d}")
        print(f"cluster up: {args.nodes} nodes, network {net.network_id}, logs in {d}")

        def api_keys():
            def code(k):
                try:
                    Vseq(net, api_key=k, lib_path=args.lib).status(net.validators[0].api)
                    return 200
                except urllib.error.HTTPError as e:
                    return e.code
            assert code(None) == 403, "no key accepted"
            assert code("0" * 64) == 403, "unknown key accepted"
            codes = [code(slow_key) for _ in range(4)]
            assert codes[:2] == [200, 200] and 400 in codes, codes
        check("API keys and rate limits", api_keys)

        def leader_schedule():
            idx_of_rank = {s["rank"]: i for i, s in enumerate(st)}
            for slot in range(0, 8 * args.nodes * 4, 3):
                want = net.validators[idx_of_rank[(slot // 4) % args.nodes]]
                assert vs.leader(slot) == want, f"slot {slot}"
        check("leader schedule matches the nodes", leader_schedule)

        time.sleep(3.0)  # let a few windows (and leaders) go by
        sent, state = [], {}

        def blocking_send():
            lat = []
            for r in range(5):
                txs = [f"tx-{r}-{i}-{time.time()}".encode() for i in range(20)]
                sent.extend(txs)
                t0 = time.time()
                state["slot"] = vs.send(txs, blocking=True, timeout=20)
                lat.append(time.time() - t0)
                time.sleep(0.7)
            print(f"        5 rounds of 20 txs, last finalized in slot {state['slot']}, "
                  f"send-to-final {min(lat):.2f}-{max(lat):.2f}s")
        check("send(blocking=True) returns once txs are final", blocking_send)

        def read_from_genesis():
            seen, blocks, prev = set(), 0, GENESIS
            for blk in vs.batches(deadline=time.time() + 10):
                assert blk.parent_slot == prev.slot and blk.parent_hash == prev.hash
                prev = blk
                blocks += 1
                seen.update(blk.txs)
                if blk.slot >= state["slot"]:
                    break
            assert set(sent) <= seen, f"{len(set(sent) - seen)} txs missing"
            state["blocks"] = blocks
            print(f"        {blocks} blocks verified from genesis to slot {prev.slot}")
        check("batches() verifies the chain from genesis", read_from_genesis)

        def last_finalized():
            tip = vs.get_last_finalized()
            assert tip.slot >= state["slot"]
        check("get_last_finalized() is verified by its own certs", last_finalized)

        raw = vs._get_blocks(net.validators[0].blocks, 0, max(state.get("blocks", 8), 8))[1]
        with_txs = [i for i, b in enumerate(raw) if payload_txs(b.payload)]

        def tampered_tx():
            r = list(raw)
            r[with_txs[0]] = with_first_tx(r[with_txs[0]], b"evil")
            expect_reject(lambda: vs.verify_blocks(GENESIS, r), "hash does not match")
        check("rejects a changed tx", tampered_tx)

        def tampered_tx_rehashed():
            # Change a tx and fix up the hash: the next block or the certs must catch it.
            r = list(raw[:with_txs[0] + 1])
            b = with_first_tx(r[-1], b"evil")
            r[-1] = dataclasses.replace(b, hash=payload_hash(b.slot, b.parent_slot, b.parent_hash, b.payload))
            expect_reject(lambda: vs.verify_blocks(GENESIS, r), "cert for another slot, block or network")
        check("rejects a changed tx with a recomputed hash", tampered_tx_rehashed)

        def forged_cert():
            r = list(raw)
            proof = bytearray(r[-1].proof)
            proof[-10] ^= 1  # inside the last cert's aggregate signature
            r[-1] = dataclasses.replace(r[-1], proof=bytes(proof))
            try:
                vs.verify_blocks(GENESIS, r)
            except VerificationError:
                return
            raise AssertionError("forged cert accepted")
        check("rejects a forged cert", forged_cert)

        def missing_certs():
            r = list(raw)
            r[-1] = dataclasses.replace(r[-1], proof=b"")
            expect_reject(lambda: vs.verify_blocks(GENESIS, r), "certs do not finalize the block")
        check("rejects a block without certs", missing_certs)

        def malformed_response():
            body = encode_blocks(0, raw)
            for bad in (body[:-1], body + b"x", b"VSQB\x02" + body[5:]):
                try:
                    decode_blocks(bad)
                except ValueError:
                    continue
                raise AssertionError("malformed /blocks body accepted")
        check("rejects malformed /blocks bodies", malformed_response)

        def wrong_network():
            other = Vseq(Network(1 + net.network_id % 65535, net.validators, net.epoch_slots), api_key=key, lib_path=args.lib)
            expect_reject(lambda: other.verify_blocks(GENESIS, raw), "cert for another slot, block or network")
        check("rejects certs from another network", wrong_network)

        def lying_node():
            proxy = LyingProxy(net.validators[0].blocks)
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            vals = list(net.validators)
            vals[0] = type(vals[0])(stake=vals[0].stake, identity=vals[0].identity, bls=vals[0].bls,
                                     api=vals[0].api, blocks=f"http://127.0.0.1:{proxy.server_address[1]}")
            liar = Vseq(Network(net.network_id, vals, net.epoch_slots), api_key=key, lib_path=args.lib)
            liar._nodes = lambda kind="api": [getattr(v, kind) for v in vals]  # ask the liar first
            got = 0
            for blk in liar.batches(deadline=time.time() + 15):
                got += 1
                if blk.slot >= state["slot"]:
                    break
            proxy.shutdown()
            assert vals[0].blocks in liar.bad_nodes, "liar was never detected"
            assert proxy.lies > 0
            print(f"        read {got} verified blocks; liar flagged: {liar.bad_nodes[vals[0].blocks]}")
        check("skips a lying node and keeps reading", lying_node)

    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    failed = [n for n, e in results if e]
    print("FAIL" if failed else "pass", f"({len(results) - len(failed)}/{len(results)} checks)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
