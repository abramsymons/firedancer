#!/usr/bin/env python3
"""Latency benchmark of a vseqd cluster.

Starts N vseqd nodes (and their blocks servers) on localhost, or uses a
running cluster with --cluster, sends txs of --tx-size bytes at --rate
tx/s for --secs with the Python SDK, reads the verified finalized blocks
with the SDK, and prints how long each tx took from send to final:

  bench_vseqd.py --vseqd PATH --lib PATH [--nodes 5] [--slot-ms 10]
                 [--rate 400] [--tx-size 256] [--secs 5] [--batch-ms 5]
                 [--local-read [DIR]] [--dir DIR]
  bench_vseqd.py --cluster cluster.toml --lib PATH [--local-read DIR] ...

With --local-read the blocks are read from a node's ledger directory
on this machine every 1 ms, unverified, instead of /blocks over HTTP
(by default node 0's of the local cluster).

The sender runs in its own process; one Python process sends up to
about 10k tx/s.  All nodes share this machine's disk: a disk with slow
or stalling fsync shows up directly in the tail (see DESIGN.md).
"""
import argparse
import multiprocessing as mp
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk", "python"))
from vseq import Network, Vseq  # noqa: E402

MAGIC = b"VB"  # tx = MAGIC, u64 sequence number, padding


def sender(args, cluster, start, out):
    vs = Vseq(Network.from_toml(cluster), lib_path=args.lib)
    pad = bytes(args.tx_size - 10)
    sent, seq, k = [], 0, 0
    while True:
        t = start + k * args.batch_ms / 1000
        if t - start >= args.secs:
            break
        if t > time.time():
            time.sleep(t - time.time())
        cnt = int(args.rate * (t - start + args.batch_ms / 1000)) - seq  # exact rate over time
        if cnt > 0:
            t_send = time.time()
            vs.send([MAGIC + struct.pack("<Q", seq + i) + pad for i in range(cnt)])
            sent.append((seq, cnt, t_send))
            seq += cnt
        k += 1
    out.put((sent, time.time() - start))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vseqd", help="vseqd binary, to start a local cluster")
    ap.add_argument("--cluster", help="cluster.toml of a running cluster: do not start nodes")
    ap.add_argument("--lib", required=True, help="libvseq_client.so")
    ap.add_argument("--nodes", type=int, default=5)
    ap.add_argument("--slot-ms", type=int, default=10)
    ap.add_argument("--rate", type=int, default=400, help="txs per second")
    ap.add_argument("--tx-size", type=int, default=256)
    ap.add_argument("--secs", type=float, default=5)
    ap.add_argument("--batch-ms", type=float, default=5, help="send the txs of this long in one call")
    ap.add_argument("--local-read", nargs="?", const="", metavar="DIR",
                    help="read this node ledger dir every 1 ms, unverified, instead of /blocks over HTTP")
    ap.add_argument("--dir", default=None)
    ap.add_argument("--base-port", type=int, default=19000)
    ap.add_argument("--api-base-port", type=int, default=18000)
    ap.add_argument("--blocks-base-port", type=int, default=18500)
    args = ap.parse_args()
    if args.tx_size < 10:
        ap.error("--tx-size must be at least 10")
    if not args.cluster and not args.vseqd:
        ap.error("pass --vseqd to start a local cluster, or --cluster for a running one")
    if args.cluster and args.local_read == "":
        ap.error("with --cluster, --local-read needs the node's ledger dir")
    if args.cluster:
        run(args, args.cluster, args.local_read, None)
        return

    d = args.dir or tempfile.mkdtemp(prefix="vseq-bench-")
    if os.path.exists(d):
        shutil.rmtree(d)
    subprocess.run([args.vseqd, "gen-cluster", "--nodes", str(args.nodes), "--dir", d, "--genesis-delay-s", "4",
                    "--base-port", str(args.base_port), "--api-base-port", str(args.api_base_port),
                    "--blocks-base-port", str(args.blocks_base_port), "--log-path", ""],
                   check=True, capture_output=True)
    cluster = f"{d}/cluster.toml"
    with open(cluster) as f:
        toml = re.sub(r"(?m)^slot_ms\s*=.*$", f"slot_ms = {args.slot_ms}", f.read())
    with open(cluster, "w") as f:
        f.write(toml)

    procs = []
    for i in range(args.nodes):
        procs.append(subprocess.Popen([args.vseqd, "run", "--cluster", cluster, "--key", f"{d}/node-{i}.toml",
                                       "--ledger", f"{d}/ledger-{i}", "--api-port", str(args.api_base_port + i),
                                       "--log-path", ""], stdout=open(f"{d}/node-{i}.log", "w"), stderr=subprocess.STDOUT))
        procs.append(subprocess.Popen([args.vseqd, "blocks", "--cluster", cluster, "--ledger", f"{d}/ledger-{i}",
                                       "--port", str(args.blocks_base_port + i), "--log-path", ""],
                                      stdout=open(f"{d}/blocks-{i}.log", "w"), stderr=subprocess.STDOUT))
    try:
        run(args, cluster, f"{d}/ledger-0" if args.local_read == "" else args.local_read, d)
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if not args.dir:
            shutil.rmtree(d, ignore_errors=True)


def run(args, cluster, ledger, logs):
    """Send and read against cluster; ledger: local ledger dir to read, or None."""
    net = Network.from_toml(cluster)
    vs = Vseq(net, lib_path=args.lib)
    deadline = time.time() + 30
    while True:  # wait until consensus runs
        try:
            if vs.get_last_finalized().slot > 20:
                break
        except Exception:
            pass
        if time.time() > deadline:
            sys.exit("cluster did not start finalizing" + (f"; see the logs in {logs}" if logs else ""))
        time.sleep(0.2)
    seen = {}
    done = threading.Event()

    def reader():
        try:
            for blk in vs.batches(after=vs.get_last_finalized(), poll_interval=0.001 if ledger else 0.0005, ledger=ledger):
                now = time.time()
                for tx in blk.txs:
                    if tx[:2] == MAGIC:
                        seen.setdefault(struct.unpack_from("<Q", tx, 2)[0], now)
                if done.is_set():
                    return
        except Exception:
            if not done.is_set():  # the nodes stopping after the run is expected
                raise

    threading.Thread(target=reader, daemon=True).start()
    out = mp.Queue()
    p = mp.Process(target=sender, args=(args, cluster, time.time() + 0.5, out))
    p.start()
    sent, send_secs = out.get()
    p.join()
    total = sum(cnt for _, cnt, _ in sent)
    deadline = time.time() + 10
    while len(seen) < total and time.time() < deadline:
        time.sleep(0.05)
    done.set()

    lat = sorted((seen[s + i] - t) * 1e3 for s, cnt, t in sent for i in range(cnt) if s + i in seen)
    if not lat:
        sys.exit("no tx was finalized" + (f"; see the logs in {logs}" if logs else ""))
    q = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]  # noqa: E731
    print(f"{len(net.validators)} nodes, {net.slot_ms} ms slots: sent {total / send_secs:,.0f} tx/s x {args.tx_size} B "
          f"({total:,} txs in {send_secs:.1f} s), finalized {len(lat):,}, missing {total - len(lat)}")
    print(f"send to final, ms: min {lat[0]:.1f}  p50 {q(.5):.1f}  p90 {q(.9):.1f}  p99 {q(.99):.1f}  max {lat[-1]:.1f}")


if __name__ == "__main__":
    main()
