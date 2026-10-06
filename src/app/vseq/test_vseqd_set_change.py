#!/usr/bin/env python3
"""End-to-end test of a validator set change on a local vseqd cluster.

Five validators, 64-slot epochs.  The config (cluster.toml) says that
at epoch 1 (slot 64) validator 0 leaves and validator 4 joins.  Node 3
runs the old release's config (cluster-old.toml: validators 0-3, no
change), so from epoch 1 on its set differs and the others must cut
it off.  That leaves validators 1, 2 and 4 of the new set {1,2,3,4}:
75% if the joiner votes, 50% (no finality) if it does not.

Checks:
  - the network keeps finalizing after the switch
  - the joiner reports a rank in the new set
  - node 3 is cut off ("different validator set") and stops finalizing
  - the SDK, given cluster.toml, verifies the chain from genesis
    through the switch (certs of epoch 1 are checked against the new set)
  - txs sent after the switch are finalized

Usage: test_vseqd_set_change.py --vseqd PATH --lib libvseq_client.so
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk", "python"))
from vseq import GENESIS, Network, Vseq, frame_txs  # noqa: E402
from test_vseqd_cluster import http_get, http_post  # noqa: E402

EPOCH_SLOTS = 64
CHANGE_EPOCH = 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vseqd", required=True)
    ap.add_argument("--lib", required=True)
    ap.add_argument("--duration", type=float, default=50.0)
    ap.add_argument("--base-port", type=int, default=19400)
    ap.add_argument("--api-base-port", type=int, default=18400)
    ap.add_argument("--blocks-base-port", type=int, default=18900)
    args = ap.parse_args()

    d = tempfile.mkdtemp(prefix="vseq-setchange-")
    subprocess.run([args.vseqd, "gen-cluster", "--nodes", "5", "--dir", d, "--genesis-delay-s", "3",
                    "--base-port", str(args.base_port), "--api-base-port", str(args.api_base_port),
                    "--blocks-base-port", str(args.blocks_base_port), "--log-path", ""], check=True, capture_output=True)

    # Validator entries in the order gen-cluster wrote them (node i is entry i)
    text = open(f"{d}/cluster.toml").read()
    head, *entries = text.split("\n[[validator]]\n")
    head = "\n".join(f"epoch_slots     = {EPOCH_SLOTS}" if line.startswith("epoch_slots") else line
                     for line in head.splitlines())
    entry = lambda i, extra="": "\n[[validator]]\n" + entries[i].rstrip("\n") + "\n" + extra
    with open(f"{d}/cluster-old.toml", "w") as f:
        f.write(head + "".join(entry(i) for i in range(4)))
    with open(f"{d}/cluster.toml", "w") as f:
        f.write(head + entry(0, f"until_epoch = {CHANGE_EPOCH}\n") + entry(1) + entry(2) + entry(3)
                + entry(4, f"from_epoch = {CHANGE_EPOCH}\n"))

    procs = []
    for i in range(5):
        cfg = f"{d}/cluster-old.toml" if i == 3 else f"{d}/cluster.toml"
        procs.append(subprocess.Popen(
            [args.vseqd, "run", "--cluster", cfg, "--key", f"{d}/node-{i}.toml", "--ledger", f"{d}/ledger-{i}",
             "--api-port", str(args.api_base_port + i), "--log-path", ""],
            stdout=open(f"{d}/node-{i}.log", "w"), stderr=subprocess.STDOUT))
        procs.append(subprocess.Popen(
            [args.vseqd, "blocks", "--cluster", cfg, "--ledger", f"{d}/ledger-{i}",
             "--port", str(args.blocks_base_port + i), "--log-path", ""],
            stdout=open(f"{d}/blocks-{i}.log", "w"), stderr=subprocess.STDOUT))

    fail = []
    net = Network.from_toml(f"{d}/cluster.toml")
    switch_s = net.genesis_time_ms / 1000 + CHANGE_EPOCH * EPOCH_SLOTS * net.slot_ms / 1000
    try:
        # Send a tx to every node now and then; record the ones sent after the switch
        sent_after, tx_id, end = [], 0, time.time() + args.duration
        while time.time() < end:
            tx = b"tx-%d" % tx_id
            for i in (0, 1, 2, 4):
                http_post(args.api_base_port + i, "/txs", frame_txs([tx]))
            if time.time() > switch_s + 2:
                sent_after.append(tx)
            tx_id += 1
            time.sleep(0.1)
        time.sleep(2.0)

        st = {i: http_get(args.api_base_port + i, "/status") for i in range(5)}
        for i, s in st.items():
            print(f"  node {i}: slot {s['finalized_slot']}, set from epoch {s['set_epoch']}, rank {s['rank']}, "
                  f"peers {s['peers_connected']}")
        switch_slot = CHANGE_EPOCH * EPOCH_SLOTS
        for i in (1, 2, 4):
            if st[i]["finalized_slot"] < switch_slot + 30:
                fail.append(f"LIVENESS: node {i} finalized only up to slot {st[i]['finalized_slot']}")
        if st[4]["rank"] < 0 or st[4]["set_epoch"] != CHANGE_EPOCH:
            fail.append("the joining validator has no rank in the new set")
        if st[0]["rank"] >= 0 and st[0]["set_epoch"] == CHANGE_EPOCH:
            fail.append("the leaving validator still has a rank")
        if st[3]["finalized_slot"] > switch_slot + 8:
            fail.append(f"node 3 with the old config kept finalizing (slot {st[3]['finalized_slot']})")
        logs = "".join(open(f"{d}/node-{i}.log").read() for i in range(5))
        if "different validator set" not in logs:
            fail.append("nobody cut off node 3")

        # Verify the chain from genesis through the switch, as a client
        vs = Vseq(net, lib_path=args.lib)
        last, seen = None, set()
        for blk in vs.batches(after=GENESIS, deadline=time.time() + 20):
            last = blk
            seen.update(blk.txs)
            if blk.slot >= st[1]["finalized_slot"]:
                break
        if not last or last.slot < switch_slot + 30:
            fail.append(f"SDK verified only up to slot {last.slot if last else None}")
        else:
            print(f"SDK verified the chain from genesis to slot {last.slot}, across the switch at slot {switch_slot}")
        missing = [t for t in sent_after if t not in seen]
        if len(missing) > 0.05 * max(len(sent_after), 1):
            fail.append(f"{len(missing)} of {len(sent_after)} txs sent after the switch were not finalized")
        print(f"txs after the switch: {len(sent_after)} sent, {len(sent_after) - len(missing)} finalized")
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    for f in fail:
        print("FAIL:", f)
    print(("FAIL, logs in " + d) if fail else "pass")
    if not fail:
        shutil.rmtree(d)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
