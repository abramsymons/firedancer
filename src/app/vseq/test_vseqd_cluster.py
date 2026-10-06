#!/usr/bin/env python3
"""End-to-end test of a local vseqd cluster.

Starts N vseqd processes on localhost, sends txs to upcoming leaders the
way the SDK will, optionally kills one node halfway through, and checks:

  safety:    every running node finalized the same blocks (slot, hash,
             parent, txs) on their common prefix
  liveness:  finalization advanced, and almost all txs were finalized
  schedule:  the leader schedule computed here from cluster.toml matches
             the ranks the nodes report

Usage:
  test_vseqd_cluster.py --vseqd PATH [--nodes 4] [--duration 20]
                        [--rate 100] [--kill-one] [--restart-one]
                        [--restart-all] [--rejoin-empty] [--dir DIR]
                        [--segment-kb KB] [--retain-slots N]

  --restart-one  SIGKILL the highest rank node at 1/3 of the run and
                 start it again at 2/3 (it must catch up from peers)
  --restart-all  SIGKILL every node at 1/2 of the run, start them all
                 again a second later
  --rejoin-empty like --restart-one, but the node's ledger directory is
                 deleted while it is down (its vote history is kept);
                 with --retain-slots its peers have pruned genesis by
                 then, so its ledger starts at their oldest kept block

  test_vseqd_cluster.py --external --dir CLUSTER_DIR [--api-base-port 18000]
      tests a running cluster (e.g. docker/local_cluster.sh) whose node i
      serves its API on api-base-port+i
"""

import argparse
import json
import os
import random
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk", "python"))
from vseq import decode_blocks, frame_txs, payload_txs  # noqa: E402

SLOTS_PER_WINDOW = 4


def http_get(port, path, timeout=2.0):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
        return json.loads(r.read())


def http_post(port, path, body, timeout=2.0):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return None


def rank_validators(validators):
    """Rank like vseq_epoch_build: stake descending, then BLS key bytes."""
    order = sorted(range(len(validators)),
                   key=lambda i: (-validators[i]["stake"], bytes.fromhex(validators[i]["bls"])))
    rank_of = [0] * len(validators)
    for rank, i in enumerate(order):
        rank_of[i] = rank
    return rank_of


def leader_rank(slot, n):
    """ag_epoch_info_leader: window % validator count."""
    return (slot // SLOTS_PER_WINDOW) % n


def fetch_all_blocks(api_port, blocks_port):
    blocks, after = [], http_get(api_port, "/status").get("ledger_base_slot", 0)
    while True:
        with urllib.request.urlopen(f"http://127.0.0.1:{blocks_port}/blocks?after={after}", timeout=10.0) as r:
            raw = decode_blocks(r.read())[1]
        if not raw:
            return blocks
        blocks += [{"slot": b.slot, "hash": b.hash, "parent_slot": b.parent_slot, "parent_hash": b.parent_hash,
                    "txs": payload_txs(b.payload)} for b in raw]
        after = raw[-1].slot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vseqd")
    ap.add_argument("--external", action="store_true", help="test a running cluster, do not start nodes")
    ap.add_argument("--nodes", type=int, default=4)
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--rate", type=float, default=100.0, help="txs per second")
    ap.add_argument("--kill-one", action="store_true", help="SIGKILL the highest rank node halfway through")
    ap.add_argument("--restart-one", action="store_true")
    ap.add_argument("--restart-all", action="store_true")
    ap.add_argument("--rejoin-empty", action="store_true")
    ap.add_argument("--segment-kb", type=int, default=0)
    ap.add_argument("--retain-slots", type=int, default=0)
    ap.add_argument("--history", default=None, help="recent or full, passed to every node")
    ap.add_argument("--slot-max", type=int, default=0, help="passed to every node (memory is ~11.5 MB per slot)")
    ap.add_argument("--dir", default=None)
    ap.add_argument("--base-port", type=int, default=19000)
    ap.add_argument("--api-base-port", type=int, default=18000)
    ap.add_argument("--blocks-base-port", type=int, default=18500)
    args = ap.parse_args()

    if args.external:
        if not args.dir or args.kill_one:
            ap.error("--external needs --dir and does not support --kill-one")
        d = args.dir
    else:
        if not args.vseqd:
            ap.error("--vseqd is required")
        d = args.dir or tempfile.mkdtemp(prefix="vseq-")
        if os.path.exists(d):
            shutil.rmtree(d)
        subprocess.run([args.vseqd, "gen-cluster", "--nodes", str(args.nodes), "--dir", d,
                        "--base-port", str(args.base_port), "--api-base-port", str(args.api_base_port),
                        "--blocks-base-port", str(args.blocks_base_port), "--log-path", ""],
                       check=True, capture_output=True)
    with open(f"{d}/cluster.toml", "rb") as f:
        cluster = tomllib.load(f)
    validators = cluster["validator"]
    n = len(validators)
    rank_of = rank_validators(validators)
    api_port_of_rank = [0] * n
    for i in range(n):
        api_port_of_rank[rank_of[i]] = args.api_base_port + i

    def launch(i):
        log = open(f"{d}/node-{i}.log", "a")
        return subprocess.Popen(
            [args.vseqd, "run", "--cluster", f"{d}/cluster.toml", "--key", f"{d}/node-{i}.toml",
             "--ledger", f"{d}/ledger-{i}", "--api-port", str(args.api_base_port + i), "--log-path", ""]
            + (["--ledger-segment-kb", str(args.segment_kb)] if args.segment_kb else [])
            + (["--ledger-retain-slots", str(args.retain_slots)] if args.retain_slots else [])
            + (["--history", args.history] if args.history else [])
            + (["--slot-max", str(args.slot_max)] if args.slot_max else []),
            stdout=log, stderr=subprocess.STDOUT)

    # Blocks servers keep running while their nodes restart or lose their ledgers.
    readers = [subprocess.Popen([args.vseqd, "blocks", "--cluster", f"{d}/cluster.toml", "--ledger", f"{d}/ledger-{i}",
                                 "--port", str(args.blocks_base_port + i), "--log-path", ""],
                                stdout=open(f"{d}/blocks-{i}.log", "a"), stderr=subprocess.STDOUT)
               for i in range(0 if args.external else n)]
    procs = [launch(i) for i in range(0 if args.external else n)]
    alive = set(range(n))
    fail = []

    def stop_all():
        if args.external:
            return
        everyone = [procs[i] for i in alive] + readers
        for p in everyone:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in everyone:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    try:
        # Wait for the mesh to come up and check the schedule.
        deadline = time.time() + 15
        while True:
            try:
                st = [http_get(args.api_base_port + i, "/status") for i in range(n)]
                if all(s["peers_connected"] == n - 1 and s.get("state", "running") == "running" for s in st):
                    break
            except OSError:
                pass
            if time.time() > deadline:
                stop_all()
                raise SystemExit(f"mesh did not come up, see logs in {d}")
            time.sleep(0.2)
        for i, s in enumerate(st):
            if s["rank"] != rank_of[i]:
                fail.append(f"node {i}: reports rank {s['rank']}, schedule here says {rank_of[i]}")
        print(f"mesh up: {n} nodes, network {st[0]['network_id']}, logs in {d}")

        # Send txs to the leaders of the next three windows.
        sent, refused, tx_id = {}, 0, 0
        start = time.time()
        killed = False
        restart_one = {"killed": None, "back": False}
        restart_all = {"killed": False, "back": False}
        while time.time() - start < args.duration:
            t = time.time() - start
            if (args.restart_one or args.rejoin_empty) and restart_one["killed"] is None and t > args.duration / 3:
                victim = rank_of.index(n - 1)
                procs[victim].kill()
                procs[victim].wait()
                alive.discard(victim)
                restart_one["killed"] = victim
                print(f"killed node {victim} (rank {n - 1}) at t={t:.1f}s")
                if args.rejoin_empty:
                    shutil.rmtree(f"{d}/ledger-{victim}")
                    print(f"deleted node {victim}'s ledger, kept its vote history")
            if (args.restart_one or args.rejoin_empty) and restart_one["killed"] is not None and not restart_one["back"] \
                    and t > 2 * args.duration / 3:
                victim = restart_one["killed"]
                procs[victim] = launch(victim)
                alive.add(victim)
                restart_one["back"] = True
                print(f"restarted node {victim} at t={t:.1f}s")
            if args.restart_all and not restart_all["killed"] and t > args.duration / 2:
                for i in range(n):
                    procs[i].kill()
                for i in range(n):
                    procs[i].wait()
                restart_all["killed"] = True
                restart_all["at"] = time.time()
                print(f"killed all nodes at t={t:.1f}s")
                time.sleep(1.0)
                for i in range(n):
                    procs[i] = launch(i)
                restart_all["back"] = True
                print(f"restarted all nodes at t={time.time() - start:.1f}s")
            if args.kill_one and not killed and time.time() - start > args.duration / 2:
                victim = rank_of.index(n - 1)
                procs[victim].kill()
                procs[victim].wait()
                alive.discard(victim)
                killed = True
                print(f"killed node {victim} (rank {n - 1}) at t={time.time() - start:.1f}s")
            src = random.choice(sorted(alive))
            try:
                slot = http_get(args.api_base_port + src, "/status")["finalized_slot"] + 1
            except OSError:
                continue
            tx = struct.pack("<Qd", tx_id, time.time()) + os.urandom(48)
            leaders = []
            for w in range(3):
                r = leader_rank(slot + w * SLOTS_PER_WINDOW, n)
                if r not in leaders:
                    leaders.append(r)
            ok = False
            for r in leaders:
                if http_post(api_port_of_rank[r], "/txs", frame_txs([tx])) == 200:
                    ok = True
            if ok:
                sent[tx_id] = time.time()
            else:
                refused += 1
            tx_id += 1
            time.sleep(1.0 / args.rate)

        time.sleep(3.0)  # let the last txs finalize
        if args.restart_one or args.rejoin_empty:
            # Give the restarted node time to catch up with the others.
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    st = {i: http_get(args.api_base_port + i, "/status") for i in sorted(alive)}
                    tips = [s["finalized_slot"] for s in st.values()]
                    if st[restart_one["killed"]]["state"] == "running" and max(tips) - min(tips) <= 8:
                        break
                except OSError:
                    pass
                time.sleep(0.5)

        # Compare the finalized chains.
        time.sleep(0.2)  # blocks servers pick up new records within ~20 ms
        chains = {i: fetch_all_blocks(args.api_base_port + i, args.blocks_base_port + i) for i in sorted(alive)}
        status = {i: http_get(args.api_base_port + i, "/status") for i in sorted(alive)}
        for i, st in status.items():
            if st["ledger_base_slot"] > 0:  # pruned history must be refused, not served or crashed on
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{args.blocks_base_port + i}/blocks?after=0", timeout=5)
                    fail.append(f"node {i}: served pruned history")
                except urllib.error.HTTPError as e:
                    if e.code != 400 or json.loads(e.read()).get("error") != "pruned":
                        fail.append(f"node {i}: pruned history answered {e.code}")
        ref_i = min(chains, key=lambda i: len(chains[i]))
        ref = chains[ref_i]

        # Certs are left out: each node aggregates its own (equally valid) signer set.
        def core(blk):
            return (blk["slot"], blk["hash"], blk["parent_slot"], blk["parent_hash"], blk["txs"])
        by_slot = {i: {b["slot"]: core(b) for b in chain} for i, chain in chains.items()}
        for i in chains:
            common = by_slot[ref_i].keys() & by_slot[i].keys()
            for slot in sorted(common):
                if by_slot[ref_i][slot] != by_slot[i][slot]:
                    fail.append(f"SAFETY: nodes {ref_i} and {i} differ at slot {slot}")
                    break
            chain = chains[i]
            prev = (chain[0]["parent_slot"], chain[0]["parent_hash"]) if chain else None
            for blk in chain:
                if (blk["parent_slot"], blk["parent_hash"]) != prev:
                    fail.append(f"node {i}: block {blk['slot']} does not extend {prev[0]}")
                    break
                prev = (blk["slot"], blk["hash"])

        finalized = {}
        full = max(chains, key=lambda i: len(chains[i]))  # txs before a pruned base are only on other nodes
        for blk in chains[full]:
            for t in blk["txs"]:
                tid = struct.unpack_from("<Q", t)[0]
                finalized.setdefault(tid, blk["slot"])
        # With pruning, only txs sent recently enough to still be kept everywhere can be checked.
        keep_s = args.retain_slots * cluster.get("slot_ms", 400) / 1000.0 * 0.7 if args.retain_slots else None
        missing = [t for t, ts in sent.items() if t not in finalized and (keep_s is None or ts >= time.time() - keep_s)]
        if restart_all["killed"]:
            # Txs not yet in a block live only in leaders' memory and die with them; clients resend.
            lost = [t for t in missing if restart_all["at"] - 2.0 <= sent[t] <= restart_all["at"]]
            missing = [t for t in missing if t not in lost]
            print(f"{len(lost)} txs sent in the 2 s before every node was killed were lost with them")
        elapsed = time.time() - start
        top = max(s["finalized_slot"] for s in status.values())
        print(f"finalized slot {min(s['finalized_slot'] for s in status.values())}-{top} after {elapsed:.0f}s "
              f"({len(ref)} blocks on the shortest chain)")
        print(f"txs: {len(sent)} accepted, {refused} refused, {len(finalized)} finalized, {len(missing)} missing")
        for i, s in status.items():
            m = s["metrics"]
            print(f"  node {i} rank {s['rank']}: {s.get('state', '?')}, slot {s['finalized_slot']}, peers {s['peers_connected']}, "
                  f"fast {m['fast_final_certs']} final {m['final_certs']} skip {m['skip_certs']}, "
                  f"standstills {m['standstills']}, repairs {m['repair_reqs_sent']}, bans {m['bans']}"
                  + (f", synced {s['synced_blocks']}, votes restored {m['votes_restored']} withheld {m['votes_withheld']}"
                     if (args.restart_one or args.restart_all) else ""))
            if m["bans"]:
                fail.append(f"node {i}: banned peers {m['bans']} times")

        if top < 0.5 * elapsed / (cluster.get("slot_ms", 400) / 1000.0):
            fail.append(f"LIVENESS: finalized slot {top} after {elapsed:.0f}s")
        if (args.restart_one or args.restart_all) and max(s["finalized_slot"] for s in status.values()) - \
                min(s["finalized_slot"] for s in status.values()) > 8:
            fail.append("LIVENESS: a restarted node did not catch up")
        if len(missing) > 0.02 * max(len(sent), 1):
            fail.append(f"LIVENESS: {len(missing)} of {len(sent)} txs not finalized")
    finally:
        stop_all()

    for i in sorted(alive) if not args.external else []:
        if procs[i].returncode not in (0, -signal.SIGTERM):
            fail.append(f"node {i}: exited with {procs[i].returncode}, see {d}/node-{i}.log")
    for i, r in enumerate(readers):
        if r.returncode not in (0, -signal.SIGTERM):
            fail.append(f"blocks server {i}: exited with {r.returncode}, see {d}/blocks-{i}.log")

    for f in fail:
        print("FAIL:", f)
    print("FAIL" if fail else "pass")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
