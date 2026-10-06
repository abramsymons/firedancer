#!/usr/bin/env python3
"""A replicated key-value store on vseq.

vseq only orders the ops.  Every replica reads the same verified,
finalized order and applies it, so every replica ends up with the same
state.  Ops carry a unique id; replicas skip ids they have seen, since a
tx can be ordered more than once.

  kv_store.py --cluster cluster.toml set color blue
  kv_store.py --cluster cluster.toml show            # replay and print the state
  kv_store.py --cluster cluster.toml follow          # keep applying new ops

Set VSEQ_CLIENT_LIB to libvseq_client.so, or pass --lib.
"""

import argparse
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vseq import Network, Vseq  # noqa: E402


class Replica:
    def __init__(self):
        self.state, self.seen = {}, set()

    def apply(self, tx):
        try:
            op = json.loads(tx)
        except ValueError:
            return  # not ours; other apps can share the network
        if not isinstance(op, dict) or op.get("app") != "kv" or op.get("id") in self.seen:
            return
        self.seen.add(op["id"])
        if op.get("op") == "set":
            self.state[op["key"]] = op["value"]
        elif op.get("op") == "del":
            self.state.pop(op["key"], None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", required=True)
    ap.add_argument("--lib", default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("cmd", choices=["set", "del", "show", "follow"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()

    vs = Vseq(Network.from_toml(a.cluster), api_key=a.api_key, lib_path=a.lib)

    if a.cmd in ("set", "del"):
        key, value = (a.args + [None, None])[:2]
        op = {"app": "kv", "id": str(uuid.uuid4()), "op": a.cmd, "key": key, "value": value}
        slot = vs.send(json.dumps(op).encode(), blocking=True)
        print(f"{a.cmd} {key} finalized in slot {slot}")
        return

    r = Replica()
    tip = vs.get_last_finalized()
    for blk in vs.batches():
        for tx in blk.txs:
            r.apply(tx)
        if a.cmd == "show" and blk.slot >= tip.slot:
            break
        if a.cmd == "follow" and blk.txs:
            print(f"slot {blk.slot}: {json.dumps(r.state, sort_keys=True)}")
    if a.cmd == "show":
        print(json.dumps(r.state, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
