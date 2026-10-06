# vseq Python SDK

Client for a vseq network: consensus-only nodes that order opaque txs
with Firedancer's Alpenglow votor and never execute them. Your app sends
txs and reads the finalized order, then executes it however it likes.

## Setup

Build the client library and the node in the Firedancer repo:

```bash
make -j vseqd libvseq_client.so
export VSEQ_CLIENT_LIB="$PWD/$(make --silent objdir)/lib/libvseq_client.so"
```

The SDK itself has no dependencies beyond Python 3.11+.

## Use

```python
from vseq import Network, Vseq

vs = Vseq(Network.from_toml("cluster.toml"),   # same file the nodes use
          api_key="...")                        # from the node operators

vs.send(b"hello")                               # to the next leaders
slot = vs.send([b"a", b"b"], blocking=True)     # wait until final

for block in vs.batches():                      # from genesis, forever
    for tx in block.txs:
        apply(tx)
```

Start from the latest block instead of genesis with
`vs.batches(after=vs.get_last_finalized())`.

## What is checked

Nothing a node returns is trusted. For every response the SDK:

1. recomputes each block's hash from its slot, parent and txs,
2. checks that each block's parent is the previous block,
3. checks the BLS certificates on the last block: a fast-final cert,
   or a final cert plus a notar cert, signed by enough stake.

A node that fails a check is recorded in `vs.bad_nodes` and the SDK
asks another node. The leader schedule and certificate checks run in
`libvseq_client.so`, built from the same code as the nodes.

## Notes

- `send` delivers each tx to the leaders of the next 3 windows, so a tx
  can appear more than once. Apps deduplicate (see `examples/kv_store.py`).
- Each validator in `cluster.toml` needs an `api` URL (node: `/txs`,
  `/status`) and, to be read from, a `blocks` URL (its `vseqd blocks`
  server: `/blocks`). `vseqd gen-cluster` writes both.

## Tests

```bash
O=$(make --silent objdir)
python3 src/app/vseq/sdk/python/tests/test_sdk.py --vseqd $O/bin/vseqd --lib $O/lib/libvseq_client.so
```
