# vseq: Alpenglow consensus as a service

vseq orders opaque transactions with Firedancer's Alpenglow consensus
(votor) and never executes them. Applications submit txs, read the
finalized blocks, verify them against the validators' BLS certificates,
and execute them themselves. Ordering is the network's job; execution is
the application's. It is the consensus-as-a-service model of
[Zellular](https://docs.zellular.xyz/), with Alpenglow as the consensus
engine.

It reuses `src/choreo/votor` unchanged (vote pool, certificates,
finality, timeouts) and replaces everything Solana-specific around it
with a small node: no accounts, no execution, no snapshots, no gossip.
No upstream Firedancer file is modified.

## How it works

- **Blocks.** The leader of each slot batches pending txs into a block,
  signs its hash with ed25519 and sends it to every validator. The
  leader order is round-robin over 4-slot windows, ranked by stake.
- **Consensus.** Validators vote with BLS12-381 keys through votor. A
  block is final with a fast-final certificate (80% of stake in one
  round) or final + notar certificates (60%, two rounds). Typical
  submit-to-final time is about 0.3 s with 400 ms slots.
- **Proofs.** Every finalized block is stored with the certificates that
  finalize it. A client checks the certificates on the last block of a
  batch and follows parent hashes back, so it only trusts the validator
  set, not the node it reads from.
- **Restart safety.** Before sending a vote, a node makes it durable,
  together with the block for a notar vote. After a crash it loads these
  back into votor, so it can neither contradict itself nor lose a block
  it helped finalize, even if every node restarts at once.
- **Validator set changes.** `cluster.toml` lists validators with
  optional `from_epoch` / `until_epoch`. Nodes switch sets at epoch
  boundaries and drop peers whose set for the current epoch differs.

## Layout

| File | What it is |
|---|---|
| `vseq_node.c/h` | Consensus core: votor wiring, leader, block store, repair, finality proofs |
| `vseq_sched.c/h` | Validator sets per epoch, ranks, leader schedule |
| `vseq_mesh.c/h` | Mutual TLS 1.3 links between validators (ed25519 identities) |
| `vseq_ledger.c/h` | Append-only segmented ledger of finalized blocks, pruning, read-only follower |
| `vseq_history.c/h` | Durable vote history for restart safety |
| `vseq_block.c/h`, `vseq_proof.c/h` | Block format and hash, certificate verification |
| `vseqd.c` | The daemon: `keygen`, `api-key`, `gen-cluster`, `run`, `blocks` |
| `vseq_client.c/h` | `libvseq_client.so`, the C core of the client SDKs |
| `sdk/python` | Python SDK, see its [README](sdk/python/README.md) |
| `docker` | Local cluster in Docker |

The full config, file and API reference is the comment at the top of
`vseqd.c`. For the design, the safety arguments and the decisions behind
them, see [DESIGN.md](DESIGN.md).

## Quick start

```bash
make -j vseqd libvseq_client.so
O=$(make --silent objdir)

# A 4-node test cluster on localhost, genesis 10 s from now
$O/bin/vseqd gen-cluster --nodes 4 --dir /tmp/vseq --genesis-delay-s 10

# Per node i: the node and its blocks server (gen-cluster prints these)
$O/bin/vseqd run    --cluster /tmp/vseq/cluster.toml --key /tmp/vseq/node-0.toml \
                    --ledger /tmp/vseq/ledger-0 --api-port 8000
$O/bin/vseqd blocks --cluster /tmp/vseq/cluster.toml --ledger /tmp/vseq/ledger-0 --port 8500
```

Or in Docker: `src/app/vseq/docker/local_cluster.sh up 4`.

Then from Python, with `PYTHONPATH=src/app/vseq/sdk/python` and
`VSEQ_CLIENT_LIB=$O/lib/libvseq_client.so`:

```python
from vseq import Network, Vseq

vs = Vseq(Network.from_toml("/tmp/vseq/cluster.toml"))
vs.send([b"hello"], blocking=True)       # returns once final
for block in vs.batches():                # verified, from genesis
    print(block.slot, block.txs)
```

## APIs

Each validator runs two processes:

| Process | Endpoint | |
|---|---|---|
| `vseqd run` | `POST /txs` | txs framed as `(u32 size, bytes)` |
| | `GET /status` | node and consensus state (JSON) |
| `vseqd blocks` | `GET /blocks?after=SLOT&limit=N` | finalized blocks with their certificates, binary |

`vseqd blocks` reads the node's ledger files, so readers never slow
down consensus. With `--api-keys FILE` every call needs
`?api-key=KEY` and is rate limited per dApp; `vseqd api-key` creates
keys.

## Tests

```bash
make -j vseqd libvseq_client.so test_vseq_sim test_vseq_ledger
O=$(make --silent objdir)

$O/unit-test/test_vseq_sim        # simulated network: loss, crashes, equivocation, restarts, set changes
$O/unit-test/test_vseq_ledger     # ledger crash recovery, pruning, follower
python3 src/app/vseq/sdk/python/tests/test_sdk.py --vseqd $O/bin/vseqd --lib $O/lib/libvseq_client.so
python3 src/app/vseq/test_vseqd_cluster.py --vseqd $O/bin/vseqd --restart-all   # also --kill-one, --restart-one, --rejoin-empty
python3 src/app/vseq/test_vseqd_set_change.py --vseqd $O/bin/vseqd --lib $O/lib/libvseq_client.so

# Fuzz everything parsed from the network (needs clang; see fuzz_vseq.c)
make -j BUILDDIR=clang-fuzz-asan CC=clang EXTRAS="fuzz asan" fuzz_vseq
FUZZ_VSEQ_SEED_DIR=corpus/fuzz_vseq build/clang-fuzz-asan/fuzz-test/fuzz_vseq -runs=0
build/clang-fuzz-asan/fuzz-test/fuzz_vseq -max_total_time=600 corpus/fuzz_vseq
```

## Status

A prototype, not production ready. Known gaps:

- Validator keys are plain files and in process memory; no remote signer.
- Leaders send each block to every validator: fine for tens of
  validators, not hundreds (Firedancer's rotor would fix that).
- No long adversarial runs yet.
- No wire protocol versioning or metrics export yet.
- Each node needs about 0.75 GB of memory (votor reserves room for 2,000
  validators in each of 64 tracked slots, `--slot-max`).
