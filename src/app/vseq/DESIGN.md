# vseq design

This document is for reviewers. It explains what vseq is for, how the
parts fit together, why it is safe, and which decisions were made on
purpose. The [README](README.md) covers usage, the comment at the top of
`vseqd.c` is the config and API reference, and each header documents
its module.

## 1. The idea: consensus as a service

vseq follows the model of [Zellular](https://docs.zellular.xyz/):
a network of nodes that only **orders** transactions for applications,
while the applications **execute** them.

- A dApp sends opaque txs to the network.
- The network agrees on one order and publishes finalized batches with
  an aggregate BLS proof signed by the validators.
- Every replica of the dApp reads the same batches, checks the proof,
  and applies the txs to its own state.

The nodes never interpret txs, keep no application state and need no
virtual machine. Any app that can be written as a deterministic state
machine over an ordered log can use it (key-value stores, order books,
token ledgers, rollup sequencing).

What vseq changes is the consensus engine: Solana's Alpenglow, as
implemented in Firedancer's `src/choreo/votor`. That brings:

- fast finality: one round with 80% of stake, or two rounds with 60%;
  about 0.3 s submit-to-final with 400 ms slots in our tests;
- Alpenglow's fault model: safe while byzantine stake stays under 20%,
  and still live with up to another 20% of stake offline;
- a protocol designed and reviewed for Solana, and code maintained by
  Firedancer, rather than a consensus written for this project.

## 2. The big picture

```
 dApp ──POST /txs──▶ node (leader of the next windows)
                      │  batches pending txs into a block per slot,
                      │  signs the block hash, sends it to every validator
                      ▼
            ┌────────────────── TLS mesh ──────────────────┐
            │ every validator: store block → votor votes   │
            │ (BLS) → certificates → finalized block       │
            └──────────────────────────────────────────────┘
                      │ finalized blocks + certs appended to the ledger
                      ▼
               ledger files ──read only──▶ vseqd blocks ──GET /blocks──▶ dApp
                                                                     verifies certs,
                                                                     follows parents,
                                                                     executes txs
```

Each validator runs two processes:

- `vseqd run`: consensus, the mesh to other validators, the ledger and
  vote history, plus `POST /txs` and `GET /status`;
- `vseqd blocks`: serves `GET /blocks` straight from the ledger files,
  so heavy readers never slow consensus down.

## 3. What comes from Firedancer, and how we use it

Unchanged upstream code: `src/choreo/votor` (`ag_pool`: votes,
certificates, finality, parent-ready tracking, slashing checks;
`ag_votor`: when to vote, timeouts), BLS (`ballet/bls`, blst), TLS 1.3
(`waltz/tls`), the HTTP server, and utility libraries. No upstream file
is modified, so upstream fixes come in with a rebase.

Our code plays the roles Firedancer's other tiles play for votor:

| Firedancer tile | vseq |
|---|---|
| replay (executes blocks, then tells votor) | `vseq_node.c` `replay()`: a block is "replayed" once it and all its ancestors are stored; nothing is executed |
| shred / rotor (block propagation) | the leader sends the whole block to every validator |
| repair | `REPAIR` request by (slot, hash), first to the leader, then to other validators |
| epoch / stake from the bank | `vseq_sched`: validator sets from `cluster.toml` |
| votor tile networking | `vseq_mesh`: authenticated TLS links |

The contract with votor, all in `vseq_node.c`:

- **Start:** `ag_pool_init` / `ag_votor_init` at a root: genesis, or the
  last finalized block in the ledger, whose certificates are checked and
  added to the pool.
- **Inputs:** blocks (`ag_pool_add_block`, `ag_votor_process_replay`),
  peer votes and certificates (`ag_pool_add_vote`, `ag_pool_add_cert`),
  skip timeouts, and standstill recovery after 10 s without
  finalization.
- **Outputs:** our own votes and certificates to broadcast,
  parent-ready events (which make us build blocks when we lead), repair
  requests, and the finalized slot.
- **Epochs:** votor holds the previous, current and next validator sets.
  We give it the next set ahead of time, and the one after once the root
  enters the next set, so a set must last at least `--slot-max` slots.
- **Memory:** votor tracks `--slot-max` slots (64 by default) and
  reserves room for 2,000 validators in each, about 11.5 MB per slot.

## 4. Why it is safe

**Finality is only ever claimed with certificates.** A block is
delivered as finalized only when the pool has a fast-final certificate
for it, a final and notar certificate pair, or a finalized descendant.
The same certificates are stored with the block and served to clients.

**A certificate commits to the whole history.** Votes are over the block
hash, which is `SHA-256("vseq-block-v1" | slot | parent_slot |
parent_hash | payload)`. So a certificate on one block also fixes its
payload and, through parent hashes, every ancestor.

**Clients trust the validator set, not the node they read from.** The
SDK recomputes each block's hash, checks the parent links, and checks
the certificates on the last block of each response against the
validator set of that block's epoch, using the same C code as the nodes
(`libvseq_client`). A lying node is detected and skipped.

**An honest node never contradicts itself, even across crashes.**
`vseq_history` records every vote the node signs, the block for every
notar vote, and the highest slot it built a block for. Each record is
fsynced before the vote or block is sent. On restart:

- saved votes go back into the pool as our own and are sent again, so
  the pool's slashing check withholds any new vote that would conflict
  with them;
- saved blocks go back into the block store, so a block we helped
  finalize can always be produced again;
- no block is built up to the end of the window of the last block
  built, so a restarted leader cannot produce a second version.

This is what lets the whole cluster crash and restart at once. Losing
the history while keeping the ledger is refused at startup.

**Finalized blocks survive a power loss on every node.** A finalized
block was voted for by at least 60% of stake, and each voter saved it
with its vote first. So after a power loss everywhere, the network
finalizes the same block again from the vote histories. The ledger is
not synced per block; it is synced when a segment is sealed and right
before the vote history drops anything the ledger holds (on open, when
consensus starts, and every 512 slots). A block is therefore always on
disk in one of the two.

**Nodes on different configs never work together.** The config is part
of the release. After connecting, and again every epoch, peers exchange
the hash of their validator set for the current epoch and drop the
connection if it differs. Before a scheduled change, old and new files
agree on the current epoch, so a rollout does not split the network. A
node that misses an update is cut off at the switch and stops, like a
validator that skipped a required upgrade on any chain.

## 5. Failure handling

| Situation | What happens |
|---|---|
| Messages lost | votor rebroadcasts on standstill (10 s); missing blocks are repaired by hash |
| Leader offline | its window times out, validators vote skip, the next leader builds on the last certified block |
| Equivocating leader | votor's notar-fallback path; blocks repaired by hash; tested in the simulator |
| Node crash and restart | reopen the ledger (torn tail cut), reload the vote history, catch up from peers if behind |
| Whole cluster restarts at once | each node resumes from its own ledger and history; finalization resumes, no conflicting votes |
| Node far behind (more than `--slot-max`) | stops consensus, fetches finalized blocks from peers (`SYNC_REQ`), checks their certs, then rejoins |
| Node starts with an empty ledger | `--history recent`: start from a peer's latest finalized block, checked by its certs; `--history full`: fetch everything peers keep |
| Peers pruned the history we need | logged clearly; the node waits (restore segments, or rejoin with an empty ledger) |
| Validator set change | at the epoch boundary; leavers stay connected one more epoch, joiners connect one epoch early |
| Peer with a different config | disconnected at the set-hash check, with a log line saying why |
| API flood | at most 16 HTTP events per loop pass; API keys with per-dApp rate limits |

## 6. Formats

**Messages** (one type byte, then the body; `vseq_node.h`):

| Type | Body |
|---|---|
| 1 VOTE | `ag_vote_ser` bytes; the signer is the authenticated peer |
| 2 CERT | `ag_cert_ser` bytes |
| 3 BLOCK | block wire bytes (below) |
| 4 REPAIR | slot, hash: send me this block |
| 16 SYNC_REQ | after slot, max blocks |
| 17 SYNC_BLOCK | one ledger record |
| 18 SYNC_END | sender's finalized slot and ledger base |
| 19 HELLO | epoch and validator set hash |

**Block** (`vseq_block.h`): slot, parent slot, parent hash, the
leader's ed25519 signature over the block hash, payload. The payload is
txs framed as `(u32 size, bytes)`.

**Finality proof** (`vseq_node.h`): a FastFinal certificate, or a Final
plus a Notar certificate, as `(u32 size, ag_cert_ser)` each. Blocks
finalized only through a descendant have an empty proof; the
descendant's proof covers them through parent hashes.

**Ledger** (`vseq_ledger.h`): a directory of append-only segments, each
a 64-byte header (sequence number, first index, the block it builds on)
followed by records (block, hash, proof). A full segment is sealed only
after a record with its own proof, so every sealed segment ends with a
verifiable block; pruning deletes whole sealed segments, oldest first.

**`GET /blocks`**: a 20-byte header (`VSQB`, version, the server's
finalized slot, record count), then ledger records exactly as stored.
The last record always carries a proof.

**Vote history** (`vseq_history.h`): checksummed records (VOTE, BLOCK,
FLOOR), compacted to those above the finalized root.

## 7. Decisions and rejected alternatives

- **A small node around votor, not full Firedancer with execution
  stubbed out.** Execution state drives much more than it looks: stake
  and the leader schedule come from accounts, txs must be Solana txs
  with fees, nodes boot from snapshots, and RPC has no finality proofs.
  Stubbing all that means a large fork of fast-moving code. Our node
  depends only on votor and libraries.
- **Direct block broadcast instead of rotor.** Fine for tens of
  validators. The leader's upload grows with the validator count, so
  hundreds of validators would need rotor-style relaying.
- **A restart floor ("never vote below slot N") was tried and
  dropped.** It deadlocked a whole-cluster restart: every node stayed
  silent over the same slots. Reloading the actual votes works, and is
  also what Agave does.
- **Blocks are saved with notar votes.** Without that, a full-cluster
  restart could finalize a block whose contents no node still had.
- **`/blocks` in a separate process.** Reads are the heavy part of the
  API and need nothing from consensus. `/txs` and `/status` stay in the
  node: they are cheap, and moving them would need an extra protocol.
- **Validator sets from the config file, not from on-chain txs.**
  Simpler, and safe because nodes compare set hashes; the trade-off is
  that the config must be distributed with the release.
- **API keys in the URL (`?api-key=`).** Firedancer's HTTP server does
  not expose request headers, and only sends a body with 200, 204 and
  400, so every error with a message is a 400. A gateway with its own
  HTTP layer would allow standard headers and status codes.
- **Peers addressed by a stable index** (every identity in the config,
  sorted by key), since ranks change with each validator set.

## 8. Trust model and limits

- Validators are known in advance (permissioned set, stake from the
  config). Safety needs byzantine stake under 20%.
- Peers authenticate with ed25519 identity keys over mutual TLS;
  votes are BLS signatures checked by votor.
- Clients need only the config file (validator set and network id).
- Tx submission is not censorship resistant beyond leader rotation: a
  dApp sends each tx to the next few leaders and resends if needed.
  Pending txs live in leader memory and are lost if the leader crashes.
- Not done yet: remote signing and key protection, fuzzing, protocol
  versioning, metrics export, rotor. Upstream votor is still in
  development (Alpenglow is not active on Solana mainnet), so expect
  API changes when rebasing.

## 9. Where to start reading

1. `vseq_node.c`: the consensus core and the votor contract (`replay`,
   `handle_pool_event`, `handle_own_vote`, `vseq_node_create`,
   `vseq_node_service`).
2. `vseqd.c`: the daemon: sync, the hello check, the main loop, the APIs.
3. `vseq_history.c` and `vseq_ledger.c`: what is on disk and when it is
   synced.
4. `test_vseq_sim.c`: the scenarios and the conflict checker, which flags
   any validator sending conflicting votes or blocks in one slot.

| Test | Covers |
|---|---|
| `test_vseq_sim` | loss, latency, crashes, equivocation, restarts of one or all nodes, set changes, uneven stake |
| `test_vseq_ledger` | segment crash recovery, pruning, the read-only follower |
| `sdk/python/tests/test_sdk.py` | proof checks, tampered data, lying nodes, API keys |
| `test_vseqd_cluster.py` | real processes: kill, restart, restart all, rejoin with an empty ledger, pruning |
| `test_vseqd_set_change.py` | real processes: a validator joins, one leaves, a node with the old config is cut off |
