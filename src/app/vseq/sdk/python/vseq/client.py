"""Python client for a vseq network.

A vseq network orders opaque txs with Alpenglow consensus and never
executes them.  Apps send txs with Vseq.send() and read the finalized
order with Vseq.batches(), then execute the txs themselves.

Nothing a node returns is trusted.  Every block read is checked:

  * its hash is recomputed from the slot, parent and txs
  * it links to the previous block by parent hash
  * the last block of a response carries BLS certificates that
    finalize it, signed by enough stake of the validator set; when a
    response was cut short of one (its last blocks were finalized only
    through a later block), the client holds them back and reads on
    until a response ends with certificates, which cover them

The certificate and leader schedule checks run in libvseq_client.so,
which is built from the same Firedancer code as the nodes.
"""

import ctypes
import hashlib
import json
import os
import random
import struct
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field

SLOTS_PER_WINDOW = 4
HASH_DOMAIN = b"vseq-block-v1"

_ERRORS = {1: "malformed cert", 2: "cert for another slot, block or network",
           3: "bad signature or not enough stake", 4: "certs do not finalize the block"}


class VerificationError(Exception):
    """A node returned data that does not check out."""


class NetworkError(Exception):
    """No node could serve the request."""


@dataclass(frozen=True)
class Validator:
    stake: int
    identity: bytes  # ed25519 public key, 32 bytes
    bls: bytes       # compressed BLS12-381 public key, 48 bytes
    api: str         # node: /txs, /status, e.g. "http://127.0.0.1:8000"
    blocks: str = "" # blocks server: /blocks, e.g. "http://127.0.0.1:8500"
    from_epoch: int = 0
    until_epoch: int | None = None  # None: no end


@dataclass(frozen=True)
class Block:
    slot: int
    hash: bytes
    parent_slot: int
    parent_hash: bytes
    txs: list = field(default_factory=list)


GENESIS = Block(slot=0, hash=bytes(32), parent_slot=0, parent_hash=bytes(32))


@dataclass
class RawBlock:
    """A finalized block as served by /blocks: a ledger record (vseq_ledger.h)."""
    slot: int
    parent_slot: int
    parent_hash: bytes
    hash: bytes
    sig: bytes       # leader's ed25519 signature over hash
    payload: bytes   # txs framed as (u32 le size, bytes)
    proof: bytes     # certs framed as (u32 le size, ag_cert_ser bytes); empty if a later block proves it


BLOCKS_MAGIC = b"VSQB"
BLOCKS_VERSION = 1
_HDR = struct.Struct("<4sB3xQI")     # magic, version, finalized slot, record count
_REC = struct.Struct("<IQQ32s32s64sI")  # rec_sz, slot, parent_slot, parent_hash, hash, sig, payload_sz


def decode_blocks(body):
    """Parse a /blocks response into (node's finalized slot, [RawBlock])."""
    if len(body) < _HDR.size:
        raise ValueError("short /blocks response")
    magic, version, finalized, count = _HDR.unpack_from(body, 0)
    if magic != BLOCKS_MAGIC or version != BLOCKS_VERSION:
        raise ValueError(f"unsupported /blocks format {magic!r} v{version}")
    off, out = _HDR.size, []
    for _ in range(count):
        if off + _REC.size > len(body):
            raise ValueError("truncated record")
        rec_sz, slot, parent_slot, parent_hash, block_hash_, sig, payload_sz = _REC.unpack_from(body, off)
        end = off + 4 + rec_sz
        p = off + _REC.size
        if end > len(body) or p + payload_sz + 4 > end:
            raise ValueError("bad record size")
        payload = body[p:p + payload_sz]
        proof_sz = struct.unpack_from("<I", body, p + payload_sz)[0]
        if p + payload_sz + 4 + proof_sz != end:
            raise ValueError("bad proof size")
        proof = body[p + payload_sz + 4:end]
        out.append(RawBlock(slot, parent_slot, parent_hash, block_hash_, sig, payload, proof))
        off = end
    if off != len(body):
        raise ValueError("trailing bytes")
    return finalized, out


def payload_txs(payload):
    """Txs in a block payload.  Like the nodes, stop at a malformed frame:
    a leader can put junk in a block, and it must not stop readers."""
    txs, off = [], 0
    while off + 4 <= len(payload):
        n = struct.unpack_from("<I", payload, off)[0]
        if off + 4 + n > len(payload):
            break
        txs.append(payload[off + 4:off + 4 + n])
        off += 4 + n
    return txs


class Network:
    """The validator sets over time, as in the nodes' cluster.toml: the set
    of epoch E is every entry with from_epoch <= E < until_epoch."""

    def __init__(self, network_id, validators, epoch_slots=9000, genesis_time_ms=0, slot_ms=400):
        if not 1 <= network_id <= 65535:
            raise ValueError("network_id must be in [1, 65535]")
        if not validators:
            raise ValueError("no validators")
        self.network_id = network_id
        self.validators = list(validators)
        self.epoch_slots = epoch_slots
        self.genesis_time_ms = genesis_time_ms
        self.slot_ms = slot_ms

    def current_epoch(self):
        """The epoch by the clock (0 before genesis)."""
        ms = time.time() * 1000 - self.genesis_time_ms
        return max(0, int(ms // self.slot_ms)) // self.epoch_slots

    @classmethod
    def from_toml(cls, path):
        with open(path, "rb") as f:
            c = tomllib.load(f)
        vals = []
        for v in c["validator"]:
            if "api" not in v:
                raise ValueError(f"{path}: every validator needs an api URL for clients")
            vals.append(Validator(stake=v["stake"], identity=bytes.fromhex(v["identity"]),
                                  bls=bytes.fromhex(v["bls"]), api=v["api"].rstrip("/"),
                                  blocks=v.get("blocks", "").rstrip("/"),
                                  from_epoch=v.get("from_epoch", 0), until_epoch=v.get("until_epoch")))
        return cls(c["network_id"], vals, c.get("epoch_slots", 9000), c.get("genesis_time_ms", 0), c.get("slot_ms", 400))


def _find_lib():
    path = os.environ.get("VSEQ_CLIENT_LIB")
    if path:
        return path
    raise FileNotFoundError("libvseq_client.so not found: pass lib_path or set VSEQ_CLIENT_LIB "
                            "(build it in the firedancer repo with: make -j libvseq_client.so)")


class _Lib:
    def __init__(self, path, network):
        self.lib = ctypes.CDLL(path)
        self.lib.vseq_client_new.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_uint, ctypes.c_ulong]
        self.lib.vseq_client_new.restype = ctypes.c_void_p
        self.lib.vseq_client_delete.argtypes = [ctypes.c_void_p]
        self.lib.vseq_client_leader.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.lib.vseq_client_leader.restype = ctypes.c_ulong
        self.lib.vseq_client_verify.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p,
                                                ctypes.c_char_p, ctypes.c_ulong]
        self.lib.vseq_client_verify.restype = ctypes.c_int
        blob = b"".join(struct.pack("<Q", v.stake) + v.identity + v.bls +
                        struct.pack("<QQ", v.from_epoch, 2**64 - 1 if v.until_epoch is None else v.until_epoch)
                        for v in network.validators)
        self.handle = self.lib.vseq_client_new(blob, len(network.validators), network.network_id, network.epoch_slots)
        if not self.handle:
            raise ValueError("invalid validator schedule (an epoch without validators, zero stake, bad BLS key or duplicate key)")

    def __del__(self):
        if getattr(self, "handle", None):
            self.lib.vseq_client_delete(self.handle)
            self.handle = None

    def leader(self, slot):
        return self.lib.vseq_client_leader(self.handle, slot)

    def verify(self, slot, block_hash, proof):
        return self.lib.vseq_client_verify(self.handle, slot, block_hash, proof, len(proof))


def frame_txs(txs):
    """Txs as a block payload or /txs body: (u32 le size, bytes) each."""
    return b"".join(struct.pack("<I", len(t)) + t for t in txs)


def payload_hash(slot, parent_slot, parent_hash, payload):
    """The block hash nodes vote on (see vseq_block.h)."""
    h = hashlib.sha256()
    h.update(HASH_DOMAIN)
    h.update(struct.pack("<QQ", slot, parent_slot))
    h.update(parent_hash)
    h.update(payload)
    return h.digest()


class Vseq:
    """Client for one vseq network.

    send(txs)           order txs; optionally wait until they are final
    batches(after)      iterate verified finalized blocks forever
    get_last_finalized  the latest verified finalized block
    """

    def __init__(self, network, api_key=None, lib_path=None, timeout=5.0, windows=3,
                 pending_max=64 << 20):
        self.network = network
        self.api_key = api_key
        self.timeout = timeout
        self.windows = windows
        self.pending_max = pending_max  # bytes of blocks held back while waiting for certs
        self._lib = _Lib(lib_path or _find_lib(), network)
        self.bad_nodes = {}  # api URL -> last verification error

    # Leader schedule ---------------------------------------------------

    def leader(self, slot):
        """The validator that leads slot (round robin over 4-slot windows by stake rank)."""
        return self.network.validators[self._lib.leader(slot)]

    def upcoming_leaders(self, slot, windows=None):
        out = []
        for w in range(windows or self.windows):
            v = self.leader(slot + w * SLOTS_PER_WINDOW)
            if v not in out:
                out.append(v)
        return out

    # HTTP --------------------------------------------------------------

    def _url(self, api, path):
        if not self.api_key:
            return api + path
        return f"{api}{path}{'&' if '?' in path else '?'}api-key={self.api_key}"

    def _get(self, api, path):
        with urllib.request.urlopen(self._url(api, path), timeout=self.timeout) as r:
            return json.loads(r.read())

    def _get_blocks(self, url, after, limit):
        """(server's finalized slot, [RawBlock])"""
        with urllib.request.urlopen(self._url(url, f"/blocks?after={after}&limit={limit}"), timeout=self.timeout) as r:
            return decode_blocks(r.read())

    def _post(self, api, path, body):
        req = urllib.request.Request(self._url(api, path), data=body, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _nodes(self, kind="api"):
        """Api or blocks URLs of validators that have not left, known-good first, in random order."""
        epoch = self.network.current_epoch()
        urls = list({getattr(v, kind) for v in self.network.validators
                     if getattr(v, kind) and (v.until_epoch is None or v.until_epoch > epoch)})
        random.shuffle(urls)
        return sorted(urls, key=lambda a: a in self.bad_nodes)

    def status(self, api=None):
        if api:
            return self._get(api, "/status")
        for a in self._nodes():
            try:
                return self._get(a, "/status")
            except OSError:
                continue
        raise NetworkError("no node answered /status")

    def current_slot(self):
        """A slot estimate for routing: the next slot after some node's finalized slot."""
        return self.status()["finalized_slot"] + 1

    # Sending -----------------------------------------------------------

    def send(self, txs, blocking=False, timeout=30.0):
        """Send txs (bytes or list of bytes) to the leaders of the next windows.

        Returns the number of leaders that accepted them.  With
        blocking=True, waits until every tx is in a verified finalized
        block and returns the slot of the last one.  A tx may be ordered
        more than once (several leaders get it); apps deduplicate.
        """
        if isinstance(txs, (bytes, bytearray)):
            txs = [bytes(txs)]
        if not txs:
            raise ValueError("no txs")
        anchor = self.get_last_finalized() if blocking else None
        body = frame_txs(txs)
        accepted = 0
        for v in self.upcoming_leaders(self.current_slot()):
            try:
                code, _ = self._post(v.api, "/txs", body)
                accepted += code == 200
            except OSError:
                continue
        if not accepted:
            raise NetworkError("no leader accepted the txs")
        if not blocking:
            return accepted

        want = {hashlib.sha256(t).digest() for t in txs}
        deadline = time.time() + timeout
        for blk in self.batches(after=anchor, deadline=deadline):
            for t in blk.txs:
                want.discard(hashlib.sha256(t).digest())
            if not want:
                return blk.slot
        raise TimeoutError(f"{len(want)} of {len(txs)} txs not finalized within {timeout}s")

    # Reading -----------------------------------------------------------

    def verify_blocks(self, anchor, raw_blocks, require_proof=True):
        """Check RawBlocks from /blocks that follow the verified block anchor.

        Returns them as Blocks, or raises VerificationError.  The last
        block must carry certs; earlier ones are covered through parent
        hashes.  With require_proof=False a last block without certs is
        accepted as chained only: the caller must not trust the blocks
        until a later block with certs extends them (see _fetch).
        """
        blocks, prev = [], anchor
        for r in raw_blocks:
            if payload_hash(r.slot, r.parent_slot, r.parent_hash, r.payload) != r.hash:
                raise VerificationError(f"slot {r.slot}: hash does not match contents")
            if (r.parent_slot, r.parent_hash) != (prev.slot, prev.hash):
                raise VerificationError(f"slot {r.slot}: does not extend slot {prev.slot}")
            prev = Block(slot=r.slot, hash=r.hash, parent_slot=r.parent_slot, parent_hash=r.parent_hash,
                         txs=payload_txs(r.payload))
            blocks.append(prev)
        if raw_blocks and (require_proof or raw_blocks[-1].proof):
            last = raw_blocks[-1]
            err = self._lib.verify(last.slot, last.hash, last.proof)
            if err:
                raise VerificationError(f"slot {last.slot}: {_ERRORS.get(err, err)}")
        return blocks

    def _fetch_proved(self, api, anchor, limit):
        """Blocks after anchor from one node, up to a block with certs.

        A reply cut short of a block with certs is held back and the
        node is asked on from its last block; everything held is
        returned once a reply ends with certs, which cover it through
        the parent hashes.  A node whose replies never reach certs
        within pending_max bytes is treated as lying.
        """
        pending, prev, size = [], anchor, 0
        while True:
            raw = self._get_blocks(api, prev.slot, limit)[1]
            if not raw:
                if pending:
                    raise VerificationError(f"slot {prev.slot}: no certs and nothing follows")
                return []
            blocks = self.verify_blocks(prev, raw, require_proof=False)
            if raw[-1].proof:
                return pending + blocks
            pending += blocks
            prev = blocks[-1]
            size += sum(len(r.payload) for r in raw)
            if size > self.pending_max:
                raise VerificationError(f"{size} bytes of blocks after slot {anchor.slot} without certs")

    def _fetch(self, anchor, limit=64):
        """Verified blocks after anchor from any node; [] if none are newer."""
        errors = []
        for api in self._nodes("blocks"):
            try:
                blocks = self._fetch_proved(api, anchor, limit)
                self.bad_nodes.pop(api, None)
                return blocks
            except VerificationError as e:
                self.bad_nodes[api] = str(e)
                errors.append(f"{api}: {e}")
            except urllib.error.HTTPError as e:
                err = json.loads(e.read() or b"{}") if e.code == 400 else {}
                if err.get("error") == "pruned":
                    errors.append(f"{api}: history before slot {err.get('base_slot')} was pruned")
                else:
                    errors.append(f"{api}: HTTP {e.code}")
            except ValueError as e:  # malformed response
                self.bad_nodes[api] = str(e)
                errors.append(f"{api}: {e}")
            except (OSError, KeyError) as e:
                errors.append(f"{api}: {e}")
        raise NetworkError("no node returned valid blocks: " + "; ".join(errors) +
                           (" (start from get_last_finalized(), or read from a node that keeps full history)"
                            if any("pruned" in e for e in errors) else ""))

    def get_last_finalized(self):
        """The latest finalized block, verified by its own certs."""
        for api in self._nodes("blocks"):
            try:
                tip = self._get_blocks(api, 2**63, 1)[0]  # no blocks, just the server's finalized slot
                if tip == 0:
                    return GENESIS
                raw = self._get_blocks(api, tip - 1, 1)[1]
                if not raw:
                    continue
                parent = Block(slot=raw[0].parent_slot, hash=raw[0].parent_hash, parent_slot=0, parent_hash=bytes(32))
                return self.verify_blocks(parent, raw[:1])[-1]  # proven by its own certs
            except VerificationError as e:
                self.bad_nodes[api] = str(e)
            except (OSError, ValueError, KeyError):
                continue
        raise NetworkError("no node returned a verifiable finalized block")

    def batches(self, after=None, poll_interval=0.2, deadline=None):
        """Yield verified finalized blocks after the block `after`, forever.

        after is a Block you already trust (from get_last_finalized() or
        an earlier batch); None starts from genesis.  Empty (skipped)
        slots produce no block.  Stops at deadline (time.time()) if set.
        """
        anchor = after or GENESIS
        while deadline is None or time.time() < deadline:
            blocks = self._fetch(anchor)
            if not blocks:
                time.sleep(poll_interval)
                continue
            for blk in blocks:
                yield blk
            anchor = blocks[-1]
