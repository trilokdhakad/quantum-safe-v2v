"""Measured costs that drive the network simulation.

A *handshake profile* gives the real on-air size of each PQ-V2V-AKE message and
the real compute time of each step (initiate, respond, finish, confirm),
measured by running the actual protocol code. A *broadcast profile* gives the
real size of a signed safety message (with certificate / with digest) and the
real sign / verify times. In "model" crypto mode the simulator uses these
numbers; in "real" mode it runs the protocol itself and checks they agree.

Profiles:
    handshake:  classical (X25519 + ECDSA P-256), pq-mldsa (ML-KEM-768 +
                ML-DSA-44, our default), pq-falcon (ML-KEM-768 + Falcon-512),
                hybrid-mldsa (ML-KEM-768 + X25519 + ML-DSA-44)
    broadcast:  ecdsa, falcon, falcon-mldsa-ca, mldsa  (vehicle / authority schemes)
"""

from __future__ import annotations

import json
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

HANDSHAKE_SETUPS = {
    "classical": dict(sig_alg="ECDSA-P256", kem_alg="X25519"),
    "pq-mldsa": dict(kem_backend="oqs", sig_backend="oqs"),
    "pq-falcon": dict(sig_alg="Falcon-512", kem_backend="oqs"),
    "hybrid-mldsa": dict(hybrid=True, kem_backend="oqs", sig_backend="oqs"),
}
BROADCAST_SETUPS = {
    "ecdsa": ("ECDSA-P256", "ECDSA-P256"),
    "falcon": ("Falcon-512", "Falcon-512"),
    "falcon-mldsa-ca": ("Falcon-512", "ML-DSA-44"),
    "mldsa": ("ML-DSA-44", "ML-DSA-44"),
}
NEEDS_OQS = {"pq-mldsa", "pq-falcon", "hybrid-mldsa", "falcon", "falcon-mldsa-ca"}


@dataclass(frozen=True)
class HandshakeProfile:
    name: str
    m1_bytes: int
    m2_bytes: int
    m3_bytes: int
    t_initiate: float  # seconds of CPU on the measuring machine
    t_respond: float
    t_finish: float
    t_confirm: float


@dataclass(frozen=True)
class BroadcastProfile:
    name: str
    vehicle_alg: str
    authority_alg: str
    msg_digest_bytes: int
    msg_cert_bytes: int
    t_sign: float
    t_verify: float  # one signature verification (message)
    t_verify_cert: float  # one verification under the authority scheme (certificate)


@dataclass(frozen=True)
class CryptoProfile:
    machine: str
    handshakes: dict
    broadcasts: dict

    def handshake(self, name: str) -> HandshakeProfile:
        return HandshakeProfile(**self.handshakes[name])

    def broadcast(self, name: str) -> BroadcastProfile:
        return BroadcastProfile(**self.broadcasts[name])


def _med(xs):
    return statistics.median(xs)


def measure_handshake(name: str, reps: int = 15, seed: int = 0) -> HandshakeProfile:
    from qsv2v.pqc import pq_v2v_ake as A

    net = A.setup_network(2, seed=seed, n_pseudonyms=1, lifetime=10**6, **HANDSHAKE_SETUPS[name])
    vi, vr = net.vehicles
    t = {"i": [], "r": [], "f": [], "c": []}
    sizes = None
    for _ in range(reps + 1):
        t0 = time.perf_counter()
        m1, st = A.initiate(vi, net.clock)
        t1 = time.perf_counter()
        m2, st_r = A.respond(vr, m1, net.clock)
        t2 = time.perf_counter()
        m3, _ = A.finish(vi, st, m2, net.clock)
        t3 = time.perf_counter()
        A.confirm(st_r, m3)
        t4 = time.perf_counter()
        for k, v in zip("irfc", (t1 - t0, t2 - t1, t3 - t2, t4 - t3), strict=True):
            t[k].append(v)
        sizes = (len(m1.encode()), len(m2.encode()), len(m3.encode()))
        net.clock.advance(1)
    for k in t:
        t[k] = t[k][1:]  # drop warm-up
    return HandshakeProfile(name, *sizes, _med(t["i"]), _med(t["r"]), _med(t["f"]), _med(t["c"]))


def measure_broadcast(name: str, reps: int = 100, seed: int = 0) -> BroadcastProfile:
    from qsv2v.crypto.rng import DeterministicRNG
    from qsv2v.pqc.broadcast import Broadcaster, bsm_payload
    from qsv2v.pqc.certs import Authority, enroll_vehicle
    from qsv2v.pqc.sig import get_scheme

    veh_alg, ca_alg = BROADCAST_SETUPS[name]
    backend = "oqs"
    rng = DeterministicRNG(seed)
    ca_scheme = get_scheme(ca_alg, backend, rng.fork("ca"))
    ca = Authority(rng.fork("ca-rng"), ca_scheme)
    veh = get_scheme(veh_alg, backend, rng.fork("veh"))
    cred = enroll_vehicle(ca, b"VIN", veh, 1, 1_790_000_000, 10**6)[0]
    b = Broadcaster(cred, veh)
    full = b.sign(bsm_payload(0), 1_790_000_000, force_cert=True)
    dig = b.sign(bsm_payload(1), 1_790_000_000)
    ts, tv, tc = [], [], []
    for i in range(reps + 1):
        t0 = time.perf_counter()
        m = b.sign(bsm_payload(i), 1_790_000_000)
        t1 = time.perf_counter()
        veh.verify(cred.cert.public_key, m.tbs(), m.signature)
        t2 = time.perf_counter()
        ca_scheme.verify(ca.public_key, cred.cert.tbs(), cred.cert.signature)
        t3 = time.perf_counter()
        ts.append(t1 - t0)
        tv.append(t2 - t1)
        tc.append(t3 - t2)
    return BroadcastProfile(
        name, veh_alg, ca_alg, len(dig), len(full), _med(ts[1:]), _med(tv[1:]), _med(tc[1:])
    )


def measure_all(reps: int = 15) -> CryptoProfile:
    from qsv2v.pqc.sig import oqs_available

    have_oqs = oqs_available()
    hs = {
        n: asdict(measure_handshake(n, reps))
        for n in HANDSHAKE_SETUPS
        if have_oqs or n not in NEEDS_OQS
    }
    bc = {
        n: asdict(measure_broadcast(n, 5 * reps))
        for n in BROADCAST_SETUPS
        if have_oqs or n not in NEEDS_OQS
    }
    return CryptoProfile(
        f"{platform.processor() or platform.machine()} / {platform.system()}", hs, bc
    )


def save(profile: CryptoProfile, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(profile), indent=1), encoding="utf-8")


def load(path: Path) -> CryptoProfile:
    d = json.loads(path.read_text(encoding="utf-8"))
    return CryptoProfile(d["machine"], d["handshakes"], d["broadcasts"])


def load_or_measure(path: Path, reps: int = 15) -> CryptoProfile:
    if path.exists():
        return load(path)
    p = measure_all(reps)
    save(p, path)
    return p


if __name__ == "__main__":
    p = measure_all()
    for n, h in p.handshakes.items():
        print(f"{n:13s} m1={h['m1_bytes']:5d} m2={h['m2_bytes']:5d} m3={h['m3_bytes']:3d}  "
              f"init={1e3*h['t_initiate']:.3f} resp={1e3*h['t_respond']:.3f} "
              f"fin={1e3*h['t_finish']:.3f} conf={1e3*h['t_confirm']:.3f} ms")  # fmt: skip
    for n, b in p.broadcasts.items():
        print(f"{n:16s} digest={b['msg_digest_bytes']:5d} cert={b['msg_cert_bytes']:5d}  "
              f"sign={1e3*b['t_sign']:.3f} verify={1e3*b['t_verify']:.3f} "
              f"cert={1e3*b['t_verify_cert']:.3f} ms")  # fmt: skip
