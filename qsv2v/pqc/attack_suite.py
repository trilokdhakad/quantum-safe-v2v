"""Every Phase 4 attack class, re-run against PQ-V2V-AKE (experiment E5).

Each function really attempts the attack with the attacker's full capability
and reports whether it was blocked. Where it makes sense, a positive control
shows the attack WOULD succeed if the defence were removed (e.g. if the
ephemeral key were kept), so a "blocked" result cannot come from a broken test.

    python -m qsv2v.pqc.attack_suite
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from qsv2v.attacks.common import AuthenticationError, Timer
from qsv2v.pqc import pq_v2v_ake as A
from qsv2v.pqc.certs import CertError, PseudonymCert, verify_cert


@dataclass
class DefenseResult:
    attack: str
    analogue_of: str
    attacker: str
    blocked: bool
    evidence: list[str] = field(default_factory=list)
    control: str = ""
    elapsed_s: float = 0.0

    def report(self) -> str:
        lines = [
            f"[PQ-V2V-AKE] {self.attack}",
            f"  analogue of: {self.analogue_of}",
            f"  attacker   : {self.attacker}",
        ]
        lines += [f"  - {e}" for e in self.evidence]
        if self.control:
            lines.append(f"  control    : {self.control}")
        lines.append(f"  result     : {'BLOCKED' if self.blocked else 'NOT BLOCKED'}")
        return "\n".join(lines)


def _public_strings(tr: A.Transcript) -> list[bytes]:
    """Every byte string an eavesdropper sees, plus the certificates' contents."""
    out = []
    for m in (tr.m1, tr.m2, tr.m3):
        for f in dataclasses.fields(m):
            v = getattr(m, f.name)
            if isinstance(v, bytes) and v:
                out.append(v)
    for c in (tr.m1.cert, tr.m2.cert):
        cert = PseudonymCert.decode(c)
        out += [cert.public_key, cert.signature, cert.pseudonym]
    return out


def _derive_with(ikm: bytes, tr: A.Transcript) -> bytes:
    th1 = A.H(A.LABEL, tr.m1.encode())
    th2 = A.H(th1, tr.m2.body())
    return A._keys(ikm, b"", th2)[0]


# 1. PSRS-D2D passive key recovery -------------------------------------------
def passive_key_recovery(seed: int = 1) -> DefenseResult:
    net = A.setup_network(2, seed)
    tr = A.handshake(*net.vehicles, net.clock)
    res = DefenseResult(
        "Passive session-key recovery",
        "PSRS-D2D attack 1 (key computable from public values)",
        "eavesdropper with the full transcript, all certificates and the authority key",
        blocked=False,
    )
    with Timer() as t:
        pub = _public_strings(tr)
        hits = sum(_derive_with(s, tr) == tr.initiator.key for s in pub)
        hits += sum(_derive_with(s[:32], tr) == tr.initiator.key for s in pub)
    res.elapsed_s = t.elapsed
    res.blocked = hits == 0
    res.evidence = [
        f"tried the key schedule on all {2 * len(pub)} public values: {hits} matched",
        "the key's only secret input is ss = ML-KEM.Decaps(dk_e, ct); dk_e is never sent",
    ]
    return res


# 2. Forward secrecy after long-term key leak ---------------------------------
def forward_secrecy(seed: int = 2) -> DefenseResult:
    net = A.setup_network(2, seed)
    vi, vr = net.vehicles
    m1, st = A.initiate(vi, net.clock)
    leaked_dk_during_session = st.dk  # positive control only: session-state reveal
    m2, st_r = A.respond(vr, m1, net.clock)
    m3, res_i = A.finish(vi, st, m2, net.clock)
    A.confirm(st_r, m3)
    tr = A.Transcript(m1, m2, m3, res_i, res_i)
    res = DefenseResult(
        "Past sessions after every long-term key leaks",
        "PSRS-D2D attack 2, P2AS-IoAV attack 2 (no forward secrecy)",
        "recorded transcript; later gets both vehicles' signing keys and the authority's key",
        blocked=False,
    )
    with Timer() as t:
        leaked = [c.secret_key for v in (vi, vr) for c in v.credentials]
        leaked.append(net.authority._secret_key)
        hits = 0
        for k in leaked:
            try:
                ss = vi.kem.decaps(k, m2.ct)
            except Exception:
                continue
            hits += _derive_with(ss, tr) == res_i.key
        control = _derive_with(vi.kem.decaps(leaked_dk_during_session, m2.ct), tr) == res_i.key
    res.elapsed_s = t.elapsed
    res.blocked = hits == 0 and st.dk is None and control
    res.evidence = [
        f"{len(leaked)} leaked long-term secrets tried as decapsulation keys: {hits} gave the key",
        f"initiator's ephemeral key erased after use: {st.dk is None}",
    ]
    res.control = (
        f"with the ephemeral key (if it had been kept, as P2AS keeps static keys) the key IS "
        f"recovered: {control}"
    )
    return res


# 3. Capture vehicles, extract or forge certificates --------------------------
def capture_and_forge(seed: int = 3) -> DefenseResult:
    net = A.setup_network(3, seed)
    a, b, victim = net.vehicles
    now = net.clock.now()
    res = DefenseResult(
        "Capture two vehicles, then forge a certificate",
        "PSRS-D2D attack 3 (authority keys from two certificates)",
        "full memory of two captured vehicles (all their keys and certificates)",
        blocked=False,
    )
    rejected = []
    with Timer() as t:
        cap = a.credentials[0]
        # (a) certify a new key by signing it with a captured vehicle key
        forged = dataclasses.replace(cap.cert, public_key=b.credentials[0].cert.public_key)
        forged = dataclasses.replace(forged, signature=a.scheme.sign(cap.secret_key, forged.tbs()))
        # (b) graft a captured certificate onto a fresh key (signature no longer matches)
        kp = a.scheme.keygen()
        grafted = dataclasses.replace(cap.cert, public_key=kp.public_key)
        # (c) impersonate the uncaptured victim: copy its certificate, sign with a captured key
        for name, cert in [
            ("self-signed new certificate", forged),
            ("grafted certificate", grafted),
        ]:
            try:
                verify_cert(cert, net.authority.public_key, net.authority.scheme, now)
                rejected.append((name, False))
            except CertError as e:
                rejected.append((name, True, str(e)))
        m1, _ = A.initiate(victim, net.clock)
        fake = dataclasses.replace(m1, sig=a.scheme.sign(cap.secret_key, A.LABEL + m1.body()))
        try:
            A.respond(b, fake, net.clock)
            rejected.append(("victim's certificate with attacker signature", False))
        except AuthenticationError as e:
            rejected.append(("victim's certificate with attacker signature", True, str(e)))
    res.elapsed_s = t.elapsed
    res.blocked = all(r[1] for r in rejected)
    res.evidence = [
        f"{r[0]}: {'rejected (' + r[2] + ')' if r[1] else 'ACCEPTED'}" for r in rejected
    ]
    res.evidence.append(
        "certificates are ML-DSA signatures by the authority: no equations in its secret to solve"
    )
    return res


# 4. Forged / replayed message 1 ----------------------------------------------
def forged_msg1(seed: int = 4) -> DefenseResult:
    net = A.setup_network(3, seed)
    honest, resp, attacker = net.vehicles
    res = DefenseResult(
        "Forged or replayed message 1",
        "P2AS-IoAV attack 1 (drone accepts forged message 1)",
        "no valid credentials for the victim; can observe and replay traffic",
        blocked=False,
    )
    outcomes = []

    def attempt(name, m1, clock=net.clock, who=resp):
        try:
            A.respond(who, m1, clock)
            outcomes.append((name, False, "accepted"))
        except AuthenticationError as e:
            outcomes.append((name, True, str(e)))

    with Timer() as t:
        real_m1, _ = A.initiate(honest, net.clock)
        # (a) brand-new key, honest's observed certificate
        kp = attacker.scheme.keygen()
        forged = dataclasses.replace(
            real_m1, sig=attacker.scheme.sign(kp.secret_key, A.LABEL + real_m1.body())
        )
        attempt("observed certificate, attacker's signature", forged)
        # (b) tamper with the ephemeral key of a real message
        attempt(
            "real message with swapped ephemeral key",
            dataclasses.replace(real_m1, ek=kp.public_key[:1184].ljust(1184, b"\0")),
        )
        # (c) legitimate message accepted once, then replayed
        A.respond(resp, real_m1, net.clock)
        attempt("replay of a real message within the window", real_m1)
        # (d) replay to another vehicle much later
        net.clock.advance(60)
        attempt("replay 60 s later", real_m1, who=attacker)
        # (e) revoked vehicle
        net.authority.revoke(net.real_ids[0])
        resp.crl = net.authority.crl(net.clock.now())
        fresh, _ = A.initiate(honest, net.clock)
        attempt("message from a revoked vehicle", fresh)
    res.elapsed_s = t.elapsed
    res.blocked = all(o[1] for o in outcomes)
    res.evidence = [
        f"{o[0]}: {'rejected (' + o[2] + ')' if o[1] else 'ACCEPTED'}" for o in outcomes
    ]
    return res


# 5. Man in the middle on the encapsulation -----------------------------------
def mitm_swap(seed: int = 5) -> DefenseResult:
    net = A.setup_network(2, seed)
    vi, vr = net.vehicles
    res = DefenseResult(
        "Man in the middle swaps the KEM ciphertext",
        "P2AS-IoAV / PSRS-D2D MITM claims",
        "controls the channel; re-encapsulates to the initiator's ephemeral key",
        blocked=False,
    )
    with Timer() as t:
        m1, st = A.initiate(vi, net.clock)
        m2, _ = A.respond(vr, m1, net.clock)
        ct_att, _ = vi.kem.encaps(m1.ek)
        try:
            A.finish(vi, st, dataclasses.replace(m2, ct=ct_att), net.clock)
            outcome = (False, "accepted")
        except AuthenticationError as e:
            outcome = (True, str(e))
    res.elapsed_s = t.elapsed
    res.blocked = outcome[0]
    res.evidence = [
        f"swapped ciphertext: {'rejected (' + outcome[1] + ')' if outcome[0] else 'ACCEPTED'}"
    ]
    return res


# 6. Linking sessions -----------------------------------------------------------
def linking(seed: int = 6, window: int = 16) -> DefenseResult:
    """Does anything in a vehicle's messages single it out across pseudonyms?

    A byte window links two sessions only if it appears in both of one vehicle's
    sessions (different pseudonyms) but NOT in another vehicle's session: shared
    format bytes and the zero runs at the end of every ML-DSA signature appear
    in everyone's messages and identify no one.
    """
    net = A.setup_network(3, seed, n_pseudonyms=2, lifetime=300)
    v0, v1, v2 = net.vehicles
    s1 = A.handshake(v0, v1, net.clock)
    net.clock.advance(10)
    s_same = A.handshake(v0, v1, net.clock)  # same pseudonym window
    other = A.handshake(v2, v1, net.clock)  # a different vehicle, same time
    net.clock.advance(300)
    s2 = A.handshake(v0, v1, net.clock)  # v0's next pseudonym
    res = DefenseResult(
        "Linking a vehicle's sessions",
        "PSLAP attack 1 (static pseudo-identity)",
        "passive observer of every message",
        blocked=False,
    )

    def windows(b: bytes) -> set[bytes]:
        return {b[i : i + window] for i in range(0, max(len(b) - window + 1, 0))}

    with Timer() as t:
        common = windows(s1.m1.encode()) & windows(s2.m1.encode())
        distinguishing = common - windows(other.m1.encode())
        cert1, cert2 = PseudonymCert.decode(s1.m1.cert), PseudonymCert.decode(s2.m1.cert)
        id_fields_equal = cert1.pseudonym == cert2.pseudonym or cert1.public_key == cert2.public_key
        same_window_linked = s1.m1.cert == s_same.m1.cert
        control_hits = len(
            (windows(s1.m1.encode()) & windows(s_same.m1.encode())) - windows(other.m1.encode())
        )
    res.elapsed_s = t.elapsed
    res.blocked = not id_fields_equal and not distinguishing and control_hits > 0
    res.control = (
        f"the same test on two sessions under ONE pseudonym finds {control_hits} "
        "identifying windows, so it does detect linkable traffic"
    )
    res.evidence = [
        f"different pseudonyms share an identifier (pseudonym or key): {id_fields_equal}",
        f"{len(common)} {window}-byte windows shared across the two pseudonyms; "
        f"{len(distinguishing)} absent from another vehicle's message (would identify it)",
        "honest limit: two sessions under the SAME pseudonym (lifetime 300 s) are linkable: "
        f"{same_window_linked}; the rotation interval is the privacy setting",
    ]
    return res


# 7. Offline password guessing --------------------------------------------------
def password_guessing() -> DefenseResult:
    fields = {f.name for f in dataclasses.fields(A.Vehicle)}
    has_pw = any("pw" in f.lower() or "password" in f.lower() for f in fields)
    return DefenseResult(
        "Offline password guessing from vehicle storage",
        "PSLAP attack 2 (password verifier in the OBU)",
        "full read-out of a vehicle's stored state",
        blocked=not has_pw,
        evidence=[
            f"stored vehicle state: {sorted(fields)}",
            "no password or password-derived verifier exists to test guesses against",
        ],
    )


# 8. Quantum adversary in hybrid mode -------------------------------------------
def quantum_breaks_x25519(seed: int = 8) -> DefenseResult:
    net = A.setup_network(2, seed, hybrid=True)
    vi, vr = net.vehicles
    m1, st = A.initiate(vi, net.clock)
    x_sk_i = st.x_sk  # a Shor-capable attacker can recover X25519 secrets from public keys
    m2, st_r = A.respond(vr, m1, net.clock)
    m3, res_i = A.finish(vi, st, m2, net.clock)
    res = DefenseResult(
        "Quantum attacker breaks X25519 in hybrid mode",
        "Shor demo (ECC falls to a quantum computer)",
        "learns the X25519 shared secret (as Shor's algorithm would), plus the transcript",
        blocked=False,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    with Timer() as t:
        x_ss = x_sk_i.exchange(X25519PublicKey.from_public_bytes(m2.x_pub))
        th2 = A.H(A.H(A.LABEL, m1.encode()), m2.body())
        guesses = [
            A._keys(s, x_ss, th2)[0]
            for s in [b"\0" * 32, x_ss] + _public_strings(A.Transcript(m1, m2, m3, res_i, res_i))
        ]
        hits = sum(g == res_i.key for g in guesses)
    res.elapsed_s = t.elapsed
    res.blocked = hits == 0
    res.evidence = [
        f"with the X25519 secret and {len(guesses)} candidate ML-KEM secrets: {hits} matched",
        "the key also needs the ML-KEM shared secret, which Shor's algorithm does not give",
    ]
    return res


def run_all() -> list[DefenseResult]:
    return [
        passive_key_recovery(),
        forward_secrecy(),
        capture_and_forge(),
        forged_msg1(),
        mitm_swap(),
        linking(),
        password_guessing(),
        quantum_breaks_x25519(),
    ]


if __name__ == "__main__":
    rs = run_all()
    for r in rs:
        print(r.report(), end="\n\n")
    print(f"{sum(r.blocked for r in rs)}/{len(rs)} attack classes blocked")
