"""Run every Phase 4 attack and print recovered secrets next to the victims'.

python -m qsv2v.attacks            # all attacks, Shor on N = 15
python -m qsv2v.attacks --n21      # also Shor on N = 21 (about 2-3 minutes)
python -m qsv2v.attacks --kem oqs  # P2AS-IoAV on liboqs instead of kyber-py
"""

from __future__ import annotations

import argparse
import sys

from qsv2v.attacks import p2as_ioav, pslap, psrs_d2d, shor_demo  # noqa: F401
from qsv2v.attacks.p2as_ioav import attacks as p2as_attacks
from qsv2v.attacks.pslap import attacks as pslap_attacks
from qsv2v.attacks.psrs_d2d import attacks as psrs_attacks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--kem", choices=["kyber-py", "oqs"], default="kyber-py")
    ap.add_argument("--n21", action="store_true", help="also run Shor on N = 21 (slow)")
    args = ap.parse_args(argv)

    results = []
    results += psrs_attacks.run_all(args.seed)
    results += pslap_attacks.run_all(args.seed)
    results += p2as_attacks.run_all(args.seed, args.kem)
    results.append(shor_demo.demo_shor(15, args.seed + 15))
    if args.n21:
        results.append(shor_demo.demo_shor(21, args.seed + 21))

    for r in results:
        print(r.report(), end="\n\n")
    print("Summary")
    print("-" * 78)
    for r in results:
        print(f"  {'SUCCESS' if r.success else 'FAILED '}  {r.paper[:26]:26s}  {r.attack[:42]}")
    ok = sum(r.success for r in results)
    print("-" * 78)
    print(f"  {ok}/{len(results)} attacks recovered the victim's secret")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
