from __future__ import annotations

import argparse
import json

from .generator import Charset, Policy, generate, generate_for_policy, generate_passphrase, generate_pin
from .strength import audit


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwdgen", description="Secure passwords and passphrases.")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="random password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--no-upper", action="store_true")
    g.add_argument("--no-digits", action="store_true")
    g.add_argument("--exclude-ambiguous", action="store_true")
    g.add_argument("-n", "--count", type=int, default=1)
    g.add_argument("--policy", action="store_true", help="enforce the default 12-char policy")

    ph = sub.add_parser("passphrase", help="diceware-style passphrase")
    ph.add_argument("-w", "--words", type=int, default=5)
    ph.add_argument("-s", "--separator", default="-")
    ph.add_argument("--capitalise", action="store_true")

    pin = sub.add_parser("pin", help="numeric PIN")
    pin.add_argument("-d", "--digits", type=int, default=6)

    a = sub.add_parser("audit", help="score an existing password")
    a.add_argument("password", nargs="?", help="omit to read it without echoing to shell history")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "generate":
        policy = Policy(require_symbol=not args.no_symbols)
        for _ in range(max(1, args.count)):
            if args.policy:
                print(generate_for_policy(policy))
            else:
                print(
                    generate(
                        args.length,
                        Charset(
                            upper=not args.no_upper,
                            digits=not args.no_digits,
                            symbols=not args.no_symbols,
                            exclude_ambiguous=args.exclude_ambiguous,
                        ),
                    )
                )
    elif args.command == "passphrase":
        print(generate_passphrase(args.words, args.separator, capitalise=args.capitalise))
    elif args.command == "pin":
        print(generate_pin(args.digits))
    elif args.command == "audit":
        password = args.password
        if password is None:
            from getpass import getpass

            password = getpass("password: ")
        print(json.dumps(audit(password), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
