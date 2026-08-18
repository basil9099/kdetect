"""Command-line interface for kdetect."""

import argparse


def main(argv=None) -> int:
    # Each call below RETURNS an object, and we bind each one to a name
    # so we can use it on the next line. That is the whole trick.
    parser = argparse.ArgumentParser(
        prog="kdetect",
        description="Linux kernel rootkit detection via cross-view comparison.",
    )

    # dest="command" is what makes args.command exist later, holding
    # whichever subcommand name the user typed.
    subparsers = parser.add_subparsers(dest="command")

    # add_parser returns a NEW parser, independent of the top-level one.
    capture = subparsers.add_parser("capture", help="Snapshot the live system.")
    capture.add_argument(
        "--out",
        default=None,
        help="Output path. Use '-' for stdout. Default: a generated name in captures/.",
    )
    capture.add_argument(
        "--pretty", action="store_true", help="Indent the JSON output."
    )

    analyze = subparsers.add_parser("analyze", help="Summarise a snapshot file.")
    analyze.add_argument("snapshot", help="Path to a snapshot JSON file.")

    # parse_args goes on the TOP-LEVEL parser. argparse routes to the right
    # subcommand itself. argv=None makes it read sys.argv[1:].
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "capture":
        return 0  # Task 9 implements this

    if args.command == "analyze":
        return 0  # Task 10 implements this

    return 2


def cli_entry() -> None:
    """Console-script entry point named in pyproject.toml."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
