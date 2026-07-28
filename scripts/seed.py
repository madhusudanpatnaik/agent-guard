"""Thin CLI wrapper around :func:`agentops.seeds.seed`."""

from __future__ import annotations

from agentops.seeds import seed


def main() -> None:
    keys = seed(reset=False)
    if keys:
        print("Created agents (store these API keys securely — shown once):")
        for name, key in keys.items():
            print(f"  {name:18} {key}")
    else:
        print("No new agents created (already seeded). Use --reset via `agentops seed --reset`.")


if __name__ == "__main__":
    main()
