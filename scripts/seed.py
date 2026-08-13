"""Thin CLI wrapper around :func:`agentguard.seeds.seed`."""

from __future__ import annotations

from agentguard.seeds import seed


def main() -> None:
    keys = seed(reset=False)
    if keys:
        print("Created agents (store these API keys securely — shown once):")
        for name, key in keys.items():
            print(f"  {name:18} {key}")
    else:
        print("No new agents created (already seeded). Use --reset via `agentguard seed --reset`.")


if __name__ == "__main__":
    main()
