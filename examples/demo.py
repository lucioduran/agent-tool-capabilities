"""Issue, use and revoke one capability for a synthetic note."""

import json
from dataclasses import asdict

from agent_capabilities import Argument, Broker, Denied, Scope
from agent_capabilities.synthetic import MemoryNotes


def main():
    notes = MemoryNotes()
    broker = Broker({"append": notes.append})
    token = broker.issue(
        Scope("append", "/owned", {"text": Argument(32)}),
        calls=2,
        bytes=64,
        ttl=60,
    )
    broker.execute(token, "append", "/owned/note", {"text": "Hello"})
    broker.revoke(token)
    try:
        broker.execute(token, "append", "/owned/note", {"text": "blocked"})
    except Denied:
        pass
    print(
        json.dumps(
            {
                "notes": notes.snapshot(),
                "decisions": [asdict(d) for d in broker.decisions()],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
