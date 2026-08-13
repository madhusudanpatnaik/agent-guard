"""A stand-in for a real internal system (CRM + payments API).

It requires an API key that ONLY the AgentGuard control plane holds — agents never
receive it — which is what makes the enforcement demonstrable: without going
through the plane, an agent cannot authenticate here at all.

Run:  uvicorn examples.mock_upstream:app --port 9100
(or it is started automatically by examples/enforcing_demo.py)
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException

UPSTREAM_API_KEY = "upstream-super-secret-key-do-not-leak"

app = FastAPI(title="Internal CRM + Payments (mock upstream)")

# Pretend production data, including PII the agent should never harvest wholesale.
_CUSTOMERS = {
    "1042": {
        "id": 1042, "name": "Dana Reyes", "tier": "vip",
        "email": "dana.reyes@example.com", "ssn": "452-11-9832",
        "card_last4": "4242", "card_number": "4242 4242 4242 4242",
    },
    "1043": {
        "id": 1043, "name": "Sam Okafor", "tier": "standard",
        "email": "sam.okafor@example.com", "ssn": "610-22-7788",
        "card_last4": "1881", "card_number": "5555 5555 5555 4444",
    },
}


def _require_key(authorization: str | None, x_api_key: str | None) -> None:
    presented = None
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization.split(" ", 1)[1]
    presented = presented or x_api_key
    if presented != UPSTREAM_API_KEY:
        raise HTTPException(401, "missing/invalid upstream API key")


@app.get("/customers/{cid}")
def get_customer(cid: str, authorization: str | None = Header(None),
                 x_api_key: str | None = Header(None, alias="X-API-Key")):
    _require_key(authorization, x_api_key)
    cust = _CUSTOMERS.get(cid)
    if not cust:
        raise HTTPException(404, "no such customer")
    return cust


@app.post("/refunds")
def create_refund(payload: dict, authorization: str | None = Header(None),
                  x_api_key: str | None = Header(None, alias="X-API-Key")):
    _require_key(authorization, x_api_key)
    return {"refund_id": "re_" + str(payload.get("invoice", "x")), "status": "succeeded",
            "amount": payload.get("amount")}


@app.get("/health")
def health():
    return {"status": "ok"}
