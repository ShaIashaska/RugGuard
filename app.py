#!/usr/bin/env python3
"""
RugGuard - A Rug Pull Detection Tool (Backend)
==============================================
Implementation of the detection framework from the thesis:
  "The Psychology of Rug Pulls in Web3: A Socio-Technical Analysis"
  Section 4.5 - Detection Framework

You paste ONE token contract address. The backend then:
  1. Pulls live on-chain security data (GoPlus API) - contract controls,
     liquidity lock, and holder/tokenomics signals.
  2. Auto-fetches the contract's verified source code (Etherscan V2 API) and
     scans it for dangerous code patterns (e.g. the SQUID approveTo/ifSir
     upgrade gate and the delegatecall proxy). If the contract is a proxy, it
     also fetches and scans the hidden implementation contract.
  3. Combines everything into ONE risk score, with every red flag mapped to a
     section of the thesis.

Chains supported: BNB Smart Chain (BSC) and Ethereum.

Data sources (both free):
  - GoPlus Token Security API  (no key required)
  - Etherscan V2 API           (one free key, works for BSC + ETH)

Run locally:
  python app.py            -> http://127.0.0.1:5000
"""

import os
import re
import json
import math
import urllib.parse
import urllib.request
import urllib.error
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Paste your free Etherscan API key between the quotes below, OR set an
# environment variable called ETHERSCAN_API_KEY. The environment variable
# wins if both are set. Without a key, on-chain checks still run, but the
# automatic code analysis is skipped.
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

# Chains supported: BSC and Ethereum only.
CHAINS = {
    "ethereum": "1",
    "bsc": "56",
}

GOPLUS_URL = ("https://api.gopluslabs.io/api/v1/token_security/"
              "{chain_id}?contract_addresses={address}")
ETHERSCAN_URL = "https://api.etherscan.io/v2/api"


# ===========================================================================
# CATEGORY LABELS (used to group findings in the UI)
# ===========================================================================
CAT_CONTRACT = "Contract & team control"
CAT_TOKENOMICS = "Tokenomics & holders"
CAT_LIQUIDITY = "Liquidity"
CAT_CODE = "Contract code"


# ===========================================================================
# PART 1 - ON-CHAIN CHECKS (GoPlus)
# ===========================================================================
# Each rule maps one field from the GoPlus API to a red flag in the thesis.
# ---------------------------------------------------------------------------
TECHNICAL_RULES = [
    {"key": "is_honeypot", "trigger": "1", "weight": 40, "cat": CAT_CONTRACT,
     "label": "Honeypot: buyers are blocked from selling",
     "thesis": "Sec 4.1 - SQUID honeypot sell restriction"},

    {"key": "cannot_sell_all", "trigger": "1", "weight": 30, "cat": CAT_CONTRACT,
     "label": "Sell restriction: holders cannot sell all of their tokens",
     "thesis": "Sec 4.1.1 - SQUID transfer mechanism blocked selling"},

    {"key": "cannot_buy", "trigger": "1", "weight": 12, "cat": CAT_CONTRACT,
     "label": "Buy restriction present",
     "thesis": "Sec 2.2 - honeypot mechanics"},

    {"key": "is_open_source", "trigger": "0", "weight": 20, "cat": CAT_CONTRACT,
     "label": "Contract source code is NOT verified / readable",
     "thesis": "Sec 4.5 - unverified contract red flag"},

    {"key": "is_proxy", "trigger": "1", "weight": 10, "cat": CAT_CONTRACT,
     "label": "Proxy contract: real logic can be hidden and swapped",
     "thesis": "Sec 4.1.1 - SQUID proxy obfuscation (approveTo/ifSir)"},

    {"key": "is_mintable", "trigger": "1", "weight": 15, "cat": CAT_CONTRACT,
     "label": "Mint function present: supply can be inflated",
     "thesis": "Sec 2.2 - hidden-mint hard rug pull"},

    {"key": "can_take_back_ownership", "trigger": "1", "weight": 15,
     "cat": CAT_CONTRACT,
     "label": "Ownership can be reclaimed by the deployer",
     "thesis": "Sec 4.1.1 - admin-only privileged control"},

    {"key": "hidden_owner", "trigger": "1", "weight": 15, "cat": CAT_CONTRACT,
     "label": "Hidden owner address",
     "thesis": "Sec 4.5 - concealed control"},

    {"key": "owner_change_balance", "trigger": "1", "weight": 20,
     "cat": CAT_CONTRACT,
     "label": "Owner can change wallet balances arbitrarily",
     "thesis": "Sec 4.5 - privileged control over funds"},

    {"key": "selfdestruct", "trigger": "1", "weight": 15, "cat": CAT_CONTRACT,
     "label": "Contract can self-destruct",
     "thesis": "Sec 4.5 - technical red flag"},

    {"key": "transfer_pausable", "trigger": "1", "weight": 10, "cat": CAT_CONTRACT,
     "label": "Transfers can be paused by the team",
     "thesis": "Sec 2.2 - team control over trading"},

    {"key": "is_blacklisted", "trigger": "1", "weight": 12, "cat": CAT_CONTRACT,
     "label": "Blacklist mechanism: wallets can be blocked from selling",
     "thesis": "Sec 2.2 - honeypot / sell-block mechanics"},
]


def fetch_token(chain_id, address):
    """Call the GoPlus API. Returns (token_dict, error_string)."""
    url = GOPLUS_URL.format(chain_id=chain_id, address=address)
    req = urllib.request.Request(url, headers={"User-Agent": "RugGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return None, f"Could not reach the security API: {e}"
    except Exception as e:  # noqa: BLE001
        return None, f"Unexpected error: {e}"

    if data.get("code") != 1:
        return None, f"API error: {data.get('message', 'unknown')}"

    token = (data.get("result") or {}).get(address.lower())
    if not token:
        return None, ("No data for this address. It may not be a token, "
                      "or it is too new to be indexed yet.")
    return token, None


def top_holder_concentration(token):
    """Top-10 holder concentration (insider / whale signal)."""
    holders = token.get("holders") or []
    pcts = []
    for h in holders:
        try:
            v = float(h.get("percent", 0))
            if math.isfinite(v):
                pcts.append(v)
        except (TypeError, ValueError):
            continue
    pcts.sort(reverse=True)
    return round(sum(pcts[:10]) * 100, 2)


def check_lp_lock(token):
    """Liquidity-pool lock check (AnubisDAO pattern). Returns locked %."""
    holders = token.get("lp_holders") or []
    if not holders:
        return None
    locked = 0.0
    for h in holders:
        try:
            v = float(h.get("percent", 0))
            if str(h.get("is_locked")) == "1" and math.isfinite(v):
                locked += v * 100
        except (TypeError, ValueError):
            continue
    return round(locked, 2)


def pct(token, key):
    try:
        v = token.get(key)
        if v in (None, ""):
            return None
        f = float(v) * 100
        return round(f, 2) if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None


def assess_token(token):
    """Build the on-chain part: flags (categorized), stats, unknown fields."""
    flags = []
    unknown = []

    for rule in TECHNICAL_RULES:
        val = token.get(rule["key"])
        if val is None or val == "":
            unknown.append(rule["label"])
            continue
        if str(val) == rule["trigger"]:
            flags.append({"label": rule["label"], "weight": rule["weight"],
                          "thesis": rule["thesis"], "category": rule["cat"]})

    # Liquidity lock -- AnubisDAO pattern.
    lp_locked = check_lp_lock(token)
    if lp_locked is not None and lp_locked < 50:
        flags.append({
            "label": f"Only {lp_locked}% of liquidity is locked - the "
                     f"deployer can pull the pool",
            "weight": 20, "category": CAT_LIQUIDITY,
            "thesis": "Sec 4.2 - AnubisDAO unlocked liquidity pool"})

    # Top-holder concentration -- insider / whale signal.
    top10 = top_holder_concentration(token)
    if top10 >= 70:
        flags.append({
            "label": f"Top 10 wallets hold {top10}% of supply - extreme "
                     f"concentration (insider / whale control)",
            "weight": 20, "category": CAT_TOKENOMICS,
            "thesis": "Sec 4.4 - insider concentration risk"})
    elif top10 >= 50:
        flags.append({
            "label": f"Top 10 wallets hold {top10}% of supply - high "
                     f"concentration",
            "weight": 10, "category": CAT_TOKENOMICS,
            "thesis": "Sec 4.4 - insider concentration risk"})

    # Creator holding -- insider signal.
    creator = pct(token, "creator_percent")
    if creator is not None and creator >= 5:
        flags.append({
            "label": f"Creator wallet holds {creator}% of supply",
            "weight": 10, "category": CAT_TOKENOMICS,
            "thesis": "Sec 4.4 - insider concentration risk"})

    # Very high taxes -- soft honeypot.
    for tkey, name in (("buy_tax", "buy"), ("sell_tax", "sell")):
        t = pct(token, tkey)
        if t is not None and t >= 20:
            flags.append({
                "label": f"Very high {name} tax: {t}%",
                "weight": 10, "category": CAT_TOKENOMICS,
                "thesis": "Sec 2.2 - hidden cost extraction"})

    return {
        "name": token.get("token_name") or "Unknown token",
        "symbol": token.get("token_symbol") or "?",
        "flags": flags,
        "unknown": unknown,
        "stats": {
            "holder_count": token.get("holder_count") or "n/a",
            "top10_percent": top10,
            "creator_percent": creator,
            "lp_locked_percent": lp_locked,
        },
    }


# ===========================================================================
# PART 2 - CONTRACT CODE FETCH + ANALYSIS (Etherscan V2)
# ===========================================================================
CODE_PATTERNS = [
    {"name": "owner-gated upgrade switch",
     "regex": r"approveTo|upgradeTo|setImplementation|_upgradeTo",
     "weight": 25,
     "label": "Owner-gated upgrade switch (e.g. approveTo): admin can swap "
              "the live contract logic at any time",
     "thesis": "Sec 4.1.1 - SQUID approveTo / ifSir upgrade gate"},

    {"name": "delegatecall proxy",
     "regex": r"delegatecall",
     "weight": 15,
     "label": "delegatecall / proxy pattern: the real logic can live in a "
              "hidden, swappable contract",
     "thesis": "Sec 4.1.1 & 4.2 - SQUID proxy obfuscation"},

    {"name": "mint",
     "regex": r"function\s+\w*[mM]int\w*\s*\(",
     "weight": 15,
     "label": "Mint function: token supply can be inflated by the team",
     "thesis": "Sec 2.2 - hidden-mint hard rug pull"},

    {"name": "blacklist",
     "regex": r"[bB]lacklist|_isBlacklisted|denylist|_isBot|setBots",
     "weight": 15,
     "label": "Blacklist mechanism: specific wallets can be blocked from "
              "selling (honeypot behaviour)",
     "thesis": "Sec 2.2 - honeypot / sell-block mechanics"},

    {"name": "adjustable fee / tax",
     "regex": r"function\s+\w*[sS]et\w*(Fee|Fees|Tax|Taxes)\w*\s*\(",
     "weight": 12,
     "label": "Adjustable fee/tax: sell tax can be raised arbitrarily "
              "(soft honeypot)",
     "thesis": "Sec 2.2 - hidden cost extraction"},

    {"name": "pause trading",
     "regex": r"function\s+\w*[pP]ause\w*\s*\(",
     "weight": 12,
     "label": "Pause function: the team can freeze all transfers/trading",
     "thesis": "Sec 2.2 - team control over trading"},

    {"name": "trading on/off switch",
     "regex": r"enableTrading|openTrading|setTrading|tradingActive|"
              r"setTradingEnabled",
     "weight": 10,
     "label": "Trading on/off switch controlled by the team",
     "thesis": "Sec 2.2 - team control over trading"},

    {"name": "adjustable max transaction / wallet",
     "regex": r"function\s+\w*[sS]etMax\w*\s*\(",
     "weight": 8,
     "label": "Adjustable max transaction/wallet limit: can be set to block "
              "selling",
     "thesis": "Sec 2.2 - trading restriction control"},

    {"name": "selfdestruct",
     "regex": r"selfdestruct",
     "weight": 15,
     "label": "selfdestruct: the contract can be destroyed",
     "thesis": "Sec 4.5 - technical red flag"},
]


def fetch_source(chain_id, address, follow_proxy=True):
    """
    Fetch verified Solidity source from Etherscan V2.
    Returns (source_string, status, contract_name).
    status: 'ok' | 'no_key' | 'not_verified' | 'error'
    """
    if not ETHERSCAN_API_KEY:
        return "", "no_key", ""

    params = urllib.parse.urlencode({
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    })
    url = f"{ETHERSCAN_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "RugGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001
        return "", "error", ""

    if str(data.get("status")) != "1":
        return "", "error", ""

    res = (data.get("result") or [{}])[0]
    src = res.get("SourceCode") or ""
    if not src.strip():
        return "", "not_verified", ""

    name = res.get("ContractName", "")
    # If this is a proxy, also fetch and append the implementation source,
    # because that is where the real (possibly malicious) logic lives.
    if (follow_proxy and str(res.get("Proxy")) == "1"
            and str(res.get("Implementation", "")).startswith("0x")):
        impl_src, _, _ = fetch_source(chain_id, res["Implementation"],
                                      follow_proxy=False)
        if impl_src:
            src = (src + "\n\n// ===== IMPLEMENTATION CONTRACT =====\n"
                   + impl_src)
    return src, "ok", name


def analyze_source(source):
    """Scan Solidity source for dangerous patterns. Returns list of flags."""
    flags = []
    lines = source.splitlines()
    for pat in CODE_PATTERNS:
        if not re.search(pat["regex"], source):
            continue
        line_no = None
        snippet = ""
        for i, line in enumerate(lines, start=1):
            if re.search(pat["regex"], line):
                line_no = i
                snippet = line.strip()[:120]
                break
        flags.append({
            "label": pat["label"], "weight": pat["weight"],
            "thesis": pat["thesis"], "category": CAT_CODE,
            "line": line_no, "evidence": snippet,
        })
    return flags


# ===========================================================================
# SCORING
# ===========================================================================
def verdict(score):
    if score >= 60:
        return "HIGH RISK", "Strong rug-pull signals. Do not invest."
    if score >= 30:
        return "MEDIUM RISK", "Several red flags. Investigate carefully."
    if score > 0:
        return "LOW RISK", "Minor flags found. Stay cautious."
    return "NO RED FLAGS", ("No technical red flags detected. NOTE: the social "
                            "layer is not checked here - see thesis Sec 4.4.")


def build_report(onchain, code_flags, code_status, name_hint=""):
    """Merge on-chain flags + code flags into one scored report."""
    flags = list(onchain["flags"]) + list(code_flags)
    score = min(sum(f["weight"] for f in flags), 100)
    label, advice = verdict(score)
    name = onchain.get("name") or name_hint or "Unknown token"
    return {
        "name": name,
        "symbol": onchain.get("symbol", "?"),
        "score": score,
        "verdict": label,
        "advice": advice,
        "flags": flags,
        "unknown": onchain.get("unknown", []),
        "stats": onchain.get("stats", {}),
        "code_status": code_status,
    }


# ===========================================================================
# DEMO DATA  (so the tool can be shown offline, e.g. live in your defense)
# ===========================================================================
DEMO_TOKEN = {
    "token_name": "Squid Game (offline demo sample)",
    "token_symbol": "SQUID",
    "is_open_source": "1", "is_proxy": "1", "is_mintable": "0",
    "is_honeypot": "1", "cannot_sell_all": "1", "cannot_buy": "0",
    "can_take_back_ownership": "1", "hidden_owner": "0",
    "owner_change_balance": "0", "selfdestruct": "0",
    "transfer_pausable": "1", "is_blacklisted": "0",
    "buy_tax": "0", "sell_tax": "0.99", "holder_count": "102154",
    "creator_percent": "0.12",
    "lp_holders": [{"is_locked": 0, "percent": "0.92"}],
    "holders": [
        {"percent": "0.41"}, {"percent": "0.19"}, {"percent": "0.07"},
        {"percent": "0.05"}, {"percent": "0.03"}, {"percent": "0.02"},
        {"percent": "0.02"}, {"percent": "0.01"}, {"percent": "0.01"},
        {"percent": "0.01"},
    ],
}

DEMO_SOURCE = """\
// Squid Game Token - excerpt (thesis Figures 4.1 and 4.2)

function approveTo(address newGame) external ifSir {
    _approveTo(newGame);
}

function _delegate(address implementation) internal {
    assembly {
        calldatacopy(0, 0, calldatasize())
        let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
"""


# ===========================================================================
# ROUTES
# ===========================================================================
@app.route("/")
def index():
    return render_template("index.html", has_key=bool(ETHERSCAN_API_KEY))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}

    # Offline demo: merge baked-in token data + baked-in SQUID code.
    if data.get("demo"):
        onchain = assess_token(DEMO_TOKEN)
        code_flags = analyze_source(DEMO_SOURCE)
        return jsonify(build_report(onchain, code_flags, "demo"))

    address = (data.get("address") or "").strip()
    chain = (data.get("chain") or "bsc").lower()
    if not address:
        return jsonify({"error": "Please enter a contract address."})
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
        return jsonify({"error": "That doesn't look like a valid contract "
                                 "address (it should be 0x + 40 characters)."})
    chain_id = CHAINS.get(chain)
    if not chain_id:
        return jsonify({"error": f"Unsupported chain '{chain}'. Use BSC or "
                                 f"Ethereum."})

    # 1) On-chain checks (GoPlus).
    token, err = fetch_token(chain_id, address)
    if err:
        return jsonify({"error": err})
    onchain = assess_token(token)

    # 2) Auto-fetch + analyze the contract code (Etherscan V2).
    source, code_status, _ = fetch_source(chain_id, address)
    code_flags = analyze_source(source) if source else []

    return jsonify(build_report(onchain, code_flags, code_status))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
