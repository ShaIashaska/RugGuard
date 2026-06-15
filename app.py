import os
import re
import json
import math
import urllib.parse
import urllib.request
import urllib.error
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

CHAINS = {"ethereum": "1", "bsc": "56"}

GOPLUS_URL = ("https://api.gopluslabs.io/api/v1/token_security/"
              "{chain_id}?contract_addresses={address}")
ETHERSCAN_URL = "https://api.etherscan.io/v2/api"

CAT_CONTRACT = "Contract & team control"
CAT_TOKENOMICS = "Tokenomics & holders"
CAT_LIQUIDITY = "Liquidity"
CAT_CODE = "Contract code"

SEVERITY_POINTS = {"critical": 45, "high": 22, "medium": 11, "low": 5}

BURN_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

RULES = [
    {"key": "is_honeypot", "trigger": "1", "sev": "critical",
     "name": "honeypot", "cat": CAT_CONTRACT,
     "label": "Honeypot: buyers are blocked from selling"},

    {"key": "cannot_sell_all", "trigger": "1", "sev": "critical",
     "name": "sell restriction", "cat": CAT_CONTRACT,
     "label": "Sell restriction: holders cannot sell all of their tokens"},

    {"key": "owner_change_balance", "trigger": "1", "sev": "critical",
     "name": "balance control", "cat": CAT_CONTRACT,
     "label": "The owner can change any wallet's balance at will"},

    {"key": "cannot_buy", "trigger": "1", "sev": "medium",
     "name": "buy restriction", "cat": CAT_CONTRACT,
     "label": "Buying this token is restricted"},

    {"key": "is_open_source", "trigger": "0", "sev": "high",
     "name": "source verification", "cat": CAT_CONTRACT,
     "label": "The contract is not verified, so its code cannot be read"},

    {"key": "is_proxy", "trigger": "1", "sev": "medium",
     "name": "proxy", "cat": CAT_CONTRACT,
     "label": "Proxy contract: the real logic can be hidden and swapped later"},

    {"key": "is_mintable", "trigger": "1", "sev": "high",
     "name": "mint function", "cat": CAT_CONTRACT,
     "label": "The team can mint new tokens and inflate the supply"},

    {"key": "can_take_back_ownership", "trigger": "1", "sev": "high",
     "name": "ownership reclaim", "cat": CAT_CONTRACT,
     "label": "Ownership can be reclaimed by the deployer after being given up"},

    {"key": "hidden_owner", "trigger": "1", "sev": "high",
     "name": "hidden owner", "cat": CAT_CONTRACT,
     "label": "The contract has a hidden owner address"},

    {"key": "selfdestruct", "trigger": "1", "sev": "high",
     "name": "self-destruct", "cat": CAT_CONTRACT,
     "label": "The contract can destroy itself"},

    {"key": "transfer_pausable", "trigger": "1", "sev": "medium",
     "name": "pausable transfers", "cat": CAT_CONTRACT,
     "label": "The team can pause all transfers and trading"},

    {"key": "is_blacklisted", "trigger": "1", "sev": "high",
     "name": "blacklist", "cat": CAT_CONTRACT,
     "label": "The team can blacklist wallets and block them from selling"},

    {"key": "honeypot_with_same_creator", "trigger": "1", "sev": "high",
     "name": "creator history", "cat": CAT_CONTRACT,
     "label": "The creator has deployed other honeypot tokens before"},

    {"key": "is_airdrop_scam", "trigger": "1", "sev": "high",
     "name": "airdrop scam", "cat": CAT_CONTRACT,
     "label": "This token has been flagged as an airdrop scam"},

    {"key": "external_call", "trigger": "1", "sev": "medium",
     "name": "external calls", "cat": CAT_CONTRACT,
     "label": "The contract makes external calls that can change its behaviour"},

    {"key": "slippage_modifiable", "trigger": "1", "sev": "medium",
     "name": "changeable tax", "cat": CAT_CONTRACT,
     "label": "The trading tax can be changed by the team at any time"},

    {"key": "trading_cooldown", "trigger": "1", "sev": "low",
     "name": "trading cooldown", "cat": CAT_CONTRACT,
     "label": "A trading cooldown can delay how soon you are allowed to sell"},

    {"key": "anti_whale_modifiable", "trigger": "1", "sev": "low",
     "name": "changeable max limit", "cat": CAT_CONTRACT,
     "label": "The maximum transaction size can be changed by the team"},
]


def fetch_token(chain_id, address):
    url = GOPLUS_URL.format(chain_id=chain_id, address=address)
    req = urllib.request.Request(url, headers={"User-Agent": "RugGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return None, f"Could not reach the security API: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"
    if data.get("code") != 1:
        return None, f"API error: {data.get('message', 'unknown')}"
    token = (data.get("result") or {}).get(address.lower())
    if not token:
        return None, ("No data for this address. It may not be a token, or it "
                      "is too new to be indexed yet.")
    return token, None


def pct(token, key):
    try:
        v = token.get(key)
        if v in (None, ""):
            return None
        f = float(v) * 100
        return round(f, 2) if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None


def top_holder_concentration(token):
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


def lp_holder_pct(token, want):
    holders = token.get("lp_holders") or []
    if not holders:
        return None
    total = 0.0
    for h in holders:
        try:
            v = float(h.get("percent", 0))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(v):
            continue
        addr = (h.get("address") or "").lower()
        tag = (h.get("tag") or "").lower()
        burned = addr in BURN_ADDRESSES or "burn" in tag or "null" in tag
        locked = str(h.get("is_locked")) == "1"
        if want == "burned" and burned:
            total += v * 100
        elif want == "locked" and locked and not burned:
            total += v * 100
        elif want == "secured" and (locked or burned):
            total += v * 100
    return round(total, 2)


def yesno(condition):
    if condition is None:
        return "unknown"
    return "yes" if condition else "no"


def assess_token(token):
    flags = []

    for rule in RULES:
        val = token.get(rule["key"])
        if val is None or val == "":
            continue
        if str(val) == rule["trigger"]:
            flags.append({"label": rule["label"], "sev": rule["sev"],
                          "points": SEVERITY_POINTS[rule["sev"]],
                          "category": rule["cat"]})

    secured = lp_holder_pct(token, "secured")
    burned = lp_holder_pct(token, "burned")
    locked = lp_holder_pct(token, "locked")
    if secured is not None and secured < 50:
        if secured <= 0:
            lp_label = ("Liquidity is not locked or burned, so the deployer "
                        "can pull the pool at any time")
        else:
            lp_label = (f"Only {secured}% of the liquidity is locked or burned, "
                        f"so the deployer can still pull most of it")
        flags.append({"label": lp_label, "sev": "high",
                      "points": SEVERITY_POINTS["high"], "category": CAT_LIQUIDITY})

    top10 = top_holder_concentration(token)
    if top10 >= 70:
        flags.append({
            "label": f"The top 10 wallets hold {top10}% of the supply "
                     f"(extreme concentration, likely insider or whale control)",
            "sev": "high", "points": SEVERITY_POINTS["high"],
            "category": CAT_TOKENOMICS})
    elif top10 >= 50:
        flags.append({
            "label": f"The top 10 wallets hold {top10}% of the supply "
                     f"(high concentration)",
            "sev": "medium", "points": SEVERITY_POINTS["medium"],
            "category": CAT_TOKENOMICS})

    creator = pct(token, "creator_percent")
    if creator is not None and creator >= 5:
        flags.append({
            "label": f"The creator wallet holds {creator}% of the supply",
            "sev": "medium", "points": SEVERITY_POINTS["medium"],
            "category": CAT_TOKENOMICS})

    owner = pct(token, "owner_percent")
    if owner is not None and owner >= 5:
        flags.append({
            "label": f"The owner wallet holds {owner}% of the supply",
            "sev": "medium", "points": SEVERITY_POINTS["medium"],
            "category": CAT_TOKENOMICS})

    for tkey, name in (("buy_tax", "buy"), ("sell_tax", "sell")):
        t = pct(token, tkey)
        if t is not None and t >= 20:
            flags.append({
                "label": f"Very high {name} tax of {t}%",
                "sev": "medium", "points": SEVERITY_POINTS["medium"],
                "category": CAT_TOKENOMICS})

    mint_revoked = token.get("is_mintable")
    freeze_revoked = token.get("transfer_pausable")
    status = [
        {"label": "Mint authority revoked",
         "value": yesno(None if mint_revoked in (None, "") else mint_revoked == "0")},
        {"label": "Freeze authority revoked",
         "value": yesno(None if freeze_revoked in (None, "") else freeze_revoked == "0")},
        {"label": "LP burned",
         "value": yesno(None if burned is None else burned >= 50)},
    ]

    return {
        "name": token.get("token_name") or "Unknown token",
        "symbol": token.get("token_symbol") or "?",
        "flags": flags,
        "status": status,
        "stats": {
            "holder_count": token.get("holder_count") or "n/a",
            "top10_percent": top10,
            "creator_percent": creator,
            "lp_secured_percent": secured,
        },
    }


CODE_PATTERNS = [
    {"name": "owner-gated upgrade switch",
     "regex": r"approveTo|upgradeTo|setImplementation|_upgradeTo",
     "sev": "high",
     "label": "An owner-gated upgrade switch lets the admin swap the live "
              "contract logic at any time"},

    {"name": "delegatecall proxy",
     "regex": r"delegatecall",
     "sev": "medium",
     "label": "A delegatecall proxy means the real logic can live in a "
              "hidden, swappable contract"},

    {"name": "mint",
     "regex": r"function\s+\w*[mM]int\w*\s*\(",
     "sev": "high",
     "label": "A mint function lets the team increase the token supply"},

    {"name": "blacklist",
     "regex": r"[bB]lacklist|_isBlacklisted|denylist|_isBot|setBots",
     "sev": "high",
     "label": "A blacklist lets the team block specific wallets from selling"},

    {"name": "adjustable fee",
     "regex": r"function\s+\w*[sS]et\w*(Fee|Fees|Tax|Taxes)\w*\s*\(",
     "sev": "medium",
     "label": "An adjustable fee or tax can be raised by the team to trap sellers"},

    {"name": "exclude from fee",
     "regex": r"excludeFromFee|excludeFromFees|isExcludedFromFee",
     "sev": "low",
     "label": "The team can exempt its own wallets from fees"},

    {"name": "pause trading",
     "regex": r"function\s+\w*[pP]ause\w*\s*\(",
     "sev": "medium",
     "label": "A pause function lets the team freeze all transfers and trading"},

    {"name": "trading switch",
     "regex": r"enableTrading|openTrading|setTrading|tradingActive|"
              r"setTradingEnabled",
     "sev": "medium",
     "label": "A trading on/off switch is controlled by the team"},

    {"name": "adjustable max",
     "regex": r"function\s+\w*[sS]etMax\w*\s*\(",
     "sev": "low",
     "label": "An adjustable max transaction or wallet limit can be set to "
              "block selling"},

    {"name": "selfdestruct",
     "regex": r"selfdestruct",
     "sev": "high",
     "label": "A self-destruct call can destroy the contract"},
]


def fetch_source(chain_id, address, follow_proxy=True):
    if not ETHERSCAN_API_KEY:
        return "", "no_key", ""
    params = urllib.parse.urlencode({
        "chainid": chain_id, "module": "contract",
        "action": "getsourcecode", "address": address,
        "apikey": ETHERSCAN_API_KEY,
    })
    url = f"{ETHERSCAN_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "RugGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return "", "error", "network or timeout error"
    if str(data.get("status")) != "1":
        reason = data.get("result")
        if not isinstance(reason, str):
            reason = data.get("message") or "unknown error"
        low = reason.lower()
        if "invalid" in low and "key" in low:
            return "", "bad_key", reason
        if "rate limit" in low or "max rate" in low or "max calls" in low:
            return "", "rate_limit", reason
        return "", "error", reason
    res = (data.get("result") or [{}])[0]
    src = res.get("SourceCode") or ""
    if not src.strip():
        return "", "not_verified", ""
    if (follow_proxy and str(res.get("Proxy")) == "1"
            and str(res.get("Implementation", "")).startswith("0x")):
        impl_src, _, _ = fetch_source(chain_id, res["Implementation"],
                                      follow_proxy=False)
        if impl_src:
            src = src + "\n\n// IMPLEMENTATION\n" + impl_src
    return src, "ok", ""


def analyze_source(source):
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
        flags.append({"label": pat["label"], "sev": pat["sev"],
                      "points": SEVERITY_POINTS[pat["sev"]],
                      "category": CAT_CODE, "line": line_no,
                      "evidence": snippet})
    return flags


def score_and_verdict(flags):
    points = sum(f["points"] for f in flags)
    score = min(points, 100)
    has_critical = any(f["sev"] == "critical" for f in flags)
    if has_critical:
        score = max(score, 85)
    if score >= 70:
        return score, "HIGH RISK", "Strong rug-pull signals. Treat as unsafe."
    if score >= 40:
        return score, "MEDIUM RISK", "Several warning signs. Investigate before trusting it."
    if score > 0:
        return score, "LOW RISK", "A few minor signs. Stay cautious."
    return score, "NO RED FLAGS", "No technical red flags were detected on the checks that ran."


def build_report(onchain, code_flags, code_status, code_detail=""):
    flags = list(onchain["flags"]) + list(code_flags)
    score, label, advice = score_and_verdict(flags)
    return {
        "name": onchain.get("name", "Unknown token"),
        "symbol": onchain.get("symbol", "?"),
        "score": score,
        "verdict": label,
        "advice": advice,
        "flags": flags,
        "status": onchain.get("status", []),
        "stats": onchain.get("stats", {}),
        "code_status": code_status,
        "code_detail": code_detail,
    }


DEMO_TOKEN = {
    "token_name": "Squid Game (offline demo sample)",
    "token_symbol": "SQUID",
    "is_open_source": "1", "is_proxy": "1", "is_mintable": "0",
    "is_honeypot": "1", "cannot_sell_all": "1", "cannot_buy": "0",
    "can_take_back_ownership": "1", "hidden_owner": "0",
    "owner_change_balance": "0", "selfdestruct": "0",
    "transfer_pausable": "1", "is_blacklisted": "0",
    "honeypot_with_same_creator": "0", "is_airdrop_scam": "0",
    "external_call": "0", "slippage_modifiable": "1",
    "trading_cooldown": "0", "anti_whale_modifiable": "0",
    "buy_tax": "0", "sell_tax": "0.99", "holder_count": "102154",
    "creator_percent": "0.12", "owner_percent": "0",
    "lp_holders": [{"is_locked": 0, "percent": "0.92",
                    "address": "0x0000000000000000000000000000000000001234"}],
    "holders": [
        {"percent": "0.41"}, {"percent": "0.19"}, {"percent": "0.07"},
        {"percent": "0.05"}, {"percent": "0.03"}, {"percent": "0.02"},
        {"percent": "0.02"}, {"percent": "0.01"}, {"percent": "0.01"},
        {"percent": "0.01"},
    ],
}

DEMO_SOURCE = """\
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


@app.route("/")
def index():
    return render_template("index.html", has_key=bool(ETHERSCAN_API_KEY))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    if data.get("demo"):
        onchain = assess_token(DEMO_TOKEN)
        return jsonify(build_report(onchain, analyze_source(DEMO_SOURCE), "demo"))

    address = (data.get("address") or "").strip()
    chain = (data.get("chain") or "ethereum").lower()
    if not address:
        return jsonify({"error": "Please enter a contract address."})
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
        return jsonify({"error": "That doesn't look like a valid contract "
                                 "address (it should be 0x followed by 40 "
                                 "characters)."})
    chain_id = CHAINS.get(chain)
    if not chain_id:
        return jsonify({"error": f"Unsupported chain '{chain}'. Use Ethereum "
                                 f"or BSC."})

    token, err = fetch_token(chain_id, address)
    if err:
        return jsonify({"error": err})
    onchain = assess_token(token)
    source, code_status, code_detail = fetch_source(chain_id, address)
    code_flags = analyze_source(source) if source else []
    return jsonify(build_report(onchain, code_flags, code_status, code_detail))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
