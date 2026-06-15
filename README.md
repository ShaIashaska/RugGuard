# RugGuard — Web3 Rug Pull Detector

A working implementation of the detection framework (Section 4.5) from the thesis
**"The Psychology of Rug Pulls in Web3: A Socio-Technical Analysis."**

**You paste one token contract address.** RugGuard then:

1. Pulls live on-chain data and checks the **contract controls**, the
   **liquidity pool lock**, and the **holders / tokenomics**.
2. Automatically fetches the contract's **source code** and scans it for
   dangerous patterns (the SQUID `approveTo`/`ifSir` upgrade gate, the
   `delegatecall` proxy, mint, blacklist, and more). If the contract is a proxy,
   it also fetches and scans the hidden implementation contract.
3. Combines everything into **one risk score**, with every red flag pointing
   back to a section of the thesis.

Chains supported: **BNB Smart Chain (BSC)** and **Ethereum**.

Data sources (both free): the **GoPlus Token Security API** (no key) and the
**Etherscan V2 API** (one free key — see below).

---

## What you need

- **Python 3** (3.9 or newer). Check with `python3 --version`.
  Download from https://www.python.org/downloads/ (on Windows, tick
  **"Add Python to PATH"** during install).
- A **free Etherscan API key** (optional but recommended — it turns on the
  automatic code analysis). Steps are below.

---

## Step 1 — Get a free Etherscan API key (2 minutes)

This one key works for **both** BSC and Ethereum (Etherscan API V2).

1. Go to https://etherscan.io/register and create a free account.
2. Log in, then open **https://etherscan.io/myapikey** (or menu → API Keys).
3. Click **Add** / **Create New API Key**. Copy the key (a long string).

### Put the key into the app (pick ONE way)

**Easy way — paste it into the code:**
Open `app.py`, find this line near the top:

```python
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
```

Put your key inside the **second** pair of quotes, like:

```python
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "YOUR_KEY_HERE")
```

**Or — set it as an environment variable** (more secure, key not in the code):
- Windows: `set ETHERSCAN_API_KEY=YOUR_KEY_HERE`
- Mac/Linux: `export ETHERSCAN_API_KEY=YOUR_KEY_HERE`

If you skip this step, the app still runs — it just won't analyze the code
automatically (the on-chain checks all still work).

---

## Step 2 — Run it on your computer (5 minutes)

1. **Open a terminal** in this project folder (the one with `app.py`).
   - Windows: type `cmd` in the folder's address bar, press Enter.
   - Mac: right-click the folder → "New Terminal at Folder".

2. **Install the dependencies** (one time):
   ```
   pip install -r requirements.txt
   ```
   (If `pip` isn't found, try `pip3` or `python3 -m pip`.)

3. **Start the program:**
   ```
   python app.py
   ```
   (If `python` isn't found, use `python3 app.py`.)

4. **Open your browser** to:
   ```
   http://127.0.0.1:5000
   ```

5. Paste a contract address, choose the chain, and click **Check this token**.
   Or click **"try the SQUID example"** for an instant offline demo.

To stop the program, press **Ctrl + C** in the terminal.

### Test addresses
- SQUID (from the thesis), BNB Smart Chain:
  `0x87230146E138d3F296a9a77e497A2A83012e9Bc5`
- A safe token for contrast (PancakeSwap CAKE), BNB Smart Chain:
  `0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82`

Note: GoPlus computes some checks (like honeypot) from *current* trading, so a
**live** scan of the long-dead SQUID token may show fewer flags than the
**offline demo**, which has the full documented SQUID case baked in.

---

## Step 3 — Put it online to share a link (free)

Uses **Render.com** (free tier) to get a public web address for your panel.

1. Upload this whole folder to a free **GitHub** repo
   (https://github.com): `app.py`, `requirements.txt`, `Procfile`, and the
   `templates` folder.
2. Create a free account at https://render.com (log in with GitHub).
3. **New +** → **Web Service** → pick your repository.
4. Set:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
   - **Instance Type:** Free
5. (Recommended) Under **Environment**, add a variable:
   - Key: `ETHERSCAN_API_KEY`  Value: your key
6. **Create Web Service.** After a minute or two you get a link like
   `https://rugguard.onrender.com` — that's what you send.

Note: on the free tier the site sleeps after inactivity, so the first visit may
take ~30 seconds to wake up. That's normal.

---

## How it maps to the thesis (for your defense)

| What the tool flags                          | Where it comes from        |
|----------------------------------------------|----------------------------|
| Honeypot / cannot sell                       | Sec 4.1 — Squid Game Token |
| Proxy / `approveTo` upgrade gate             | Sec 4.1.1 — SQUID          |
| `delegatecall` proxy obfuscation             | Sec 4.1.1 & 4.2            |
| Unlocked liquidity pool                       | Sec 4.2 — AnubisDAO        |
| Top-holder / creator concentration           | Sec 4.4 — insider risk     |
| Unverified contract, no audit                 | Sec 4.5 — red flags        |
| Reminder: social layer not measured          | Sec 4.4                    |

**Validation:** the SQUID example returns HIGH RISK (100/100) and the code scan
flags the exact `approveTo`/`delegatecall` functions documented in the thesis.

**Honest scope (say this in your defense):** RugGuard is a screening tool, not a
certified audit, and it measures the *technical* layer. As the thesis argues
(Sec 4.4), the strongest frauds rely on the *social* layer — hype, fake
partnerships, trusted names, urgency — which an on-chain tool cannot fully
capture. That limitation is itself one of your findings.

---

## Files

- `app.py` — backend (Flask): on-chain checks, code fetch + analysis, scoring.
- `templates/index.html` — the web interface.
- `requirements.txt` — Python packages.
- `Procfile` — start command for deployment.
