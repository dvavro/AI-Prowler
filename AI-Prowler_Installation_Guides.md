# AI-Prowler v7.0.0 — Installation Guides

Three complete installation paths. Follow only the guide that matches your situation.

---

## Guide A — Individual / Home Install

**Who this is for:** A single user installing AI-Prowler on their own Windows PC for personal use, with optional remote access from Claude.ai on their phone or browser.

---

### Part 1 — Run the Installer

**What you need:**
- Windows 11 (64-bit)
- Administrator access on the PC
- Internet connection (downloads Claude Desktop, Tesseract OCR, Cloudflare tunnel client)
- ~3 GB free disk space
- ~15 minutes

**Steps:**

1. Download `AI-Prowler_INSTALL.exe` from the GitHub Releases page.
2. Right-click the file → **Run as administrator**. Accept the UAC prompt.
3. Read and accept the license agreement.
4. The installer runs silently from there. A progress bar shows each phase:

   | Phase | What happens |
   |---|---|
   | 10 % | Python 3.11.8 installs to `%LocalAppData%\Programs\Python\Python311` |
   | 30 % | pip installs all AI-Prowler Python packages from `requirements.txt` |
   | 50 % | PyTorch installs — CUDA 12.8 build if NVIDIA GPU detected, CPU build otherwise |
   | 60 % | Tesseract OCR 5.4 downloads and installs (enables scanned PDF support) |
   | 70 % | Claude Desktop downloads and installs via MSIX |
   | 80 % | MCP configuration written to Claude Desktop automatically |
   | 90 % | Cloudflare tunnel client (`cloudflared.exe`) downloads and installs |
   | 95 % | Job Tracker spreadsheet deployed to `Documents\AI-Prowler\` |
   | 100 % | Windows Task Scheduler logon task created (AI-Prowler auto-starts at login) |

5. When the installer finishes, tick **Run AI-Prowler** and click **Finish**.

> **If anything fails:** The full install log is at `%LocalAppData%\Temp\AI-Prowler\install_log.txt`. Share it with support.

---

### Part 2 — First Launch

1. AI-Prowler opens automatically (or double-click the Desktop shortcut).
2. Claude Desktop also opens — **sign in to your Anthropic account**.
3. In Claude Desktop, start a new conversation and type:
   ```
   What AI-Prowler tools do you have available?
   ```
   Claude should list tools including `get_knowledge_base_overview` and `search_documents`. If it does, the local MCP connection is working.

---

### Part 3 — Index Your First Documents

1. In AI-Prowler, click the **Index Documents** tab.
2. Click **Add Directory** and select a folder of documents you want Claude to search.
3. Tick **Include Subfolders** if needed.
4. Click **Start Indexing**. Wait for the progress bar to complete.
5. Go back to Claude Desktop and ask a question about your documents.

> The Job Tracker spreadsheet is at `Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx` and is pre-configured automatically.

---

### Part 4 — Subscribe for Remote Access (Optional)

Skip this part if you only need Claude Desktop on this PC.

1. In AI-Prowler → **Settings** tab → **Remote Access** section.
2. Enter a **Bearer Token** — at least 10 characters, mixed case and numbers (e.g. `MyDog$Rufus2024`). This is your remote access password.
3. Click **Save Token**.
4. Email **david.vavro1@gmail.com** with your name and Bearer token to subscribe. Your subscription activates your token in the cloud registry.

---

### Part 5 — Set Up Remote Access (After Subscription Active) (This process is done by AI-Prowler technician pre done and
ready for your usage and with passwords and tunnel tokens sent via Email after subscription)

**Set up a Cloudflare tunnel** so Claude.ai on your phone can reach AI-Prowler on your PC.

**Prerequisites:**
- A free [Cloudflare account](https://dash.cloudflare.com)
- A domain name added to Cloudflare (e.g. `yourdomain.com`)

**One-time tunnel setup:**

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com) → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel**
2. Name it (e.g. `ai-prowler`), copy the **Tunnel token** shown on screen.
3. Add a **Public hostname**: e.g. `mobile.yourdomain.com`, service = `http://localhost:8000`.
4. In AI-Prowler → Settings → Remote Access → Named Tunnel section:
   - **Public hostname:** `mobile.yourdomain.com`
   - **Tunnel token:** paste the token from step 2
5. Click **Activate Tunnel Service** → AI-Prowler installs cloudflared as a Windows background service. The green dot appears: **Tunnel active (Windows service)**.
6. Click **▶ Start HTTP Server** → status shows **Running · Port 8000**.
7. Test in your browser: `https://mobile.yourdomain.com/health` → should return `OK`.

**Correct startup order:** HTTP server must be running before cloudflared connects to it. The Windows service handles this automatically after the first manual start.

---

### Part 6 — Connect Claude.ai on Your Phone or Browser

1. Open [claude.ai](https://claude.ai) → sign in (Claude Pro required).
2. Profile icon → **Settings** → **Connectors** → **Add custom connector**.
3. Enter your tunnel URL + `/mcp`: `https://mobile.yourdomain.com/mcp`
4. Claude.ai redirects to your AI-Prowler authorization page.
5. Enter your Bearer token → click **Connect**.
6. Start a new conversation in Claude.ai and ask a question about your documents.

---

### Part 7 — Machine Activation

Your Individual subscription activates on **1 machine at a time**.

1. In AI-Prowler → Settings → Mobile Activation → click **Check Activation**.
2. Status shows: *"This machine: allowed"* — you are active.

**If you replace your computer:** On the new machine after installing AI-Prowler and entering your Bearer token → Settings → Mobile Activation → **Check Activation** → **Transfer to This Machine**. The old machine is released and the new one activates in one step.

---

## Guide B — Business Server Install

**Who this is for:** The business owner installing AI-Prowler on a dedicated company server (or an always-on PC) that employees will connect to from Claude.ai on their phones and laptops.

---

### Part 1 — Prepare the Server Machine

**Requirements:**
- Windows 11 PC (always-on — server must be running for employees to connect)
- Administrator access
- Internet connection
- Static LAN IP recommended (or use DHCP reservation)
- 4 GB+ RAM, 10 GB+ free disk space
- A Business license — contact david.vavro1@gmail.com

**Recommended hardware:** A dedicated mini-PC (Intel NUC, Beelink, etc.) works well. The server does not need a GPU — embeddings run on CPU in server mode.

---

### Part 2 — Run the Installer

1. Download `AI-Prowler_INSTALL.exe` from the GitHub Releases page.
2. Right-click → **Run as administrator**.
3. Accept the license and let the installer complete (same phases as Guide A).
4. When finished, tick **Run AI-Prowler** and click **Finish**.

---

### Part 3 — Configure Business Server Mode

After AI-Prowler opens:

1. Open `C:\Users\YourName\.ai-prowler\config.json` in Notepad (create the folder if it doesn't exist — AI-Prowler creates it on first run).
2. Edit the file to set Business Server mode:

   ```json
   {
     "edition": "business",
     "mode": "server",
     "default_spreadsheet_path": "C:\\Users\\YourName\\Documents\\AI-Prowler\\AI-Prowler_Job_Tracker.xlsx"
   }
   ```

3. Save the file.
4. **Restart AI-Prowler** (close and reopen via the Desktop shortcut).
5. After restart, a **👥 Admin** tab appears as the last tab — this confirms server mode is active.

> The Tier A tool suppression is now active. When employees connect via Claude.ai, they will see 35 tools (not 58). Developer tools, host filesystem write tools, and email configuration tools are hidden from all users.

---

### Part 4 — Enter Your Parent License Key

1. In AI-Prowler → **Settings** tab → **Remote Access** section.
2. Enter your **Parent License Key** (from your Business subscription email) in the license key field.
3. Click **Save Key** → the Subscription dot turns green.

> The Parent License Key is NOT machine-locked. If the server machine is ever replaced, you simply enter the same key on the new server. No transfer step required.

---

### Part 5 — Set Up the Cloudflare Tunnel (Server) (This process is done by AI-Prowler technician pre done and
ready for your usage and with passwords and tunnel tokens sent via Email after subscription)

This is the same tunnel process as Guide A, but for the company server.

**Prerequisites:**
- A free [Cloudflare account](https://dash.cloudflare.com)
- A domain name added to Cloudflare (e.g. `yourcompany.com`)

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com) → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel**.
2. Name it (e.g. `ai-prowler-server`), copy the **Tunnel token**.
3. Add a **Public hostname**: e.g. `server.yourcompany.com`, service = `http://localhost:8000`.
4. In AI-Prowler → Settings → Remote Access → Named Tunnel section:
   - **Public hostname:** `server.yourcompany.com`
   - **Tunnel token:** paste the token
5. Click **Activate Tunnel Service** → green dot: **Tunnel active (Windows service)**.
6. Click **▶ Start HTTP Server** → **Running · Port 8000**.
7. Test: `https://server.yourcompany.com/health` → `OK`.

From this point forward the tunnel and HTTP server start automatically at Windows logon (via Task Scheduler). No manual steps needed after each reboot.

---

### Part 6 — Index Company Documents

1. In AI-Prowler → **Index Documents** tab.
2. Add the folders containing your company knowledge base — manuals, procedures, customer records, price lists, etc.
3. Start indexing. This is the shared knowledge base all employees will search.

> **Scopes:** You can assign folders to named scopes (e.g. `scope:office`, `scope:field`) to control which employees can see which documents. Scope assignment is done when indexing — see Guide B Part 8 below for the full roles and scopes setup.

---

### Part 7 — Enter the Admin Tab and Authenticate

1. Click the **👥 Admin** tab (last tab).
2. A bearer token prompt appears. Enter **your bearer token** (the owner's token — the one you saved in Part 4, or your own personal token from Settings → Remote Access).
3. The Admin tab unlocks showing the empty user table and seat summary.

> **Security:** Bearer tokens are always fully masked (●●●●●●●●) in the Admin tab. The table never shows any part of a token. The only time a full token is shown is in the **Show Token** dialog after generating one — and even then it is masked by default with a Reveal checkbox.

---

### Part 8 — Understand Roles and Scopes

**Four roles** control what each employee can do on the server:

| Role | Description | Tool access | Can manage users |
|---|---|---|---|
| **owner** | You — the business owner | All 35 server tools | ✅ Yes |
| **manager** | Senior employee, trusted admin | All 35 server tools | ✅ If granted |
| **staff** | Regular office employee | 25 tools — RAG + limited indexing of own scopes | ❌ No |
| **field_crew** | Field technician | 26 tools — RAG + send_email + send_alert | ❌ No |

**Scopes** are named data-access groups you define. Each scope maps to a dedicated slice of the knowledge base. Employees only see documents in their assigned scopes.

**Example — a window and pressure washing company:**

| Employee | Role | Scopes assigned | What they can search |
|---|---|---|---|
| David | owner | `scope:office, scope:field` | Everything |
| Maria (office manager) | manager | `scope:office` | Invoices, customer records, admin procedures |
| Jake (field tech) | field_crew | `scope:field` | Job sheets, equipment manuals, safety procedures |
| Sam (office staff) | staff | `scope:office` | Office documents, limited indexing of own scope |

**Scope naming:** Enter scopes as a comma-separated list: `scope:office, scope:field`. Use names that match how your business is organized. You define them — there is no preset list.

---

### Part 9 — Add Employees to the Server

For each employee:

1. In the Admin tab → click **➕ Add User**.
2. Fill in:
   - **Name** — employee's name
   - **Email** — optional contact
   - **Role** — choose from owner / manager / staff / field_crew
   - **Scopes** — e.g. `scope:office` or `scope:field, scope:shared`
   - **Can manage users** — tick only for managers you trust to add/remove users
   - **Private collection** — tick if this employee should have their own private knowledge slice
   - **License seat** — select from the dropdown (the child keys from your seat pool)
   - **Bearer token** — leave blank to auto-generate (recommended)
3. Click **Save**.
4. Click **🔑 Regenerate Token** on the new user row to see their token (masked — click **👁 Reveal token** to see the full value).
5. Send the employee their token **securely** (not plain email — use a password manager share, Signal, or another secure channel).

---

### Part 10 — Give Each Employee Their Connection Details

Send each employee:

1. **Their bearer token** (from the Show Token dialog — send securely)
2. **The company connector URL:** `https://server.yourcompany.com/mcp`
3. Link to **Guide C** (Employee Individual Install instructions) if they want a personal install too

The employee adds the connector URL in Claude.ai → Settings → Connectors → Add custom connector, authenticates with their bearer token, and starts a new conversation. No software install required on their device.

---

### Part 11 — Ongoing Management

| Task | How |
|---|---|
| Add new employee | Admin tab → ➕ Add User |
| Suspend access (e.g. employee leaves) | Admin tab → select user → 🚫 Suspend |
| Reset a compromised token | Admin tab → select user → 🔑 Regenerate Token (old token stops working immediately) |
| Remove user permanently | Admin tab → select user → 🗑 Remove (frees their seat) |
| Add more documents | Index Documents tab → index new folders (assign to appropriate scopes) |
| Check database state | Settings → Database → **View Statistics** |
| Clean orphaned server collections | Settings → Database → **Clear Database only** |

---

### Part 12 — Replacing the Server Machine

If the server PC fails and must be replaced:

1. Install AI-Prowler on the new machine (Guide B Part 1–2).
2. Edit `~/.ai-prowler/config.json` to set `edition=business`, `mode=server` (Guide B Part 3).
3. Enter the same **Parent License Key** (Guide B Part 4).
4. Reconfigure the Cloudflare tunnel on the new machine using the **same tunnel token** from Cloudflare Zero Trust dashboard (Guide B Part 5).
5. Copy `~/.ai-prowler/users.json` and `seats.json` from the old machine if recoverable — or re-add users manually via the Admin tab.
6. Re-index company documents (Guide B Part 6).

**All employees' Claude.ai connectors continue working without any changes on their side** — the URL doesn't change, only the machine behind it changes.

> No transfer step is needed for the Parent License Key. It has no machine lock — it validates your subscription status only.

---

## Guide C — Business Employee Individual Install

**Who this is for:** An employee who has been given a **child seat key** and **bearer token** by the business owner, and wants to install AI-Prowler on their own laptop for personal use. This install is separate from the company server — it gives the employee their own private knowledge base plus their own Claude.ai remote access.

This is optional. Employees can use the company server from Claude.ai without any local install.

---

### Part 1 — What You Will Have After This Guide

After completing this guide you will have **two separate Claude.ai connectors**:

| Connector | URL | What it searches |
|---|---|---|
| Company server | `https://server.yourcompany.com/mcp` | Shared company knowledge base (scoped to your role) |
| Your personal install | `https://mobile.yourdomain.com/mcp` | Your own private documents on your laptop |

Each uses a different bearer token and a different Cloudflare tunnel. They are completely independent — nothing on your personal install affects the company server.

---

### Part 2 — What You Need Before Starting

From your employer:
- ✅ Your **child seat key** (looks like `XXXX-YYYY-ZZZZ-WWWW`)
- ✅ Your **bearer token** for the company server connector (for connecting Claude.ai to the company server — this is separate from your personal install's token)
- ✅ The **company server connector URL** (e.g. `https://server.yourcompany.com/mcp`)

For your personal install:
- ✅ Windows 10 or Windows 11 PC
- ✅ Administrator access on the PC
- ✅ Internet connection
- ✅ ~3 GB free disk space
- ✅ A Cloudflare account and a domain name (if you want Claude.ai remote access to your personal install — optional)

---

### Part 3 — Run the Installer

1. Download `AI-Prowler_INSTALL.exe` from the GitHub Releases page.
2. Right-click → **Run as administrator**.
3. Accept the license and let the installer complete (same phases as Guide A — Python, packages, Claude Desktop, Tesseract, cloudflared, Job Tracker).
4. When finished, tick **Run AI-Prowler** and click **Finish**.

The installer sets up AI-Prowler in **personal mode** by default. Do **not** edit `config.json` to set server mode — your personal install should stay in personal mode. You get the full 58-tool individual tool set.

---

### Part 4 — Set Your Personal Bearer Token

This token is for **your personal install's** remote access — it is different from the bearer token you use to connect to the company server.

1. In AI-Prowler → **Settings** → **Remote Access** section.
2. Enter a **Bearer Token** for this install — at least 10 characters, mixed case and numbers (e.g. `Jake$Personal2024`).
3. Click **Save Token**.

---

### Part 5 — Enter Your Child Seat Key

1. Still in Settings → Remote Access, find the **License Key** field.
2. Enter your **child seat key** provided by your employer.
3. Click **Save Key** → the Subscription dot turns green.

---

### Part 6 — Index Your Personal Documents

1. Click the **Index Documents** tab.
2. Add folders containing your own working documents — project notes, reference materials, anything you want Claude to search on your behalf.
3. Click **Start Indexing**.

These documents are **private to you** — they are only indexed on your machine and are never visible to anyone on the company server.

---

### Part 7 — Connect Claude Desktop to Your Personal Install

Claude Desktop was installed automatically. Verify it is connected:

1. Open Claude Desktop → start a new conversation.
2. Type: `What AI-Prowler tools do you have available?`
3. Claude should list tools including `get_knowledge_base_overview`. If so, the local connection is working.

---

### Part 8 — Set Up Remote Access for Your Personal Install (Optional)

If you want to access your personal knowledge base from Claude.ai on your phone or other devices, set up a personal Cloudflare tunnel.

**Prerequisites:**
- A free [Cloudflare account](https://dash.cloudflare.com)
- A domain name added to Cloudflare (can be the same domain as the company uses, with a different subdomain — e.g. `jake.yourcompany.com` — ask your employer)

1. Log in to Cloudflare → **Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel**.
2. Name it (e.g. `jake-personal`), copy the **Tunnel token**.
3. Add a **Public hostname**: e.g. `jake.yourcompany.com`, service = `http://localhost:8000`.
4. In AI-Prowler → Settings → Named Tunnel:
   - **Public hostname:** `jake.yourcompany.com`
   - **Tunnel token:** paste the token
5. Click **Activate Tunnel Service** → green dot appears.
6. Click **▶ Start HTTP Server** → Running.
7. Test: `https://jake.yourcompany.com/health` → `OK`.

---

### Part 9 — Connect Claude.ai to Both Servers

You will add **two connectors** in Claude.ai — one for the company server and one for your personal install.

**Add the company server connector:**

1. Open [claude.ai](https://claude.ai) → Profile → Settings → Connectors → **Add custom connector**.
2. URL: `https://server.yourcompany.com/mcp`
3. Authenticate with the **company bearer token** your employer gave you.
4. Name it something like "Company AI-Prowler".

**Add your personal install connector (if you set up a tunnel in Part 8):**

1. Connectors → **Add custom connector**.
2. URL: `https://jake.yourcompany.com/mcp`
3. Authenticate with **your personal bearer token** (the one you set in Part 4).
4. Name it something like "My AI-Prowler".

In Claude.ai conversations you can now choose which connector to use — or use both together. Claude will search the relevant knowledge base based on which connector is active.

---

### Part 10 — Machine Activation for Your Personal Install

Your child seat gives you **1 machine activation** for your personal install.

1. In AI-Prowler → Settings → Mobile Activation → click **Check Activation**.
2. Status shows: *"This machine: allowed"* → you are active.

**If you replace your laptop:** On the new machine after installing AI-Prowler and entering your child seat key and personal bearer token → Settings → Mobile Activation → **Check Activation** → **Transfer to This Machine**. The old laptop is released and the new one activates in one step.

---

## Quick Reference — What Each Guide Covers

| Step | Guide A (Individual) | Guide B (Business Server) | Guide C (Employee) |
|---|---|---|---|
| Run installer | ✅ | ✅ | ✅ |
| Set bearer token | ✅ Personal token | ✅ Owner token | ✅ Personal token |
| Enter license key | ✅ Individual key | ✅ Parent key | ✅ Child seat key |
| Edit config.json for server mode | ❌ | ✅ Required | ❌ Stay personal mode |
| Index documents | ✅ Personal docs | ✅ Company shared docs | ✅ Private docs |
| Set up Cloudflare tunnel | ✅ Personal tunnel | ✅ Company tunnel | ✅ Personal tunnel (optional) |
| Admin tab / Add users | ❌ | ✅ Required | ❌ |
| Connect Claude Desktop | ✅ | ❌ Server has no local desktop use | ✅ |
| Connect Claude.ai | ✅ 1 connector | ✅ For all employees | ✅ 2 connectors (company + personal) |
| Machine activation | ✅ 1 machine | ❌ No lock | ✅ 1 machine |
| Transfer to new machine | ✅ Self-service | ❌ Just reinstall | ✅ Self-service |

---

## Troubleshooting — Common Issues Across All Installs

### Claude Desktop can't see AI-Prowler tools
1. AI-Prowler → Settings → Claude Desktop MCP → **Write MCP Config**
2. Restart Claude Desktop completely (quit from system tray)
3. Start a **new conversation** (existing conversations don't pick up reconnected tools)

### Cloudflare Error 1033 (tunnel can't reach the server)
Most common cause: cloudflared started before the HTTP server.
1. Open a browser on the PC and go to `http://localhost:8000/health` → should return `OK`
2. If `OK`: click **Stop Tunnel** in AI-Prowler → **Uninstall Service** → **Activate Tunnel Service** (reinstalls cloudflared pointing to the now-running HTTP server)
3. If not `OK`: click **▶ Start HTTP Server** first, then start the tunnel

### Cloudflare tunnel credentials lost (cert.pem / ai-prowler.json missing)
Run in a command prompt on the server machine:
```
cloudflared tunnel login
cloudflared tunnel token --cred-file "C:\Users\YourName\.cloudflared\ai-prowler.json" ai-prowler
```
Then in AI-Prowler: Stop Tunnel → Uninstall Service → Activate Tunnel Service.

### Claude.ai connector says "Couldn't register with sign-in service"
The tunnel is not reachable. Check:
1. Is the HTTP server running? (green dot in Settings)
2. Is the tunnel active? (green dot — Tunnel active Windows service)
3. Test `https://your-tunnel-url/health` in a browser — should return `OK`
4. If `OK` but connector still fails: remove the connector in Claude.ai completely, wait 30 seconds, re-add it

### Employee gets "Unauthorized" when connecting to company server
- Their bearer token may have been regenerated. Ask the server admin to check the Admin tab and share the current token via **🔑 Regenerate Token** → Show Token → Reveal.

### Database shows scoped collections on a personal install (dirty database)
This happens if the machine was previously in server mode. In AI-Prowler → Settings → Database → **Clear Database only** → removes all scoped collections while keeping your tracked-directories list and learnings.

---

*AI-Prowler v7.0.0 Installation Guides*
*For support: david.vavro1@gmail.com*
