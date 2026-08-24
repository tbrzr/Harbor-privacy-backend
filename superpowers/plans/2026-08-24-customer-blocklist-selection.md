# Customer Blocklist Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Harbor Privacy customers pick which blocklists apply to their own account (main client + all Harbor Kids sub-profiles), with attribution links, reusing the already-shipped `adguard-private` tier feature via auto-hash-named tiers for cross-customer dedup.

**Architecture:** Two sub-projects. (A) Deploy the unmodified, already-tested per-client-tier feature from `adguard-private`'s `bab` branch to the customer-facing AGH instance (`/opt/AdGuardHome`, `AdGuardHome.service`). (B) New `dashboard.py` code: hash-named tier find-or-create under a lock, fan-out of `filter_tier` to the customer's main client and kid profiles, a `selected_filter_ids` field on the customer's `CUSTOMERS_LOG` record as ground truth, a hand-maintained `BLOCKLIST_SOURCES` attribution dict, a new `/dashboard/blocklists` page and `/api/blocklists` route, and a nav link.

**Tech Stack:** Python 3 / Flask (`dashboard.py`, no gunicorn, single-process `app.run()`), `harbor_lib.agh` (`agh_get`/`agh_post`/`get_client`), Jinja `render_template_string`, AGH REST API (`/control/filtering/tiers`, `/control/filtering/status`, `/control/clients/update`).

**Spec:** `/home/ubuntu/harbor-backend/superpowers/specs/2026-08-24-customer-blocklist-selection-design.md`

## Global Constraints

- Never modify `harbor_kids` or `plan_type` logic (CLAUDE.md hard rule). New code only *reads* `customer.get("plan_type", "")` / `customer.get("harbor_kids", False)`, never writes them.
- No em dashes anywhere in code, comments, or output strings.
- HTML lives as inline template strings in `.py` files - never separate `.html` templates.
- No structural/CSS changes to nav, sidebar, or layout beyond the one new link explicitly called for.
- No automated test suite exists in this repo - verification is manual: curl against the running service, `GET /control/filtering/tiers` / `GET /control/clients` against AGH, `dig` for actual DNS enforcement.
- Pre-restart safety gate: use `/home/ubuntu/harbor-backend/check-dashboard.sh` (curls 6 known-good routes; only restarts `harbor-dashboard.service` itself if all pass), never a bare `sudo systemctl restart harbor-dashboard` as the first move after an edit.
- Sub-project A targets customer-facing production (`/opt/AdGuardHome`) - gets its own explicit go-ahead before executing, separate from approving this plan.

---

### Task 1: Deploy the tier feature to customer-facing AGH (Sub-project A)

**Files:**
- No source changes. Binary deploy only: `/opt/AdGuardHome/AdGuardHome` (target), `/opt/AdGuardHome/AdGuardHome.yaml` (untouched - tiers need no schema change), source binary built earlier this session from `adguard-private`'s `bab` branch.

**Interfaces:**
- Consumes: nothing from this plan's later tasks.
- Produces: `GET /control/filtering/tiers`, `POST /control/filtering/set_tiers`, and `client.filter_tier` become live on the customer-facing AGH instance (`http://127.0.0.1:8080`, same instance `dashboard.py`'s `ADGUARD_URL` already points at by default). Task 2 depends on this being live before its manual verification step can succeed against the real instance (Task 2's unit-level code has no runtime dependency on A, but nothing in Tasks 2-5 can be *verified end to end* until A is done).

**GATE: do not run this task until the user has given explicit, separate go-ahead for touching `/opt/AdGuardHome` / `AdGuardHome.service` - this is customer-facing production.**

- [ ] **Step 1: Confirm the already-built binary and its checksum**

```bash
sha256sum /opt/AdGuardHome-bab/AdGuardHome 2>/dev/null || sha256sum /home/timbrazer/AdGuardHome/AdGuardHome
```

Expected: `e0c8402ca70d0a40b267c8df8bb24d61a54f81b85bfa164ed9db5da329ba0af6` (the binary already deployed to the Pi and vm3's `bab.service` earlier this session). If this doesn't match on this box, `scp` it from the Pi first:

```bash
scp timbrazer@<pi-host>:/home/timbrazer/AdGuardHome/AdGuardHome /home/ubuntu/AdGuardHome-bab-verified
sha256sum /home/ubuntu/AdGuardHome-bab-verified
```

Expected: same hash as above.

- [ ] **Step 2: Back up the current customer-facing binary and config**

```bash
sudo cp /opt/AdGuardHome/AdGuardHome /opt/AdGuardHome/AdGuardHome.pre-tiers.bak
sudo cp /opt/AdGuardHome/AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml.pre-tiers.bak
sha256sum /opt/AdGuardHome/AdGuardHome.pre-tiers.bak
```

Expected: prints a hash - confirms the backup file exists and is non-empty.

- [ ] **Step 3: Stop the service, swap the binary, verify the checksum, restart**

```bash
sudo systemctl stop AdGuardHome.service
sudo cp /home/ubuntu/AdGuardHome-bab-verified /opt/AdGuardHome/AdGuardHome
sudo chmod +x /opt/AdGuardHome/AdGuardHome
sha256sum /opt/AdGuardHome/AdGuardHome
sudo systemctl start AdGuardHome.service
sleep 2
sudo systemctl is-active AdGuardHome.service
```

Expected: the `sha256sum` line matches `e0c8402ca70d0a40b267c8df8bb24d61a54f81b85bfa164ed9db5da329ba0af6` (or whatever Step 1 confirmed), and `is-active` prints `active`.

- [ ] **Step 4: Verify the tiers API is live and existing clients are untouched**

```bash
curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/filtering/tiers
curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/clients | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('clients',[])), 'clients')"
```

Expected: first command prints `[]` (empty tier array - this AGH instance has never had tiers set). Second command prints the same client count as before the swap (confirms no client data was lost or altered by the binary swap).

- [ ] **Step 5: Spot-check DNS resolution still works for a real client**

```bash
dig @127.0.0.1 -p 53 doubleclick.net
```

Expected: an answer is returned (blocked or not, per whatever the global filter state already is) - confirms the resolver itself is healthy post-swap, not just the admin API.

No commit for this task (binary deploy, no source change in this repo).

---

### Task 2: Hash-naming, lock, fan-out, and storage helpers in `dashboard.py`

**Files:**
- Modify: `dashboard.py` - add `import hashlib` and `import threading` near the existing `import os, json, secrets, logging, re` (line 47); add new functions immediately before `@app.route("/api/admin/addon", methods=["POST"])` (the line directly after `update_customer_harbor_kids_flag`'s closing, currently at dashboard.py:4964 - verify with the grep in Step 1 before editing, since line numbers drift).

**Interfaces:**
- Consumes: `agh_get`, `agh_post`, `get_client` (already imported from `harbor_lib.agh` at dashboard.py:321-330), `CUSTOMERS_LOG` (dashboard.py:165), `log` (dashboard.py:69), `json` (dashboard.py:47).
- Produces (used by Task 3): `_tier_hash_name(filter_ids: list[int]) -> str`, `apply_customer_blocklist_selection(client_id: str, filter_ids: list[int]) -> bool`, `save_selected_filter_ids(client_id: str, filter_ids: list[int]) -> None`, module-level `BLOCKLIST_SOURCES: dict[str, str]` (keyed by AGH filter URL).

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'def update_customer_harbor_kids_flag\|@app.route("/api/admin/addon"' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: two line numbers, `update_customer_harbor_kids_flag`'s `def` line followed a few lines later by the `/api/admin/addon` route decorator. The new code goes between the end of that function's body and that decorator.

- [ ] **Step 2: Add the new imports**

Find this exact line near the top of the file:

```python
import os, json, secrets, logging, re
```

Replace it with:

```python
import os, json, secrets, logging, re, hashlib, threading
```

- [ ] **Step 3: Add the helper functions**

Insert this block immediately before `@app.route("/api/admin/addon", methods=["POST"])` (right after `update_customer_harbor_kids_flag`'s closing `log.error(...)` line):

```python
_TIER_LOCK = threading.Lock()

BLOCKLIST_SOURCES = {
    # AGH filter URL -> link to the list's own maintainer/source page.
    # Add one entry here each time a new list is added to the AGH catalog.
}

def _tier_hash_name(filter_ids):
    key = ",".join(str(i) for i in sorted(filter_ids))
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"cust-{digest}"

def apply_customer_blocklist_selection(client_id, filter_ids):
    filter_ids = sorted(set(filter_ids))
    hash_name = _tier_hash_name(filter_ids) if filter_ids else ""
    with _TIER_LOCK:
        if hash_name:
            tiers = agh_get("/control/filtering/tiers") or []
            if not any(t.get("name") == hash_name for t in tiers):
                tiers.append({"name": hash_name, "filter_ids": filter_ids})
                if not agh_post("/control/filtering/set_tiers", tiers):
                    log.error(f"apply_customer_blocklist_selection: set_tiers failed for {client_id}")
                    return False
        targets = [client_id] + [k["name"] for k in get_kids_profiles(client_id)]
        all_ok = True
        for target_id in targets:
            client = get_client(target_id)
            if not client:
                all_ok = False
                continue
            updated = {**client, "filter_tier": hash_name}
            ok = agh_post("/control/clients/update", {"name": client.get("name", target_id), "data": updated})
            if not ok:
                log.error(f"apply_customer_blocklist_selection: client update failed for {target_id}")
            all_ok = all_ok and ok
        return all_ok

def save_selected_filter_ids(client_id, filter_ids):
    lines = []
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    if r.get("client_id") == client_id:
                        r["selected_filter_ids"] = filter_ids
                    lines.append(json.dumps(r))
                except Exception:
                    lines.append(line)
        with open(CUSTOMERS_LOG, "w") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        log.error(f"save_selected_filter_ids error: {e}")

```

Note: `apply_customer_blocklist_selection` calls `get_kids_profiles(client_id)`, which is defined a few lines above it in the same file and returns AGH client dicts with a `"name"` key (not `"client_id"`) - using `k["name"]` for fan-out targets is correct because `get_client(target_id)` matches by `client_id in c.get("ids", [])`, and a kid profile's own `name` is also its own `id`.

- [ ] **Step 4: Syntax-check the file**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output, exit code 0.

- [ ] **Step 5: Manual verification against the live customer-facing AGH instance (requires Task 1 done)**

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, "/home/ubuntu/harbor-backend")
from dashboard import _tier_hash_name, apply_customer_blocklist_selection
import os
print(_tier_hash_name([3, 1, 2]))
print(_tier_hash_name([1, 2, 3]))
assert _tier_hash_name([3, 1, 2]) == _tier_hash_name([1, 2, 3])
TEST_CLIENT = os.environ.get("HARBOR_TEST_CLIENT_ID", "")
if TEST_CLIENT:
    ok = apply_customer_blocklist_selection(TEST_CLIENT, [1, 2])
    print("apply result:", ok)
EOF
```

Expected: both hash prints are identical (order-independence confirmed). If `HARBOR_TEST_CLIENT_ID` is set to a real disposable test client's id, `apply result: True` and a subsequent `curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/filtering/tiers` shows exactly one new `cust-...` tier containing `filter_ids: [1, 2]`. Do not run the `apply_customer_blocklist_selection` call against a real paying customer's `client_id` - use a disposable test client or skip this half of Step 5 until a test client exists (Task 5 covers full account-level verification).

- [ ] **Step 6: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add hash-named tier find-or-create and fan-out helpers for customer blocklist selection"
```

---

### Task 3: `POST /api/blocklists` route

**Files:**
- Modify: `dashboard.py` - add a new route immediately after `/api/addon`'s closing `return jsonify({"ok": False})` and before `@app.route("/api/admin/delete-customer", methods=["POST"])`.

**Interfaces:**
- Consumes: `find_customer` (dashboard.py:224, from `harbor_lib.data`), `login_required` (dashboard.py:394), `apply_customer_blocklist_selection` and `save_selected_filter_ids` (Task 2).
- Produces: `POST /api/blocklists` - Task 4's page posts to this. Request body: `{"filter_ids": [int, ...]}`. Response: `{"ok": bool}`.

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if data.get("type") == "harbor_kids_remove"\|@app.route("/api/admin/delete-customer"' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: the `harbor_kids_remove` block, then a `return jsonify({"ok": False})` a few lines later (the end of `api_addon`), then the `/api/admin/delete-customer` decorator.

- [ ] **Step 2: Add the route**

Insert this block immediately before `@app.route("/api/admin/delete-customer", methods=["POST"])`:

```python
@app.route("/api/blocklists", methods=["POST"])
@login_required
def api_blocklists():
    if request.is_admin and not request.args.get("preview"):
        return jsonify({"ok": False, "error": "Use admin endpoint"})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False, "error": "No active subscription"})
    client_id = customer.get("client_id", "")
    if not client_id:
        return jsonify({"ok": False, "error": "No AdBlock client on this account"})
    data = request.json or {}
    filter_ids = data.get("filter_ids", [])
    if not isinstance(filter_ids, list) or not all(isinstance(i, int) for i in filter_ids):
        return jsonify({"ok": False, "error": "filter_ids must be a list of integers"})
    save_selected_filter_ids(client_id, filter_ids)
    ok = apply_customer_blocklist_selection(client_id, filter_ids)
    return jsonify({"ok": ok})

```

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output, exit code 0.

- [ ] **Step 4: Manual verification (requires Task 1 done, dashboard restarted per Task 5's restart step, or run standalone)**

Since restarting the live dashboard mid-plan isn't warranted until the feature is complete, verify the route function directly without going through Flask's dev server yet:

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py && echo "OK: route added and file still compiles"
grep -n 'def api_blocklists' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: `OK: route added and file still compiles`, and the grep shows the new function. Full HTTP-level verification of this route happens in Task 5 after the real restart.

- [ ] **Step 5: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add POST /api/blocklists route for customer blocklist selection"
```

---

### Task 4: `/dashboard/blocklists` page and nav link

**Files:**
- Modify: `dashboard.py` - add the nav link inside `NAV_CUSTOMER`'s `.nav-drop-menu`, and add a new route as a new "SECTION 25" block right before `if __name__ == "__main__":` at the end of the file (mirroring how Sections 23/24 were appended).

**Interfaces:**
- Consumes: `STYLE`, `NAV_CUSTOMER` (module-level globals), `find_customer`, `get_client`, `has_family_addon`, `login_required`, `agh_get` (all already imported/defined earlier in the file), `BLOCKLIST_SOURCES` (Task 2).
- Produces: `GET /dashboard/blocklists` - a customer-facing page. No later task depends on this.

- [ ] **Step 1: Add the nav link**

Find this exact line in `NAV_CUSTOMER`:

```python
          <a href="/dashboard/adblock" class="{{ 'active' if active == 'adblock' else '' }}">AdBlock Usage</a>
```

Replace it with:

```python
          <a href="/dashboard/adblock" class="{{ 'active' if active == 'adblock' else '' }}">AdBlock Usage</a>
          <a href="/dashboard/blocklists" class="{{ 'active' if active == 'blocklists' else '' }}">Blocklists</a>
```

- [ ] **Step 2: Confirm the end-of-file insertion anchor**

```bash
tail -5 /home/ubuntu/harbor-backend/dashboard.py
```

Expected: the last non-blank lines are `if __name__ == "__main__":` followed by the `app.run(...)` line.

- [ ] **Step 3: Add the new route**

Insert this block immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 25 - CUSTOMER BLOCKLIST SELECTION
# Owns: /dashboard/blocklists page. API lives in /api/blocklists
# (see api_blocklists near /api/addon).
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/blocklists")
@login_required
def dashboard_blocklists():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""

    is_trial = customer.get("is_trial", False) if customer else False
    plan_type = customer.get("plan_type", "") if customer else ""
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    has_family_badge = has_family_addon(client_id) if client_id else False
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif customer and not is_trial: plan_badge = "MONTHLY"

    status = agh_get("/control/filtering/status") or {}
    all_filters = status.get("filters", [])
    selected = set((customer or {}).get("selected_filter_ids", []))
    filters = [
        {
            "id": f.get("id"),
            "name": f.get("name", ""),
            "url": f.get("url", ""),
            "rules_count": f.get("rules_count", 0),
            "source_link": BLOCKLIST_SOURCES.get(f.get("url", "")),
            "checked": f.get("id") in selected,
        }
        for f in all_filters
    ]

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap-sm">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">AdBlock</p>
  <h1 style="margin-bottom:8px;">Choose your blocklists.</h1>
  <p class="note" style="margin-bottom:24px;">Applies to your AdBlock client and every Harbor Kids profile on this account.</p>
  {% if not client_id %}
  <p class="note">No AdBlock client found on your account.</p>
  {% else %}
  <div id="save-error" class="note" style="display:none;color:#a64a40;margin-bottom:12px;">Save failed. Please try again.</div>
  <div class="card">
    {% for f in filters %}
    <div class="row" style="align-items:flex-start;">
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
        <input type="checkbox" class="blocklist-check" value="{{ f.id }}" {% if f.checked %}checked{% endif %} style="margin-top:3px;">
        <span>
          <span style="display:block;">{{ f.name }}</span>
          <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">{{ f.rules_count }} rules{% if f.source_link %} &middot; <a href="{{ f.source_link }}" target="_blank" style="color:var(--accent);">source &rarr;</a>{% endif %}</span>
        </span>
      </label>
    </div>
    {% endfor %}
    {% if not filters %}
    <p class="note">No blocklists available yet.</p>
    {% endif %}
  </div>
  <button id="save-blocklists" class="btn" style="margin-top:16px;">Save selection</button>
  {% endif %}
  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>
<script>
document.getElementById('save-blocklists')?.addEventListener('click', function() {
  var ids = Array.from(document.querySelectorAll('.blocklist-check:checked')).map(function(el) { return parseInt(el.value, 10); });
  var btn = document.getElementById('save-blocklists');
  var err = document.getElementById('save-error');
  btn.disabled = true;
  err.style.display = 'none';
  fetch('/api/blocklists', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({filter_ids: ids})
  }).then(function(r) { return r.json(); }).then(function(d) {
    btn.disabled = false;
    if (!d.ok) { err.style.display = 'block'; }
  }).catch(function() {
    btn.disabled = false;
    err.style.display = 'block';
  });
});
</script>"""
    return render_template_string(
        html, client_id=client_id, filters=filters,
        user_email=email, is_trial=is_trial, plan_badge=plan_badge,
        has_family_badge=has_family_badge, harbor_kids=harbor_kids,
        active="blocklists", light_theme=True,
    )

```

- [ ] **Step 4: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output, exit code 0.

- [ ] **Step 5: Verify the nav link and route both landed**

```bash
grep -n 'dashboard/blocklists\|def dashboard_blocklists' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: three matches - the nav `<a href>` line, the `@app.route` decorator, and the `def dashboard_blocklists` line.

- [ ] **Step 6: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/blocklists customer page and nav link"
```

---

### Task 5: Restart, end-to-end verification, and rollback readiness

**Files:**
- No source changes. This task restarts the live service and verifies Tasks 2-4 work together against the real customer-facing AGH instance (Task 1).

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: the live, verified feature.

- [ ] **Step 1: Confirm the working tree compiles clean before touching the live service**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py && echo "COMPILE OK"
```

Expected: `COMPILE OK`.

- [ ] **Step 2: Run the pre-restart safety gate**

```bash
cd /home/ubuntu/harbor-backend
./check-dashboard.sh
```

Expected: the script's own output shows all 6 pre-checks passing and it restarts `harbor-dashboard.service` itself. If any check fails, stop - do not manually force a restart; investigate the failing route first.

- [ ] **Step 3: Confirm the service came back up healthy**

```bash
sudo systemctl is-active harbor-dashboard.service
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7000/login
```

Expected: `active`, then `200`.

- [ ] **Step 4: End-to-end verification with a disposable test account**

Using a real or disposable test customer account (per the spec's Testing section - never a real paying customer for this step), log in and:

```bash
curl -s -b "<session-cookie-from-a-real-browser-login>" http://127.0.0.1:7000/dashboard/blocklists | grep -o 'blocklist-check[^>]*' | head -20
```

Expected: one `<input class="blocklist-check" ...>` per filter currently enabled on the customer-facing AGH instance, matching `GET http://127.0.0.1:8080/control/filtering/status`'s `filters` array count.

Then, from the browser (not curl, since this needs the session cookie and JS), check two boxes and click "Save selection." Confirm:

```bash
curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/filtering/tiers
```

Expected: exactly one new `cust-...` tier, `filter_ids` matching the two checked filters' ids.

```bash
curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/clients | python3 -c "
import json, sys
d = json.load(sys.stdin)
for c in d.get('clients', []):
    if c.get('filter_tier'):
        print(c['name'], c['filter_tier'])
"
```

Expected: the test account's main client id and every one of its kid profiles (if any exist) show the same `cust-...` tier name.

- [ ] **Step 5: Confirm dedup works across two accounts**

Repeat Step 4's save with a second disposable test account, selecting the identical two filters.

```bash
curl -s -u "$ADGUARD_USER:$ADGUARD_PASS" http://127.0.0.1:8080/control/filtering/tiers
```

Expected: still exactly one `cust-...` tier (not two) - both test accounts' clients now point at the same `filter_tier` name.

- [ ] **Step 6: DNS-level enforcement spot check**

```bash
dig @127.0.0.1 -p 53 -b <test-client-source-ip> <a-domain-known-blocked-by-one-of-the-two-selected-lists>
```

Expected: `NXDOMAIN` or the configured block response, confirming the selection is actually enforced, not just stored.

- [ ] **Step 7: Confirm real existing customers are unaffected**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7000/dashboard/adblock
```

Run this while authenticated as a pre-existing real customer (not the test accounts). Expected: `200`, page renders exactly as before this plan's changes (no `filter_tier` was set on any client that never called `/api/blocklists`, so their behavior is untouched).

- [ ] **Step 8: Note rollback path (no commit needed, this is documentation of an already-available option)**

If Step 4-7 reveal a problem: `sudo cp /opt/AdGuardHome/AdGuardHome.pre-tiers.bak /opt/AdGuardHome/AdGuardHome && sudo systemctl restart AdGuardHome.service` reverts Sub-project A; `git revert` the Task 2-4 commits and re-run `./check-dashboard.sh` reverts Sub-project B. No `AdGuardHome.yaml` schema changed, so no data migration is needed either direction.

No commit for this task (verification only - Tasks 2-4 already committed their changes).

---

## After this plan ships

Per the spec's Deployment section, once all 5 tasks are verified live, Tim sends the customer announcement email about the new self-service blocklist picker. That is a separate, later, non-code step - not part of this plan's execution.
