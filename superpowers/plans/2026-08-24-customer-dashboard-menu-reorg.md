# Customer Dashboard Menu Reorganization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the customer dashboard's one long scrolling page into a lightweight main page (protection status, stats, DNS setup) plus five new pages (Account, Add-Ons, Filters, Harbor Kids, Support), reachable from a hamburger menu that replaces the current small "Menu ▾" text link.

**Architecture:** Pure `dashboard.py` (Python/Jinja) reorganization. Five new routes each relocate existing card markup, following the exact pattern `/dashboard/adblock` and `/dashboard/blocklists` already use (`@login_required`, independently computed customer/plan locals, `STYLE + NAV_CUSTOMER + """html"""`, `render_template_string`). The main `/dashboard` route's two plan-type branches (Harbor Light, full/Remote) each lose the relocated cards and gain shortcut cards linking out. `NAV_CUSTOMER`'s trigger becomes a hamburger icon holding one unified link list.

**Tech Stack:** Python 3 / Flask, Jinja `render_template_string`, no new JS libraries, no new CSS framework - two small CSS rules added to the existing `STYLE` block for the hamburger icon.

**Spec:** `/home/ubuntu/harbor-backend/superpowers/specs/2026-08-24-customer-dashboard-menu-reorg-design.md`

## Global Constraints

- No new business logic, no new data sources, no new API routes beyond the 5 new page GETs. Every new page calls the same helper functions the main dashboard route already calls today (`get_client_stats_real`, `get_client_rules`, `has_family_addon`, `get_kids_profiles`, `get_all_blocked_services`, `get_client_blocked_services`, `get_doh_uptime_pct`, `find_customer`, `get_client`, `_standalone_vpn_status`).
- No changes to `/settings`, `/dashboard/adblock`, `/dashboard/blocklists`, `/dashboard/adblock/screen-time/<kid_name>`, or any admin page. They keep working exactly as they do today; the menu just links to them.
- Never write `harbor_kids` or `plan_type` - every new route only reads these fields, matching every existing customer route.
- No em dashes in any new copy or code comments.
- No automated test suite exists in this repo - verification is manual: curl with a minted session token (`harbor_lib.auth.make_token` using the real `DASHBOARD_SECRET` from `/etc/harbor-dashboard.env`, the same technique used for the blocklist-selection plan) plus grepping the response for expected content, plus a real-browser visual check for the hamburger's open/close behavior.
- Deploy via `/home/ubuntu/harbor-backend/check-dashboard.sh` followed by `sudo systemctl restart harbor-dashboard` - never a bare restart. This is a pure `dashboard.py` change, no AGH/Go binary involved, no special production gate beyond the pre-restart check passing.

---

### Task 1: `/dashboard/account` route

**Files:**
- Modify: `dashboard.py` - append a new route immediately before `if __name__ == "__main__":` (currently at line 10584 - verify with the grep in Step 1, since earlier tasks in this plan will shift it).

**Interfaces:**
- Consumes: `find_customer`, `has_family_addon` (already imported), `STYLE`, `NAV_CUSTOMER` (module-level globals).
- Produces: `GET /dashboard/account`, `active="account"` value for nav highlighting. Not consumed by any later task in this plan - Task 8's menu just links to this URL.

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if __name__ == "__main__":' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: one match, near the end of the file.

- [ ] **Step 2: Add the route**

Insert this block immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 26 - CUSTOMER ACCOUNT PAGE
# Owns: /dashboard/account. Account Info (relocated from the main
# /dashboard route) plus a Settings-links card, for both plan types.
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/account")
@login_required
def dashboard_account():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""
    is_active = customer is not None

    is_trial = customer.get("is_trial", False) if customer else False
    plan_type = customer.get("plan_type", "") if customer else ""
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    is_light_plan = plan_type == "harbor-remote-light"
    has_family_badge = has_family_addon(client_id) if client_id else False
    has_family = has_family_badge
    is_founder = customer.get("is_founder", False) if customer else False
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_trial: plan_badge = "TRIAL"
    elif is_active: plan_badge = "MONTHLY"

    if is_trial: plan_type_display = "Remote Trial"
    elif plan_type == "annual": plan_type_display = "Remote Yearly"
    elif plan_type == "harbor-remote-light": plan_type_display = "Light Monthly"
    else: plan_type_display = "Remote Monthly"

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Account</p>
  <h1 style="margin-bottom:24px;">Your account.</h1>
  {% if is_active %}
  <div class="card" style="margin-bottom:20px;">
    <div class="sec-head"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account Info</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">EMAIL</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ user_email }}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">PLAN</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{% if plan_badge %}{{ plan_badge }}{% else %}Remote{% endif %}</span>
      </div>
      {% if customer and customer.plan_type %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">PLAN TYPE</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{{ plan_type_display }}</span>
      </div>
      {% endif %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">STATUS</span>
        <span class="badge badge-on">ACTIVE</span>
      </div>
      {% if customer %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">JOINED</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{{ customer.date[:10] }}</span>
      </div>
      {% if customer.last_seen %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">LAST ACTIVE</span>
        <span id="last-active-local" data-utc="{{ customer.last_seen }}" style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ customer.last_seen[:16].replace("T"," ") }} UTC</span>
      </div>
      {% endif %}
      {% endif %}
      {% if is_founder %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">TIER</span>
        <span class="badge" style="background:#1f5d6b;color:#ffffff;">FOUNDER</span>
      </div>
      {% endif %}
      {% if has_family %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">ADD-ONS</span>
        <span class="badge badge-family">FAMILY SAFE</span>
      </div>
      {% endif %}
    </div>
  </div>
  {% else %}
  <p class="note" style="margin-bottom:20px;">No active subscription found on your account.</p>
  {% endif %}

  <div class="card">
    <div class="card-label">Settings</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <a href="/settings" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Change Password &rarr;</a>
      <a href="/settings" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Two-Factor Authentication &rarr;</a>
      <a href="/settings/data-request" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Download My Data &rarr;</a>
    </div>
  </div>

  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>"""
    return render_template_string(
        html, client_id=client_id, customer=customer, is_active=is_active,
        user_email=email, is_trial=is_trial, plan_badge=plan_badge, plan_type_display=plan_type_display,
        has_family_badge=has_family_badge, has_family=has_family, harbor_kids=harbor_kids,
        is_founder=is_founder, is_light_plan=is_light_plan,
        active="account", light_theme=True,
    )

```

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output, exit code 0.

- [ ] **Step 4: Verify the route landed**

```bash
grep -n 'def dashboard_account\|@app.route("/dashboard/account")' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: two matches.

- [ ] **Step 5: Manual verification (after this task's commit, restart is not required yet - defer full HTTP verification to Task 6/7's cutover check; for now just confirm the file is syntactically sound and self-consistent)**

```bash
python3 -c "
import ast
with open('/home/ubuntu/harbor-backend/dashboard.py') as f:
    ast.parse(f.read())
print('SYNTAX_OK')
"
```

Expected: `SYNTAX_OK`.

- [ ] **Step 6: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/account customer page"
```

---

### Task 2: `/dashboard/addons` route

**Files:**
- Modify: `dashboard.py` - append immediately before `if __name__ == "__main__":`.

**Interfaces:**
- Consumes: `get_client`, `has_family_addon`, `_standalone_vpn_status`, `VPN_CHECKOUT_MODAL` (module-level string, defined later in the file but resolved at call time, same as the main dashboard route already relies on).
- Produces: `GET /dashboard/addons`, `active="addons"`.

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if __name__ == "__main__":' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 2: Add the route**

Insert immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 27 - CUSTOMER ADD-ONS PAGE
# Owns: /dashboard/addons. Full plan: Family Safe + Harbor VPN
# (relocated from the main /dashboard route's Add-Ons card). Light
# plan: Harbor VPN only, Light has no Family Safe toggle.
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/addons")
@login_required
def dashboard_addons():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""
    is_active = customer is not None
    client = get_client(client_id) if client_id else {}

    plan_type = customer.get("plan_type", "") if customer else ""
    is_light_plan = plan_type == "harbor-remote-light"
    is_trial = customer.get("is_trial", False) if customer else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    has_family_badge = has_family_addon(client_id) if client_id else False
    family_safe = client.get("parental_enabled", False) if client else False
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_trial: plan_badge = "TRIAL"
    elif is_active: plan_badge = "MONTHLY"

    vpn_status = customer.get("vpn_status", False) if customer else False
    if customer and not vpn_status:
        _sv = _standalone_vpn_status(email)
        if _sv and _sv.get("active"):
            vpn_status = True

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Add-Ons</p>
  <h1 style="margin-bottom:24px;">Add-ons.</h1>
  {% if is_light_plan %}
  <div class="card">
    <div class="card-label">Harbor VPN {% if vpn_status %}<span class="badge badge-on">ACTIVE</span>{% endif %}</div>
    <p class="note" style="margin-bottom:16px;">WireGuard, OpenVPN &amp; AmneziaWG tunnels with the same DNS-layer blocking, added to any plan.</p>
    {% if vpn_status %}
    <a href="/vpn-sso" target="_blank" class="btn" style="background:transparent;border-color:var(--accent);color:var(--accent);">Manage Devices &#8594;</a>
    {% else %}
    <button onclick="openVpnAddonCheckout('monthly')" class="btn" style="background:transparent;border-color:var(--accent);color:var(--accent);cursor:pointer;">Add Harbor VPN &mdash; $4.99/mo &#8594;</button>
    <button onclick="openVpnAddonCheckout('annual')" style="background:none;border:none;color:var(--muted);font-family:'DM Mono',monospace;font-size:11px;text-decoration:underline;cursor:pointer;margin-left:10px;">or $49/yr</button>
    {% endif %}
  </div>
  {% else %}
  <div class="card">
    <div class="card-label">Add-Ons {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <div style="position:relative;">
      <div class="toggle-row">
        <div>
          <div class="toggle-label">
            Family Safe
            <span class="badge {% if family_safe %}badge-on{% else %}badge-off{% endif %}">{% if family_safe %}ON{% else %}OFF{% endif %}</span>
          </div>
          <div class="toggle-desc">SafeSearch enforcement, adult content blocking, NSFW filtering</div>
        </div>
        <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
          <input type="checkbox" {% if family_safe %}checked{% endif %} {% if not is_active %}disabled{% else %}onchange="toggleAddon('family',this.checked)"{% endif %}>
          <span class="slider" style="border-radius:24px;"></span>
        </label>
      </div>

      <div class="toggle-row">
        <div>
          <div class="toggle-label">
            Harbor VPN
            <span class="badge {% if vpn_status %}badge-on{% else %}badge-off{% endif %}">{% if vpn_status %}ACTIVE{% else %}NOT ACTIVE{% endif %}</span>
          </div>
          <div class="toggle-desc">WireGuard, OpenVPN &amp; AmneziaWG tunnels with the same DNS-layer blocking</div>
        </div>
        {% if vpn_status %}
        <a href="/vpn-sso" target="_blank" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--accent);border:1px solid var(--accent);padding:8px 14px;text-decoration:none;white-space:nowrap;">Manage Devices &#8594;</a>
        {% else %}
        <span style="white-space:nowrap;">
          <button onclick="openVpnAddonCheckout('monthly')" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--accent);background:none;border:1px solid var(--accent);padding:8px 14px;cursor:pointer;white-space:nowrap;">Add &mdash; $4.99/mo &#8594;</button>
          <button onclick="openVpnAddonCheckout('annual')" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);background:none;border:none;text-decoration:underline;cursor:pointer;">or $49/yr</button>
        </span>
        {% endif %}
      </div>
    </div>
  </div>
  {% endif %}

  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>
<script>
async function toggleAddon(type,enabled){
  const r=await fetch('/api/addon'+location.search,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,enabled})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed to update. Please try again.');
}
</script>
""" + VPN_CHECKOUT_MODAL + """
</html>"""
    return render_template_string(
        html, client_id=client_id, is_active=is_active, is_light_plan=is_light_plan,
        family_safe=family_safe, vpn_status=vpn_status, has_family_badge=has_family_badge,
        harbor_kids=harbor_kids, user_email=email, is_trial=is_trial, plan_badge=plan_badge,
        active="addons", light_theme=True,
    )

```

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output.

- [ ] **Step 4: Verify**

```bash
grep -n 'def dashboard_addons' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: one match.

- [ ] **Step 5: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/addons customer page"
```

---

### Task 3: `/dashboard/filters` route

**Files:**
- Modify: `dashboard.py` - append immediately before `if __name__ == "__main__":`.

**Interfaces:**
- Consumes: `get_client_rules`, `get_all_blocked_services`, `get_client_blocked_services`.
- Produces: `GET /dashboard/filters`, `active="filters"`.

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if __name__ == "__main__":' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 2: Add the route**

Insert immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 28 - CUSTOMER FILTERS PAGE
# Owns: /dashboard/filters. Full plan: Custom Rules, Quick Profiles,
# Blocked Services (relocated from the main /dashboard route). Light
# plan: the simplified "Block or Allow a Site" tool (also relocated).
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/filters")
@login_required
def dashboard_filters():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""
    is_active = customer is not None

    plan_type = customer.get("plan_type", "") if customer else ""
    is_light_plan = plan_type == "harbor-remote-light"
    is_trial = customer.get("is_trial", False) if customer else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    has_family_badge = has_family_addon(client_id) if client_id else False
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_trial: plan_badge = "TRIAL"
    elif is_active: plan_badge = "MONTHLY"

    rules = get_client_rules(client_id) if client_id else []
    active_profile = customer.get("active_profile", "custom") if customer else "custom"
    service_groups = get_all_blocked_services() if is_active else {}
    blocked_services = get_client_blocked_services(client_id) if is_active and client_id else []

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Filters</p>
  <h1 style="margin-bottom:24px;">Filters.</h1>
  {% if is_light_plan %}
  <div class="card">
    <div class="card-label">Block or Allow a Site</div>
    <p class="note" style="margin-bottom:16px;">If something gets blocked that should not be, allow it here. Or block a specific site on your network.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input type="text" id="light-domain" placeholder="example.com" style="flex:1;min-width:140px;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:10px 12px;font-family:'DM Mono',monospace;font-size:13px;">
      <button onclick="lightAddRule(false)" class="btn" style="background:var(--accent);color:var(--bg);">Allow</button>
      <button onclick="lightAddRule(true)" class="btn" style="background:transparent;border:1px solid var(--danger);color:var(--danger);">Block</button>
    </div>
    <div id="light-rules-list">
      {% for rule in rules %}
      <div class="row" style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);">
        <span class="{% if rule.startswith('@@') %}rule-allow{% else %}rule-block{% endif %}" style="font-family:'DM Mono',monospace;font-size:12px;">{{ rule }}</span>
        <button onclick="removeRule('{{ rule }}')" class="btn btn-danger btn-sm">Remove</button>
      </div>
      {% else %}
      <p class="note">No custom rules yet.</p>
      {% endfor %}
    </div>
  </div>
  <script>
  function lightAddRule(block){
    var domain = document.getElementById('light-domain').value.trim();
    if(!domain) return;
    fetch('/api/rule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain:domain, block:block})})
      .then(r=>r.json()).then(d=>{ if(d.ok) location.reload(); else alert('Error: '+d.error); });
  }
  async function removeRule(rule){
    if(!confirm('Remove this rule?'))return;
    const r=await fetch('/api/rule',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule})});
    const d=await r.json();
    if(d.ok)location.reload();
  }
  </script>
  {% else %}
  <div class="card">
    <div class="card-label">Custom Rules {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    {% if is_active %}
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <input type="text" id="rule-domain" placeholder="example.com" style="margin:0;flex:1;min-width:140px;">
      <select id="rule-type" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;margin:0;width:auto;">
        <option value="block">Block</option>
        <option value="allow">Allow</option>
      </select>
      <button onclick="addRule()" class="btn">Add Rule</button>
    </div>
    {% for rule in rules %}
    <div class="row">
      <span class="{% if rule.startswith('@@') %}rule-allow{% else %}rule-block{% endif %}">{{ rule }}</span>
      <button onclick="removeRule('{{ rule }}')" class="btn btn-danger btn-sm">Remove</button>
    </div>
    {% else %}
    <p class="note">No custom rules yet. Add a domain above to block or allow it.</p>
    {% endfor %}
    {% else %}
    <p class="note" style="margin-bottom:16px;">Block or allow specific websites on your network. Unlocks with an active Harbor Remote subscription.</p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;opacity:0.4;pointer-events:none;">
      <input type="text" placeholder="example.com" style="margin:0;flex:1;min-width:140px;" disabled>
      <button class="btn btn-disabled">Add Rule</button>
    </div>
    {% endif %}
  </div>

  {% if is_active %}
  <div class="card">
    <div class="card-label">Quick Profiles</div>
    <p class="note" style="margin-bottom:20px;">Apply a preset profile to quickly block groups of services. Your custom settings are saved automatically. Current: {{ active_profile }}</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:16px;">
      <button onclick="applyProfile('kid')" class="profile-btn {% if active_profile == 'kid' %}profile-active{% endif %}" data-profile="kid">
        <div style="font-size:24px;margin-bottom:6px;">&#128103;</div>
        <div style="font-weight:700;margin-bottom:4px;">Kid Mode</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, adult, gambling</div>
      </button>
      <button onclick="applyProfile('work')" class="profile-btn {% if active_profile == 'work' %}profile-active{% endif %}" data-profile="work">
        <div style="font-size:24px;margin-bottom:6px;">&#128188;</div>
        <div style="font-weight:700;margin-bottom:4px;">Work Focus</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, streaming, gaming</div>
      </button>
      <button onclick="applyProfile('gaming')" class="profile-btn {% if active_profile == 'gaming' %}profile-active{% endif %}" data-profile="gaming">
        <div style="font-size:24px;margin-bottom:6px;">&#127918;</div>
        <div style="font-weight:700;margin-bottom:4px;">Gaming Mode</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, keeps gaming open</div>
      </button>
      <button onclick="applyProfile('custom')" class="profile-btn {% if active_profile == 'custom' or not active_profile %}profile-active{% endif %}" data-profile="custom">
        <div style="font-size:24px;margin-bottom:6px;">&#9881;</div>
        <div style="font-weight:700;margin-bottom:4px;">Custom</div>
        <div style="font-size:11px;opacity:0.7;">Your saved settings</div>
      </button>
    </div>
    <button onclick="applyProfile('clear')" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);background:transparent;border:1px solid var(--border);padding:6px 14px;cursor:pointer;">Clear All Blocks</button>
  </div>

  <div class="card">
    <div class="card-label">Blocked Services</div>
    <p class="note" style="margin-bottom:20px;">Block entire services on your network. Toggle on to block, off to allow.</p>
    {% for group_name, services in service_groups.items() %}
    {% set blocked_in_group = services | selectattr("id", "in", blocked_services) | list %}
    <div class="service-group" style="margin-bottom:4px;border:1px solid var(--border);">
      <button onclick="toggleGroup(this)" style="width:100%;display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--surface);border:none;cursor:pointer;text-align:left;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;">{{ group_name.replace("_"," ") }}</span>
          <span class="group-badge" style="font-family:'DM Mono',monospace;font-size:9px;{% if blocked_in_group %}background:var(--accent);color:var(--bg);{% else %}background:var(--border);color:var(--muted);{% endif %}padding:2px 6px;">{{ blocked_in_group|length }}/{{ services|length }} BLOCKED</span>
        </div>
        <span class="group-arrow" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">&#9660;</span>
      </button>
      <div class="group-body" style="display:none;padding:12px;background:var(--bg);">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;">
          {% for svc in services %}
          <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface);border:1px solid var(--border);">
            <span style="font-size:13px;color:var(--text);">{{ svc.name }}</span>
            <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
              <input type="checkbox" {% if svc.id in blocked_services %}checked{% endif %} onchange="toggleService(this,'{{ svc.id }}',this.checked)">
              <span class="slider" style="border-radius:24px;"></span>
            </label>
          </div>
          {% endfor %}
        </div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <script>
  async function addRule(){
    const domain=document.getElementById('rule-domain').value.trim();
    const type=document.getElementById('rule-type').value;
    if(!domain)return;
    const r=await fetch('/api/rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,block:type==='block'})});
    const d=await r.json();
    if(d.ok)location.reload();else alert('Failed to add rule.');
  }
  async function removeRule(rule){
    if(!confirm('Remove this rule?'))return;
    const r=await fetch('/api/rule',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule})});
    const d=await r.json();
    if(d.ok)location.reload();
  }
  async function applyProfile(profile){
    if(profile === 'clear' && !confirm('Remove all blocked services?')) return;
    const btns = document.querySelectorAll('.profile-btn');
    btns.forEach(b => b.classList.remove('profile-active'));
    const activeBtn = document.querySelector('[data-profile="'+profile+'"]');
    if(activeBtn) activeBtn.classList.add('profile-active');
    const r = await fetch('/api/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile})});
    const d = await r.json();
    if(d.ok) location.reload();
    else alert('Error: ' + (d.error || 'Unknown error'));
  }
  async function toggleService(el, id, blocked){
    const r=await fetch('/api/service'+location.search,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service_id:id,blocked:blocked})});
    const d=await r.json();
    if(!d.ok){ el.checked=!blocked; alert('Failed to update. Try again.'); return; }
    const group=el.closest('.service-group');
    const badge=group.querySelector('.group-badge');
    const boxes=group.querySelectorAll('.group-body input[type="checkbox"]');
    let blockedCount=0;
    boxes.forEach(b=>{ if(b.checked) blockedCount++; });
    badge.textContent=blockedCount+'/'+boxes.length+' BLOCKED';
    badge.style.background=blockedCount?'var(--accent)':'var(--border)';
    badge.style.color=blockedCount?'var(--bg)':'var(--muted)';
  }
  </script>
  {% endif %}

  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>"""
    return render_template_string(
        html, client_id=client_id, is_active=is_active, is_light_plan=is_light_plan,
        rules=rules, active_profile=active_profile, service_groups=service_groups, blocked_services=blocked_services,
        has_family_badge=has_family_badge, harbor_kids=harbor_kids, user_email=email, is_trial=is_trial, plan_badge=plan_badge,
        active="filters", light_theme=True,
    )

```

Note: `toggleGroup` (called by the Blocked Services markup's `onclick="toggleGroup(this)"` above) is intentionally NOT defined in this page's script block. It already exists as a global helper inside the shared `STYLE` block (`dashboard.py:676`, included on every customer page via `STYLE + NAV_CUSTOMER`), so every page that includes `STYLE` already has it. Defining a second, local copy here would be redundant at best and could silently diverge from the real one at worst - confirmed by checking the real implementation directly: it also flips a `.group-arrow` chevron icon between `&#9650;`/`&#9660;`, which an earlier draft of this task guessed incorrectly and omitted.

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 4: Verify**

```bash
grep -n 'def dashboard_filters' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 5: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/filters customer page"
```

---

### Task 4: `/dashboard/kids` route

**Files:**
- Modify: `dashboard.py` - append immediately before `if __name__ == "__main__":`.

**Interfaces:**
- Consumes: `get_kids_profiles`.
- Produces: `GET /dashboard/kids`, `active="kids"`. Full plan only - not linked from Light plan's shortcut cards or menu (Task 7, Task 8).

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if __name__ == "__main__":' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 2: Add the route**

Insert immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 29 - CUSTOMER HARBOR KIDS PAGE
# Owns: /dashboard/kids. Full plan only - not eligible on Harbor
# Light. Relocated from the main /dashboard route's Harbor Kids card.
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/kids")
@login_required
def dashboard_kids():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""
    is_active = customer is not None

    plan_type = customer.get("plan_type", "") if customer else ""
    is_trial = customer.get("is_trial", False) if customer else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    has_family_badge = has_family_addon(client_id) if client_id else False
    kids_eligible = plan_type != "harbor-remote-light"
    kids_profiles = get_kids_profiles(client_id) if client_id else []
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_trial: plan_badge = "TRIAL"
    elif is_active: plan_badge = "MONTHLY"

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Harbor Kids</p>
  <h1 style="margin-bottom:24px;">Harbor Kids.</h1>
  <div class="card">
    <div class="card-label">Harbor Kids &#8212; Your Child Profiles</div>
    {% if kids_profiles %}
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">Each child profile has its own DNS address. Use the setup guide to install it on your child's device.</p>
    {% for kp in kids_profiles %}
    <div style="border:1px solid var(--border);padding:16px;margin-bottom:12px;background:var(--bg);">
      <div style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);margin-bottom:10px;">{{ kp.name }}</div>
      <div style="background:var(--surface);border-left:3px solid var(--accent);padding:10px 14px;font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);word-break:break-all;margin-bottom:10px;">https://doh.harborprivacy.com/dns-query/{{ kp.name }}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="https://adblock.harborprivacy.com/profiles/{{ kp.name }}.mobileconfig" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#8659; iOS/Mac Profile</a>
        <a href="https://adblock.harborprivacy.com/setup/android/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
        <a href="https://harborprivacy.com/docs/harbor-kids#kids-setup" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">Windows Setup</a>
        <a href="/dashboard/adblock/screen-time/{{ kp.name }}" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#128274; Lock with Screen Time</a>
      </div>
    </div>
    {% endfor %}
    {% else %}
    <p style="font-size:13px;color:var(--muted);">Add your first child profile to get started.</p>
    {% endif %}
    {% if not kids_eligible %}
    <div style="margin-top:16px;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Harbor Kids is included with Harbor Remote. <a href="https://billing.stripe.com/p/login/3cI28qfUX5Tp5rn80T6kg00" target="_blank" style="color:var(--accent);">Switch to Remote (prorated) &#8594;</a></div>
    {% elif kids_profiles|length < 5 %}
    <div style="margin-top:16px;">
      <button onclick="addKidProfileCustomer()" style="background:var(--accent);color:#0a0e0f;border:none;padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;letter-spacing:0.08em;">+ Add Child Profile</button>
      <span style="font-size:12px;color:var(--muted);margin-left:8px;">{{ 5 - kids_profiles|length }} of 5 remaining</span>
    </div>
    {% else %}
    <div style="margin-top:16px;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Maximum of 5 child profiles reached.</div>
    {% endif %}
    <div style="font-size:11px;color:var(--muted);margin-top:12px;">Harbor Kids accounts are managed by a parent or guardian. We do not collect personal information from children. <a href="https://harborprivacy.com/nologs" style="color:var(--accent);text-decoration:none;">Privacy Policy</a></div>
  </div>

  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>
<script>
async function addKidProfileCustomer(){
  const kid_num = parseInt('{{ kids_profiles|length }}') + 1;
  if(kid_num > 5){alert('Maximum of 5 child profiles reached.');return;}
  const r = await fetch('/api/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'harbor_kids_add',kid_num:kid_num})});
  const d = await r.json();
  if(d.ok){location.reload();}else{alert('Failed to create profile. Contact support@harborprivacy.com');}
}
</script>"""
    return render_template_string(
        html, client_id=client_id, is_active=is_active, kids_profiles=kids_profiles, kids_eligible=kids_eligible,
        has_family_badge=has_family_badge, harbor_kids=harbor_kids, user_email=email, is_trial=is_trial, plan_badge=plan_badge,
        active="kids", light_theme=True,
    )

```

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 4: Verify**

```bash
grep -n 'def dashboard_kids' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 5: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/kids customer page"
```

---

### Task 5: `/dashboard/support` route

**Files:**
- Modify: `dashboard.py` - append immediately before `if __name__ == "__main__":`.

**Interfaces:**
- Consumes: nothing beyond the standard customer/plan locals every new page computes.
- Produces: `GET /dashboard/support`, `active="support"`.

- [ ] **Step 1: Confirm the exact insertion anchor**

```bash
grep -n 'if __name__ == "__main__":' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 2: Add the route**

Insert immediately before `if __name__ == "__main__":`:

```python
# ════════════════════════════════════════════════════════════
# SECTION 30 - CUSTOMER SUPPORT PAGE
# Owns: /dashboard/support. Both plan types. Full plan never had a
# Support card before this - authored here using Harbor Light's
# existing Support card's exact copy.
# ════════════════════════════════════════════════════════════

@app.route("/dashboard/support")
@login_required
def dashboard_support():
    email = request.user_email
    customer = find_customer(email)
    client_id = customer.get("client_id", "") if customer else ""

    plan_type = customer.get("plan_type", "") if customer else ""
    is_trial = customer.get("is_trial", False) if customer else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    has_family_badge = has_family_addon(client_id) if client_id else False
    plan_badge = ""
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_trial: plan_badge = "TRIAL"
    elif customer: plan_badge = "MONTHLY"

    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Support</p>
  <h1 style="margin-bottom:24px;">Support.</h1>
  <div class="card">
    <div class="card-label">Support</div>
    <p class="note" style="margin-bottom:16px;">Need help with setup or have a question?</p>
    <a href="mailto:support@harborprivacy.com" class="btn" style="background:transparent;border-color:var(--border);color:var(--text);">Email Support &#8594;</a>
  </div>

  <a href="/dashboard" class="ghost" style="margin-top:16px;display:inline-block;">&larr; Back to Dashboard</a>
</div>"""
    return render_template_string(
        html, client_id=client_id, has_family_badge=has_family_badge, harbor_kids=harbor_kids,
        user_email=email, is_trial=is_trial, plan_badge=plan_badge,
        active="support", light_theme=True,
    )

```

- [ ] **Step 3: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 4: Verify**

```bash
grep -n 'def dashboard_support' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 5: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Add /dashboard/support customer page"
```

---

### Task 6: End-to-end verification of all 5 new pages before cutover

**Files:** none - this task is manual verification only, no source changes. It exists because the main dashboard cutover (Tasks 7-8) removes the only place these cards used to live, so every new page must be proven working first.

**Interfaces:**
- Consumes: all 5 routes from Tasks 1-5.
- Produces: confidence to proceed - if any check fails here, fix the failing route before starting Task 7.

- [ ] **Step 1: Restart the service through the safety gate**

```bash
cd /home/ubuntu/harbor-backend
./check-dashboard.sh
```

Expected: all pre-checks pass, service restarts, ends active.

- [ ] **Step 2: Mint a session token for a real test account**

Use your own account (matching the technique from the blocklist-selection plan - never a real paying customer for exploratory testing):

```bash
TOKEN=$(sudo bash -c '
export FLASK_SECRET=$(grep "^FLASK_SECRET=" /etc/harbor-dashboard.env | cut -d= -f2-)
export DASHBOARD_SECRET=$(grep "^DASHBOARD_SECRET=" /etc/harbor-dashboard.env | cut -d= -f2-)
export CUSTOMERS_LOG=/var/log/harbor-customers.json
cd /home/ubuntu/harbor-backend
python3 -c "
from harbor_lib.auth import make_token
print(make_token(\"tim@harborprivacy.com\", is_admin=False))
"
')
echo "token minted"
```

- [ ] **Step 3: Verify each new page returns 200 and its expected content**

```bash
for path in account addons filters kids support; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -b "hp_token=$TOKEN" "http://127.0.0.1:7000/dashboard/$path")
  echo "$path -> $code"
done
```

Expected: `200` for all five.

```bash
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard/account | grep -o "Account Info\|Settings" | sort -u
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard/addons | grep -o "Add-Ons\|Harbor VPN"
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard/filters | grep -o "Custom Rules\|Quick Profiles\|Blocked Services"
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard/kids | grep -o "Harbor Kids"
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard/support | grep -o "Support"
```

Expected: each grep prints the matching card labels found on its page.

- [ ] **Step 4: No commit for this task** - verification only.

---

### Task 7: Main `/dashboard` page cutover - full/Remote plan

**Files:**
- Modify: `dashboard.py:1809-2307` (the full-plan branch of `dashboard()` - reconfirm exact lines with the grep in Step 1 before editing, since Tasks 1-5 only appended new code and should not have shifted this range, but always verify).

**Interfaces:**
- Consumes: nothing new - removes cards, does not touch data computation this branch already does for the cards that stay (protection status, stats, DNS setup, trial/upsell/Harbor Scan cards).
- Produces: the main dashboard's full-plan branch now shows 5 shortcut cards. Task 8 depends on nothing from this task directly (Task 8 only touches `NAV_CUSTOMER`), but this task and Task 8 together complete the visible cutover.

- [ ] **Step 1: Confirm the exact card boundaries to remove**

```bash
grep -n 'card-label">Account Info\|sec-head">Account Info\|card-label">Add-Ons\|card-label">Harbor Kids &#8212\|card-label">Custom Rules\|card-label">Quick Profiles\|card-label">Blocked Services\|Harbor Scan &mdash\|return render_template_string(html, name=name, client_id=client_id,$' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: matches for each card label inside the full-plan branch (roughly lines 1890-2211), plus the closing `render_template_string` call around line 2299. Read the surrounding lines with the Read tool to get exact current line numbers before editing - do not assume the numbers from this plan's research are still exact.

- [ ] **Step 2: Remove the Account Info card**

Find the block starting `{% if is_active %}` immediately before `<div class="sec-head">...Account Info</div>` and ending at its matching `{% endif %}` (this is the block Task 1 relocated to `/dashboard/account`). Delete that whole `{% if is_active %}...{% endif %}` block, including the `<!-- CUSTOMER INFO CARD -->` comment immediately above it if present.

- [ ] **Step 3: Remove the Add-Ons, Harbor Kids, Custom Rules, Quick Profiles, and Blocked Services cards**

Delete each of these five card blocks in full (from their opening `<!-- ... -->` comment or `<div class="card">` through their closing `</div>`, and any `{% if is_active %}` wrapper around Quick Profiles/Blocked Services as already exists in the source):
- The `<!-- ADD-ONS -->` card (Family Safe + Harbor VPN toggle-row)
- The `Harbor Kids &#8212; Your Child Profiles` card
- The `<!-- CUSTOM RULES -->` card
- The `Quick Profiles` card and the `Blocked Services` card (both inside the shared `{% if is_active %}...{% endif %}` wrapper they're already in)

- [ ] **Step 4: Add the 5 shortcut cards**

Insert this block immediately after the DNS setup / Connection Check section and before the trial-early-upgrade card (`{% if is_trial and personal_promo_code %}`):

```html
  <!-- SHORTCUT CARDS -->
  <div class="card">
    <div class="card-label">Account</div>
    <p class="note" style="margin-bottom:12px;">Your plan, status, and login settings</p>
    <a href="/dashboard/account" class="ghost">View Account &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Add-Ons {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <p class="note" style="margin-bottom:12px;">Family Safe and Harbor VPN</p>
    <a href="/dashboard/addons" class="ghost">View Add-Ons &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Filters {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <p class="note" style="margin-bottom:12px;">Custom rules and blocked services</p>
    <a href="/dashboard/filters" class="ghost">View Filters &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Harbor Kids</div>
    <p class="note" style="margin-bottom:12px;">Manage your child profiles</p>
    <a href="/dashboard/kids" class="ghost">View Harbor Kids &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Support</div>
    <p class="note" style="margin-bottom:12px;">Get help with your account</p>
    <a href="/dashboard/support" class="ghost">View Support &rarr;</a>
  </div>

```

- [ ] **Step 5: Update the closing `render_template_string` call**

The call currently passes `rules`, `family_safe`, `has_family`, `kids_eligible`, `kids_profiles`, `active_profile`, `service_groups`, `blocked_services` - all of these were only used by the cards just removed. Remove them from the kwargs list and from the local-variable computation earlier in the function (the lines computing `rules = get_client_rules(...)`, `family_safe = ...`, `kids_eligible = ...`, `has_family = has_family_addon(...)` if no longer referenced, `service_groups = ...`, `blocked_services = ...`) - but first check each is not still referenced by a card that stays (e.g. `has_family` may still be read by the Account Info card, which just moved to a different route entirely and no longer lives in this function, so it is safe to remove here). Also add `is_light_plan=False` to the kwargs (this branch is definitionally the non-Light branch), since Task 8's `NAV_CUSTOMER` change reads this variable.

The updated call:

```python
    return render_template_string(html, name=name, client_id=client_id,
        is_active=is_active, total=total, blocked=blocked, pct=pct, blocked_month=blocked_month, lifetime=lifetime,
        user_email=email, is_trial=is_trial, plan_badge=plan_badge, plan_type_display=plan_type_display, has_family_badge=has_family_badge, vpn_status=vpn_status,
        personal_promo_code=personal_promo_code,
        filtering_paused=filtering_paused,
        is_founder=is_founder, top_blocked=top_blocked, customer=customer,
        harbor_kids=harbor_kids, is_light_plan=False, active="dashboard", light_theme=True, uptime_pct=uptime_pct)
```

- [ ] **Step 6: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

Expected: no output. If this fails with a `NameError`-adjacent complaint is impossible at compile time - instead run Step 7 to catch any leftover reference to a removed variable.

- [ ] **Step 7: Confirm no leftover references to removed variables**

```bash
sed -n '1809,2200p' /home/ubuntu/harbor-backend/dashboard.py | grep -n "kids_profiles\|kids_eligible\|service_groups\|blocked_services\|family_safe\b\| rules \|{{ rules"
```

Expected: no matches (adjust the line range in this command to match Task 7's actual final boundaries after Steps 2-4's edits, found via `grep -n "if plan_type == .harbor-remote-light.: plan_badge" dashboard.py` for the branch start and the render_template_string call location for the end).

- [ ] **Step 8: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Cut over main dashboard (full plan) to shortcut cards"
```

---

### Task 8: Main `/dashboard` page cutover - Harbor Light plan, plus `NAV_CUSTOMER` hamburger and unified menu

**Files:**
- Modify: `dashboard.py` - the Harbor Light branch of `dashboard()` (roughly lines 1640-1808, reconfirm before editing) and `NAV_CUSTOMER` (roughly lines 835-869, reconfirm before editing).

**Interfaces:**
- Consumes: `is_light_plan` kwarg, now passed by Task 7's full-plan branch (`is_light_plan=False`) and by this task's Light branch (`is_light_plan=True`), and by every new route from Tasks 1-5 (already threaded through in their own `render_template_string` calls).
- Produces: the complete cutover - every page that renders `NAV_CUSTOMER` now shows the hamburger and the right menu list for its plan type.

**Design decision for the Light-vs-Full menu flag:** `NAV_CUSTOMER` checks a new `is_light_plan` variable to decide whether to show the Harbor Kids link. Tasks 1-5's new routes and this task's two `dashboard()` branches all pass it explicitly. The three pre-existing, untouched routes that also render `NAV_CUSTOMER` (`/dashboard/adblock`, `/dashboard/blocklists`, `/dashboard/adblock/screen-time/<kid_name>`) are out of scope for this plan (Global Constraints) and do not pass `is_light_plan` - Jinja treats an undefined variable as falsy, so `{% if not is_light_plan %}` on those three pages evaluates true and the Harbor Kids link shows even for a Light-plan customer viewing one of those specific pages. This is an accepted, explicit gap: showing an inapplicable link on three unrelated, unmodified pages is a smaller problem than hiding a real link would be anywhere else, and fixing those three pages is out of this plan's scope per the spec's Non-goals.

- [ ] **Step 1: Confirm the exact Light-plan branch boundaries**

```bash
grep -n 'Harbor Light plan\|card-label">Block or Allow a Site\|card-label">Harbor VPN\|card-label">Support\|card-label">Settings\|return render_template_string(html, name=name, client_id=client_id, total=total' /home/ubuntu/harbor-backend/dashboard.py
```

Expected: matches from roughly line 1639 through the `render_template_string` call around line 1808. Read the surrounding lines to confirm exact current boundaries before editing.

- [ ] **Step 2: Remove the Block or Allow a Site, Harbor VPN, Support, and Settings cards**

Delete each of these four card blocks in full (Task 3 relocated "Block or Allow a Site" to `/dashboard/filters`; Task 2 relocated "Harbor VPN" to `/dashboard/addons`; Task 5 relocated "Support" to `/dashboard/support`; Task 1 relocated "Settings" to `/dashboard/account`), along with their associated `<script>` block for `lightAddRule` (now only needed on `/dashboard/filters`, already added there by Task 3).

- [ ] **Step 3: Add the 4 shortcut cards**

Insert immediately after the "Upgrade to Harbor Remote" card and before the closing `</div>` of the Light plan's `<div class="wrap">`:

```html
  <!-- SHORTCUT CARDS -->
  <div class="card">
    <div class="card-label">Account</div>
    <p class="note" style="margin-bottom:12px;">Your plan, status, and login settings</p>
    <a href="/dashboard/account" class="ghost">View Account &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Add-Ons</div>
    <p class="note" style="margin-bottom:12px;">Harbor VPN</p>
    <a href="/dashboard/addons" class="ghost">View Add-Ons &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Filters</div>
    <p class="note" style="margin-bottom:12px;">Block or allow specific sites</p>
    <a href="/dashboard/filters" class="ghost">View Filters &rarr;</a>
  </div>

  <div class="card">
    <div class="card-label">Support</div>
    <p class="note" style="margin-bottom:12px;">Get help with your account</p>
    <a href="/dashboard/support" class="ghost">View Support &rarr;</a>
  </div>

```

- [ ] **Step 4: Update the Light plan's closing `render_template_string` call**

Current call: `return render_template_string(html, name=name, client_id=client_id, total=total, blocked=blocked, blocked_month=blocked_month, lifetime=lifetime, active="dashboard", light_theme=True, vpn_status=vpn_status, uptime_pct=uptime_pct)`. `vpn_status` was only used by the removed Harbor VPN card - check the surviving Light-plan template (DNS setup, Connection Check, stats, Upgrade card, 4 shortcut cards) for any other reference to `vpn_status` before removing it from the kwargs; if none remains, drop it from both the kwargs and its computation earlier in the branch. Add `is_light_plan=True`:

```python
        return render_template_string(html, name=name, client_id=client_id, total=total, blocked=blocked, blocked_month=blocked_month, lifetime=lifetime, is_light_plan=True, active="dashboard", light_theme=True, uptime_pct=uptime_pct)
```

- [ ] **Step 5: Confirm the exact current `NAV_CUSTOMER` text**

```bash
grep -n '^NAV_CUSTOMER = ' /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 6: Replace the menu trigger and link list**

Find this block inside `NAV_CUSTOMER` (the exact text as of this plan's research - reconfirm with Step 5's line number and a direct read before editing, since earlier tasks in this plan do not touch this string but confirm anyway):

```python
      <div class="nav-drop">
        <a href="#" onclick="this.parentNode.classList.toggle('open');return false;" class="{% if active in ('adblock',) %}active{% endif %}">Menu &#9662;</a>
        <div class="nav-drop-menu">
          <a href="https://harborprivacy.com">← Site</a>
          <a href="/dashboard/adblock" class="{{ 'active' if active == 'adblock' else '' }}">AdBlock Usage</a>
""" + ("""          <a href="/dashboard/blocklists" class="{{ 'active' if active == 'blocklists' else '' }}">Blocklists</a>
""" if BLOCKLIST_SELECTION_ENABLED else "") + """          <a href="https://breach.harborprivacy.com/app">Breach Monitor</a>
          <a href="https://scan.harborprivacy.com">Harbor Scan</a>
        </div>
      </div>
```

Replace it with:

```python
      <div class="nav-drop">
        <a href="#" onclick="this.parentNode.classList.toggle('open');return false;" class="nav-hamburger-btn {% if active in ('account','addons','filters','kids','support','adblock','blocklists') %}active{% endif %}" aria-label="Menu"><svg viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></a>
        <div class="nav-drop-menu">
          <a href="https://harborprivacy.com">← Site</a>
          <a href="/dashboard/account" class="{{ 'active' if active == 'account' else '' }}">Account</a>
          <a href="/dashboard/addons" class="{{ 'active' if active == 'addons' else '' }}">Add-Ons</a>
          <a href="/dashboard/filters" class="{{ 'active' if active == 'filters' else '' }}">Filters</a>
          {% if not is_light_plan %}<a href="/dashboard/kids" class="{{ 'active' if active == 'kids' else '' }}">Harbor Kids</a>{% endif %}
          <a href="/dashboard/support" class="{{ 'active' if active == 'support' else '' }}">Support</a>
          <a href="/dashboard/adblock" class="{{ 'active' if active == 'adblock' else '' }}">Usage</a>
""" + ("""          <a href="/dashboard/blocklists" class="{{ 'active' if active == 'blocklists' else '' }}">Blocklists</a>
""" if BLOCKLIST_SELECTION_ENABLED else "") + """          <a href="https://breach.harborprivacy.com/app">Breach Monitor</a>
          <a href="https://scan.harborprivacy.com">Harbor Scan</a>
        </div>
      </div>
```

- [ ] **Step 7: Add CSS for the hamburger icon**

Find this exact line in `STYLE` (the existing nav-drop-menu link rule):

```css
  .nav-drop-menu a{display:block;padding:8px 10px;white-space:nowrap;}
```

Add immediately after it:

```css
  .nav-hamburger-btn{display:inline-flex;align-items:center;}
  .nav-hamburger-btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
```

- [ ] **Step 8: Syntax-check**

```bash
python3 -m py_compile /home/ubuntu/harbor-backend/dashboard.py
```

- [ ] **Step 9: Confirm no leftover references to removed variables in the Light branch**

```bash
sed -n '1639,1810p' /home/ubuntu/harbor-backend/dashboard.py | grep -n "lightAddRule\|vpn_status"
```

Expected: no matches (adjust the line range to match this task's actual final boundaries).

- [ ] **Step 10: Restart through the safety gate**

```bash
cd /home/ubuntu/harbor-backend
./check-dashboard.sh
```

Expected: all pre-checks pass, service restarts, ends active.

- [ ] **Step 11: End-to-end verification**

```bash
TOKEN=$(sudo bash -c '
export FLASK_SECRET=$(grep "^FLASK_SECRET=" /etc/harbor-dashboard.env | cut -d= -f2-)
export DASHBOARD_SECRET=$(grep "^DASHBOARD_SECRET=" /etc/harbor-dashboard.env | cut -d= -f2-)
export CUSTOMERS_LOG=/var/log/harbor-customers.json
cd /home/ubuntu/harbor-backend
python3 -c "
from harbor_lib.auth import make_token
print(make_token(\"tim@harborprivacy.com\", is_admin=False))
"
')
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard | grep -o "View Account\|View Add-Ons\|View Filters\|View Harbor Kids\|View Support\|Account Info\|Custom Rules\|Quick Profiles\|Blocked Services" | sort -u
```

Expected: `View Account`, `View Add-Ons`, `View Filters`, `View Harbor Kids`, `View Support` all present. `Account Info`, `Custom Rules`, `Quick Profiles`, `Blocked Services` all absent (confirming they moved out, not duplicated).

```bash
curl -s -b "hp_token=$TOKEN" http://127.0.0.1:7000/dashboard | grep -o 'nav-hamburger-btn\|href="/dashboard/account"\|href="/dashboard/addons"\|href="/dashboard/filters"\|href="/dashboard/kids"\|href="/dashboard/support"' | sort -u
```

Expected: all six present in the hamburger menu markup.

- [ ] **Step 12: Confirm a Light-plan render omits Harbor Kids from the menu**

Since minting a token only sets the email/is_admin claim, and the actual plan-type check happens against `find_customer`'s data, this check requires either a real Light-plan test customer or a temporary manual check: read the rendered `/dashboard` HTML for a known Light-plan account and confirm no `href="/dashboard/kids"` appears in its hamburger menu, while `/dashboard/addons`, `/dashboard/account`, `/dashboard/filters`, `/dashboard/support` still do. If no Light-plan test account exists, note this gap explicitly in the task report rather than skipping the check silently - do not fabricate a passing result.

- [ ] **Step 13: Visual check in a real browser**

Log in as a real account, click the hamburger, confirm it opens the dropdown, click outside, confirm it closes, click each of the 9 (or 8 for Light) links and confirm each one loads its page with that link visually marked active.

- [ ] **Step 14: Commit**

```bash
cd /home/ubuntu/harbor-backend
git add dashboard.py
git commit -m "Cut over main dashboard (Light plan) and NAV_CUSTOMER hamburger menu"
```

---

## Self-review notes (from writing this plan)

- **Spec coverage:** Goal 1 (main page keeps protection/stats/DNS setup) - Tasks 7-8. Goal 2 (five new pages) - Tasks 1-5. Goal 3 (shortcut cards) - Tasks 7-8. Goal 4 (hamburger, unified list) - Task 8. Goal 5 (Light plan gets the same treatment) - Task 8's Light branch plus every new route's `is_light_plan` handling. All five Non-goals are restated in Global Constraints and no task introduces a new API route, writes `harbor_kids`/`plan_type`, or touches `/settings`/`/dashboard/adblock`/`/dashboard/blocklists`/`/dashboard/screen-time`/admin pages.
- **Placeholder scan:** no TBD/TODO. Task 3's `toggleGroup` gap (flagged during initial plan-writing as a reconstruction needing verification) was resolved by checking the real implementation directly at `dashboard.py:676`: it's a global helper already defined in the shared `STYLE` block, present on every customer page, so `/dashboard/filters` doesn't define its own copy at all - the task now correctly omits it rather than reproducing a guess.
- **Type/name consistency:** `is_light_plan` is the exact name used everywhere it appears (Tasks 1-5's new routes, Task 7's `is_light_plan=False`, Task 8's `is_light_plan=True` and the `NAV_CUSTOMER` Jinja check) - no task introduces a differently-named or differently-typed variant. `active="account"`/`"addons"`/`"filters"`/`"kids"`/`"support"` string values match exactly between each new route's own kwarg and `NAV_CUSTOMER`'s corresponding `{{ 'active' if active == '...' else '' }}` check added in Task 8.
