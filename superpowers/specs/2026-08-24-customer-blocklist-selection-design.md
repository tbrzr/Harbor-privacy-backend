# Customer Blocklist Selection — Design

## Context

Harbor Privacy's AdGuard Home fork (`adguard-private`, branch `bab`) shipped a
per-client blocklist tiers feature earlier this session: an admin can define
named tiers (subsets of the globally enabled blocklists) and assign one to a
client via `filter_tier`. It's built, tested, and deployed to the Pi and
vm3's `bab.service` (dev/staging instances) — never to the customer-facing
AGH instance at `/opt/AdGuardHome`.

This spec covers a *different* feature that reuses that same mechanism:
letting Harbor Privacy customers pick, for their own account, which
individual blocklists apply to their traffic — rather than an admin curating
a small number of named tiers customers choose from. Tim will keep adding
new blocklist sources to AGH's filter catalog over time; customers should
see the current catalog and toggle which lists they want, with a link back
to each list's original maintainer.

This is customer-facing, spans two codebases (`adguard-private` and
`harbor-backend`), and the second codebase's dashboard.py has its own
standing constraints (never touch `harbor_kids`/`plan_type` logic, no em
dashes in output, Python-only — HTML lives as inline template strings in
`.py` files, never separate `.html` template files).

## Goals

1. A customer can see every blocklist Tim has added to the customer-facing
   AGH instance, each with a link to its original source/maintainer.
2. A customer can toggle any subset of those lists on for their account.
3. The selection applies to every AGH client on that account — the main
   client and any Harbor Kids sub-profiles — confirmed explicitly: "the
   main account decides what all clients use for blocklists."
4. Many customers picking the same combination of lists must not each cost
   a separately-compiled filtering engine on the AGH side.
5. Two customers saving their selections around the same time must not
   corrupt each other's choice.

## Non-goals

- No per-kid-profile blocklist override. Kid profiles inherit whatever the
  main account selected; they don't get their own list picker.
- No change to the admin-facing tier UI in `client_v2` (built earlier this
  session). That UI keeps working exactly as-is for Tim's own admin-curated
  tiers; this feature is a second, independent consumer of the same
  `GET/POST /control/filtering/tiers` API.
- No new `adguard-private` backend code. The tier feature as already
  shipped is sufficient; only *how it's driven* is new, and that driving
  logic lives entirely in `harbor-backend`.
- No attribution metadata added to AGH's `Filter` schema. Attribution links
  are maintained as a small mapping inside `harbor-backend`, not inside the
  AGH fork's data model (see "Attribution links" below for why).

## Architecture

### Sub-project A: deploy the existing tier feature to the customer-facing AGH instance

The tier feature (`GET/POST /control/filtering/tiers`, `client.filter_tier`)
is unmodified — this is a deployment step, not new code. Same build already
sitting in `adguard-private`'s `bab` branch, same stop → backup → copy →
sha256-verify → start pattern used for the Pi and `bab.service` deploys
earlier this session, run against `/opt/AdGuardHome` (`AdGuardHome.service`,
admin port 8080) instead. This is the one genuinely risky step in this
whole feature — it's the first time this session touches the box real
customers' traffic goes through — and gets its own explicit go-ahead before
executing, separate from approving this spec.

### Sub-project B: harbor-backend customer UI + API

**Tier auto-naming and dedup.** Instead of an admin typing a tier name,
tiers created by this feature are named deterministically from their
content: `cust-{sha256(sorted(filter_ids))[:16]}`. Two customers who pick
the identical set of lists resolve to the identical tier name and therefore
share one compiled engine on the AGH side — the number of distinct
compiled engines scales with the number of *unique combinations* customers
actually choose, not the number of customers. This also satisfies the
existing tier feature's own constraint that tier names are immutable and
never reused for a different meaning: a hash-named tier's content is
exactly what its name commits to, by construction.

**Concurrency.** `harbor-dashboard.service` runs `python3 dashboard.py`
directly (see `/etc/systemd/system/harbor-dashboard.service`) — no
gunicorn, no `--workers`, and `app.run(...)` at the bottom of `dashboard.py`
doesn't pass `threaded=True`, so Werkzeug's dev server processes one
request at a time today. That already prevents the two-customers-race
scenario, but it's an implicit property of how the app happens to be run,
not a documented guarantee. A new module-level `threading.Lock()` guards
the read-modify-write of the tier array explicitly, so the safety doesn't
silently disappear if someone later adds `threaded=True` or moves this
service to gunicorn with multiple workers.

**Find-or-create flow**, run under the lock:
1. `agh_get("/control/filtering/tiers")` → current tier array.
2. Compute the hash-name for the customer's requested `filter_ids`.
3. If a tier with that name already exists, reuse it (no-op write).
4. Otherwise append `{"name": hash_name, "filter_ids": filter_ids}` and
   `agh_post("/control/filtering/set_tiers", tiers)`.

**Fan-out to the account's clients.** After the tier exists, assign
`filter_tier = hash_name` to the customer's main client and every Harbor
Kids sub-profile via the same `agh_post("/control/clients/update", ...)`
pattern `set_client_blocked_services` already uses — read the client,
spread its existing fields, overwrite `filter_tier`, post the whole object
back. Kid profiles are discovered the same way `get_kids_profiles(client_id)`
already does (name prefix match on `{client_id}kid`).

**Storing the customer's own selection.** The raw `filter_ids` list the
customer picked is written onto their record in `CUSTOMERS_LOG`
(`/var/log/harbor-customers.json`) as a new field, `selected_filter_ids`,
using the exact same read-all-lines/rewrite-matching-line pattern
`save_active_profile`/`save_profile_snapshot` already use. This is what the
picker page reads back to pre-check the customer's current selection — it's
the source of truth for "what did this customer choose," independent of
which hash-named tier currently backs it, so a hash collision or a future
change to the naming scheme can never strand a customer's actual intent.

**Attribution links.** A plain Python dict in `harbor-backend`,
`BLOCKLIST_SOURCES = {"<AGH filter URL>": "<link to the list's own page>"}`,
maintained by hand alongside adding each new list to AGH — the same moment
Tim already has that information, so there's nothing new to remember
separately. Deliberately not a new field on AGH's `Filter` struct: that
would mean keeping a schema change in sync between the fork's admin UI and
this customer picker for a value only the customer picker ever displays.
A dict is enough given the catalog only grows one entry at a time, by hand.

**Customer-facing page.** New route `/dashboard/blocklists` (mirrors the
existing `/dashboard/adblock` route's shape: `@login_required`,
`find_customer(request.user_email)`, `NAV_CUSTOMER` + inline HTML string
via `render_template_string`, same `STYLE`/badge/nav conventions). Lists
every currently-enabled filter from `agh_get("/control/filtering/status")`
(reusing what's already fetched for the admin Blocklists page, not
`querylog`), each row showing the list's name, its attribution link from
`BLOCKLIST_SOURCES` when present, and a checkbox pre-checked against the
customer's stored `selected_filter_ids`. A save button posts to a new
`POST /api/blocklists` route (`@login_required`, same shape as the existing
`/api/pause` and `/api/addon` routes) that runs the find-or-create-and-assign
flow above. Add a "Blocklists" entry to `NAV_CUSTOMER`'s dropdown, next to
the existing "AdBlock Usage" link.

## Data flow

```
Customer checks/unchecks lists on /dashboard/blocklists
  → POST /api/blocklists {filter_ids: [...]}
    → save selected_filter_ids onto the customer's CUSTOMERS_LOG record
    → [under lock] find-or-create hash-named tier via
      GET/POST /control/filtering/tiers
    → assign filter_tier to main client + all kid profiles via
      POST /control/clients/update (once per client)
  → 200 OK, page re-renders with the saved selection
```

## Error handling

- `agh_get`/`agh_post` already degrade gracefully (cached snapshot on read
  failure, `False` return on write failure) — the new code surfaces a
  failed save as a plain error state on the page rather than silently
  reporting success, matching how `/api/pause` and `/api/addon` already
  handle `agh_post` returning `False`.
- If fan-out partially fails (main client updates, a kid profile's update
  call fails), the customer's `selected_filter_ids` in `CUSTOMERS_LOG` is
  still the source of truth — a retry (re-saving the same selection) is
  idempotent and will re-attempt every client's update.
- Empty selection (customer unchecks everything) is allowed and maps to
  `filter_tier: ""` on their clients — global default filtering, same
  meaning it already has everywhere else in this fork.

## Testing

`harbor-backend` has no existing automated test suite (confirmed: no
`pytest`/`unittest` files in the repo). This feature follows the repo's
existing verification convention instead: manual verification against a
real customer account (or a disposable test account) after deploying to
`harbor-dashboard.service`, checking:
- The picker page renders the current AGH filter catalog with attribution
  links where `BLOCKLIST_SOURCES` has an entry.
- Saving a selection creates exactly one tier (verified via
  `GET /control/filtering/tiers`) and assigns it to the account's main
  client and every kid profile (verified via `GET /control/clients`).
- Saving the identical selection from a second test account reuses the
  same tier name — no duplicate tier created.
- `dig`-based DNS resolution check against the customer AGH instance
  confirms the selected lists are actually being enforced for that
  client's IP, matching the verification pattern used for the tier
  feature's own backend plan earlier this session.

## Deployment

1. Sub-project A ships first and independently — it's a deploy of
   already-shipped code, gated on its own explicit go-ahead given the
   target is customer-facing production.
2. Sub-project B ships once A is live: new routes in `dashboard.py`,
   `sudo systemctl restart harbor-dashboard`, then the manual verification
   above.
3. After both are live and verified, Tim sends the customer announcement
   email about the new self-service list selection — a separate, later,
   non-code step, not part of this implementation.
