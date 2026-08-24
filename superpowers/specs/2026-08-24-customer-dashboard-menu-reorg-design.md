# Customer Dashboard Menu Reorganization - Design

## Context

The main customer dashboard (`/dashboard` in `dashboard.py`) stacks every
account-management section on one long scrolling page. For a full/Remote
plan customer this is: protection status toggle, a locked-account overlay,
stats, an Account Info card, DNS setup (DoH address + Connection Check), a
trial-early-upgrade card, a monthly-to-annual upsell card, an Add-Ons card
(Family Safe toggle plus a Harbor VPN toggle-row), a Harbor Kids card, a
Custom Rules card, a Quick Profiles card, a Blocked Services card, and a
Harbor Scan cross-promo card. A separate, shorter template serves Harbor
Light plan customers: DNS setup, Connection Check, stats, a simplified
"Block or Allow a Site" tool, an "Upgrade to Harbor Remote" card, a Harbor
VPN card, a Support card, and a Settings card (three links out to
`/settings`).

The existing `NAV_CUSTOMER` nav bar already has a small dropdown ("Menu
▾") holding links to `/dashboard/adblock`, `/dashboard/blocklists`
(customer-facing pages built earlier), and two external links (Breach
Monitor, Harbor Scan). This spec moves most of the main dashboard's
sections into new pages reachable from that same menu, and makes the menu
itself more visually obvious.

## Goals

1. The main `/dashboard` page keeps only protection status, stats, and DNS
   setup (address plus Connection Check) - everything else moves to its own
   page.
2. Five new pages exist: Account, Add-Ons, Filters, Harbor Kids, Support.
3. The main page still shows a shortcut card per new page (not just menu
   entries), so nothing is hidden behind a click a returning customer
   wouldn't expect.
4. The nav menu trigger becomes a hamburger icon instead of a text link, and
   holds one unified list covering both the new pages and the links that
   already existed.
5. Harbor Light plan customers get the same treatment, scoped to the
   sections that apply to their plan.

## Non-goals

- No new business logic, no new data sources, no new API routes. Every new
  page relocates existing card markup and calls the same helper functions
  the main dashboard route already calls today (`get_client_stats_real`,
  `get_client_rules`, `has_family_addon`, `get_kids_profiles`,
  `get_all_blocked_services`, `get_client_blocked_services`,
  `get_doh_uptime_pct`, `find_customer`, `get_client`).
- No changes to `/settings`, `/dashboard/adblock`, `/dashboard/blocklists`,
  `/dashboard/screen-time`, or any admin page. They keep working exactly as
  they do today; the menu just links to them (some already did).
- Never write `harbor_kids` or `plan_type` - every new route only reads
  these fields, matching every existing customer route.
- No em dashes in any new copy or code comments.

## Architecture

### Two separate source templates, corrected understanding

The full/Remote plan and Harbor Light plan are two separate template
blocks inside the same `dashboard()` function (`dashboard.py`, Harbor Light
branch first, full-plan branch second, each ending in its own
`render_template_string` call). Their card inventories differ:

| Section | Full plan today | Harbor Light today |
|---|---|---|
| Account Info | Its own card | Does not exist |
| Settings links | Does not exist | Its own card (3 links) |
| Add-Ons | Family Safe toggle + Harbor VPN toggle-row, one card | N/A (no Family Safe on Light) |
| Harbor VPN | Folded into the Add-Ons card above | Its own card |
| Support | Does not exist | Its own card |
| Filters (Custom Rules / Quick Profiles / Blocked Services) | Three separate cards | One simplified "Block or Allow a Site" card |
| Harbor Kids | Its own card | N/A (not eligible on Light) |

Two full-plan-only sections were never discussed in the design conversation
and need a placement decision: the trial-early-upgrade card and the
monthly-to-annual upsell card. Judgment call, not directly confirmed by the
user: both stay on the main `/dashboard` page, unmoved, alongside the
Harbor Scan cross-promo card. These are promotional upsells rather than
account-management sections, and the main page is the highest-visibility
place for them. Flagged here for correction if wrong.

Because full plan has no existing Support card or Settings-links card, the
new `/dashboard/support` and `/dashboard/account` pages author that copy
fresh for full-plan customers, using the exact text Harbor Light's existing
Support and Settings cards already use. This is new markup, not new
behavior - same "Email Support" mailto link, same three settings links to
`/settings` and `/settings/data-request`.

Because Harbor Light has no existing Account Info card, the new
`/dashboard/account` page authors one for Light customers too, following
the same layout the full-plan Account Info card already uses (email, plan,
status, joined, last active) with a plan badge of "LIGHT".

### Every new page is an independent route

`/dashboard/adblock` and `/dashboard/blocklists` already establish the
pattern every new page follows: each route independently calls
`find_customer(request.user_email)`, computes its own `client_id`,
`is_active`, `plan_type`, `plan_badge`, `has_family_badge`, and other
locals it needs, and renders `STYLE + NAV_CUSTOMER + """html"""` via
`render_template_string`. New pages cannot reuse variables computed inside
`dashboard()` - they recompute the same handful of standard fields
themselves, exactly like the two existing independent pages already do.

### Main `/dashboard` page changes

**Full plan** keeps: header, protection status toggle, locked-account
overlay, stats, DNS setup card (DoH address + Connection Check),
trial-early-upgrade card, monthly-to-annual upsell card, Harbor Scan
cross-promo card. Removed from this page (moved to new pages): Account
Info, Add-Ons, Harbor Kids, Custom Rules, Quick Profiles, Blocked
Services. Added: five shortcut cards (Account, Add-Ons, Filters, Harbor
Kids, Support), styled as plain `.card` elements consistent with the rest
of the page, each a link to its new page. A shortcut card whose source
card had a `LOCKED` badge for inactive accounts (Add-Ons, Filters) keeps
that same badge treatment.

**Harbor Light** keeps: header, DNS setup card, Connection Check, stats,
the "Upgrade to Harbor Remote" card (stays inline, per explicit
instruction - Light's clearest conversion path stays on the page they
land on). Removed: Block or Allow a Site, Harbor VPN, Support, Settings.
Added: four shortcut cards (Account, Add-Ons, Filters, Support) - no
Harbor Kids shortcut, not eligible on this plan.

### Shortcut card copy

Each shortcut card on the main page uses the section name as its
`card-label` and a one-line description, with a link styled like the
page's existing `.btn`/`.ghost` links:

| Card | Label | Description | Link text |
|---|---|---|---|
| Account | Account | Your plan, status, and login settings | View Account &rarr; |
| Add-Ons | Add-Ons | Family Safe and Harbor VPN | View Add-Ons &rarr; |
| Filters | Filters | Custom rules and blocked services | View Filters &rarr; |
| Harbor Kids | Harbor Kids | Manage your child profiles | View Harbor Kids &rarr; |
| Support | Support | Get help with your account | View Support &rarr; |

Add-Ons and Filters keep the existing `{% if not is_active %}<span
class="badge badge-locked">LOCKED</span>{% endif %}` badge next to their
label on the shortcut card, matching the source card.

### Five new routes

All five follow `@app.route("/dashboard/<name>")`, `@login_required`,
`STYLE + NAV_CUSTOMER + """html"""`, `render_template_string`, matching
every existing customer page.

- **`/dashboard/account`** - Account Info card (full plan: same fields as
  today's card - email, plan, plan type, status, joined, last active,
  founder badge, family-safe badge; Light plan: same layout, new for this
  plan, badge "LIGHT") plus a Settings-links card (Change Password,
  Two-Factor Authentication, Download My Data) shown for both plans, same
  three links Light's existing Settings card already uses.
- **`/dashboard/addons`** - Full plan: the existing Add-Ons card as-is
  (Family Safe toggle + Harbor VPN toggle-row, `LOCKED` badge when
  inactive). Light plan: the existing Harbor VPN card as-is (Light has no
  Family Safe toggle - none is added).
- **`/dashboard/filters`** - Full plan: Custom Rules, Quick Profiles, and
  Blocked Services cards, each relocated as-is including their `LOCKED`
  badges and the JS functions they call (`addRule`, `removeRule`,
  `applyProfile`, `toggleService`, `toggleGroup`). Light plan: the "Block
  or Allow a Site" card as-is, including `lightAddRule`.
- **`/dashboard/kids`** - Full plan only. The Harbor Kids card as-is,
  including `addKidProfileCustomer` and the per-child profile markup. Not
  reachable on Light (not eligible); no Light-plan version of this page
  exists.
- **`/dashboard/support`** - Both plans: an Email Support card, same copy
  Light's existing Support card uses.

### Nav menu

`NAV_CUSTOMER`'s trigger changes from the text link `Menu ▾` to a
hamburger icon button, reusing the exact 3-line SVG icon `NAV_ADMIN`
already uses for `.hp-menu-btn`:

```html
<svg viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
```

This reuses the existing `.nav-drop` / `.nav-drop-menu` dropdown
mechanism unchanged - same toggle (`this.parentNode.classList.toggle
('open')`), same click-outside-close listener, same dropdown panel CSS.
Only the trigger element and the link list inside the panel change.
`NAV_ADMIN`'s separate fixed-sidebar mechanism (`.hp-sidebar`,
`hpSidebarToggle()`) is not used here - adopting it would convert the
whole customer layout to a sidebar, a bigger change than was asked for.

Unified menu list, full plan (9 items): Account, Add-Ons, Filters, Harbor
Kids, Support, Usage (renamed from "AdBlock Usage" per explicit
instruction to shorten it - same link, `/dashboard/adblock`), Blocklists
(only when `BLOCKLIST_SELECTION_ENABLED`, unchanged condition), Breach
Monitor (external, unchanged), Harbor Scan (external, unchanged).

Light plan menu: the same list minus Harbor Kids (8 items).

Every internal link gets its own explicit active-state check, following
the exact pattern the existing two links already use (`class="{{ 'active'
if active == 'adblock' else '' }}"`) - `NAV_CUSTOMER` has no generic
active-highlighting mechanism today, each link's check is written by
hand. Each new route passes `active="account"` / `"addons"` / `"filters"`
/ `"kids"` / `"support"` accordingly.

## Data flow

No new data flow. Every new page reads the same customer/client/AGH state
the main dashboard already reads today, through the same helper
functions, scoped down to just what that page's cards need. Writes
(toggling add-ons, adding rules, applying profiles, adding kid profiles)
go through the exact same existing API routes (`/api/addon`, `/api/rule`,
`/api/profile`, `/api/service`, `/api/pause`) unchanged - only the page
that renders the trigger button moves, not the endpoint it calls.

## Error handling

Unchanged from today's behavior, just relocated: inactive accounts see
the same `LOCKED` badges and disabled/grayed-out controls the current
cards already show, on whichever new page now hosts that card. No new
failure modes are introduced since no new business logic exists.

## Testing

No automated test suite exists in this repo. Verification is manual:

- For each new page: mint a session token for a real test account (the
  same technique used earlier this session - `harbor_lib.auth.make_token`
  with the real `DASHBOARD_SECRET` from `/etc/harbor-dashboard.env`), curl
  the page with that token as the `hp_token` cookie, and grep the response
  for the cards/badges/links expected on that page for both an active and
  an inactive test account, and for both plan types.
- Confirm the main `/dashboard` page for both plan types still renders
  protection status, stats, and DNS setup, plus exactly the right shortcut
  cards (5 for full plan, 4 for Light), and no longer renders the sections
  that moved out.
- Confirm the hamburger menu's HTML contains all 9 (full plan) or 8
  (Light) links, each pointing at the right URL, and that visiting each
  new page renders that page's link with the `active` class applied.
- Confirm every existing API route the relocated cards call
  (`/api/addon`, `/api/rule`, `/api/profile`, `/api/service`,
  `/api/pause`) still works unchanged by exercising one action per moved
  card against the test account.
- Visual check in a real browser: hamburger opens/closes on click and on
  click-outside, matches the existing dropdown's open/close behavior, and
  the shortcut cards render consistently with the rest of the page's
  `.card` styling.

## Deployment

Pure `dashboard.py` change - no AGH or Go binary involved. Deploy via
`/home/ubuntu/harbor-backend/check-dashboard.sh` followed by `sudo
systemctl restart harbor-dashboard`, per this repo's established rule
against a bare restart. This does not touch customer-facing DNS
infrastructure, so no separate production go-ahead gate is needed beyond
that pre-restart check passing.
