// Harbor Privacy — MRR Widget
// Scriptable medium widget · shows live MRR, sub count, and top plan
// CONFIG ─────────────────────────────────────────────────────────────
const STRIPE_KEY = "YOUR_STRIPE_SECRET_KEY"
// ─────────────────────────────────────────────────────────────────────

const ACCENT = new Color("#00e5c0")
const MUTED  = new Color("#6b8a87")
const DANGER = new Color("#ff4e4e")
const BG     = new Color("#07090a")
const SURF   = new Color("#111618")

async function fetchMRR() {
  try {
    const req = new Request("https://api.stripe.com/v1/subscriptions?status=active&limit=100")
    req.headers = { Authorization: "Bearer " + STRIPE_KEY }
    const d = await req.loadJSON()
    if (d.error) throw new Error(d.error.message)
    let mrr = 0
    const plans = {}
    for (const s of d.data) {
      for (const i of s.items.data) {
        const p = i.price, a = i.quantity * p.unit_amount
        if (p.recurring.interval === "year")       mrr += a / 12
        else if (p.recurring.interval === "month") mrr += a
        else if (p.recurring.interval === "week")  mrr += a * 4.33
        const name = p.nickname || p.id
        plans[name] = (plans[name] || 0) + 1
      }
    }
    const topPlan = Object.entries(plans).sort((a,b)=>b[1]-a[1])[0]
    return { mrr: (mrr/100).toFixed(2), subs: d.data.length, topPlan: topPlan?.[0] || "—", topCount: topPlan?.[1] || 0 }
  } catch(e) { return { error: e.message } }
}

const w = new ListWidget()
w.backgroundColor = BG
w.setPadding(14, 16, 14, 16)
w.url = "https://dashboard.stripe.com"

const d = await fetchMRR()

const title = w.addText("harbor/mrr")
title.font = Font.boldMonospacedSystemFont(10)
title.textColor = MUTED

w.addSpacer(8)

if (d.error) {
  const err = w.addText(d.error)
  err.font = Font.regularMonospacedSystemFont(11)
  err.textColor = DANGER
} else {
  const mrrVal = w.addText("$" + d.mrr)
  mrrVal.font = Font.boldSystemFont(36)
  mrrVal.textColor = ACCENT
  mrrVal.minimumScaleFactor = 0.6

  w.addSpacer(4)

  const sub = w.addText(d.subs + " active subs · MRR")
  sub.font = Font.regularMonospacedSystemFont(11)
  sub.textColor = MUTED

  w.addSpacer(6)

  const plan = w.addText("top: " + d.topPlan + " (" + d.topCount + ")")
  plan.font = Font.regularMonospacedSystemFont(10)
  plan.textColor = new Color("#6b8a87")
  plan.lineLimit = 1
}

w.addSpacer()
const ts = w.addText("updated " + new Date().toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"}))
ts.font = Font.regularMonospacedSystemFont(9)
ts.textColor = new Color("#3a4a48")

Script.setWidget(w)
Script.complete()
w.presentMedium()
