// Brazer Family — Bills Due Widget
// Scriptable small/medium widget · bills due in the next 7 days
// CONFIG ─────────────────────────────────────────────────────────────
const BRAZER_KEY = "YOUR_BRAZER_WIDGET_KEY"
const BASE       = "https://start.brazer.us"
// ─────────────────────────────────────────────────────────────────────

const ACCENT = new Color("#ff8c69")
const URGENT = new Color("#e76f51")
const WARN   = new Color("#e09c2a")
const SAGE   = new Color("#5a9e64")
const MUTED  = new Color("#888888")
const BG     = new Color("#fff8f0")
const TEXT   = new Color("#2d2d2d")

async function fetchData() {
  try {
    const req = new Request(BASE + "/api/widget?k=" + BRAZER_KEY)
    return await req.loadJSON()
  } catch(e) { return { error: e.message } }
}

const w = new ListWidget()
w.backgroundColor = BG
w.setPadding(12, 14, 12, 14)
w.url = BASE

const d = await fetchData()

const hdr = w.addStack()
hdr.layoutHorizontally()
const title = hdr.addText("brazer/bills")
title.font = Font.boldMonospacedSystemFont(10)
title.textColor = ACCENT
hdr.addSpacer()
const ts = hdr.addText("next 7d")
ts.font = Font.regularMonospacedSystemFont(9)
ts.textColor = MUTED

w.addSpacer(8)

if (d.error) {
  const err = w.addText(d.error)
  err.font = Font.regularMonospacedSystemFont(10)
  err.textColor = URGENT
} else {
  const bills = d.urgent_bills || []
  if (!bills.length) {
    const ok = w.addText("No bills due soon ✓")
    ok.font = Font.systemFont(12)
    ok.textColor = SAGE
  } else {
    for (const b of bills) {
      const row = w.addStack()
      row.layoutHorizontally()
      row.spacing = 6
      const name = row.addText(b.name)
      name.font = Font.systemFont(11)
      name.textColor = TEXT
      name.lineLimit = 1
      row.addSpacer()
      const days = b.days_until
      const daysColor = days <= 2 ? URGENT : days <= 5 ? WARN : MUTED
      const daysLabel = days === 0 ? "TODAY" : days + "d"
      const daysEl = row.addText(daysLabel)
      daysEl.font = Font.boldMonospacedSystemFont(10)
      daysEl.textColor = daysColor
      if (b.amount) {
        const amt = w.addText("$" + b.amount + "/mo")
        amt.font = Font.regularMonospacedSystemFont(9)
        amt.textColor = MUTED
      }
      w.addSpacer(4)
    }
  }
}

Script.setWidget(w)
Script.complete()
w.presentMedium()
