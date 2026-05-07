// Harbor Privacy — Fax Volume Widget
// Scriptable medium widget · this month vs last month
// CONFIG ─────────────────────────────────────────────────────────────
const TELNYX_KEY = "YOUR_TELNYX_API_KEY"
// ─────────────────────────────────────────────────────────────────────

const ACCENT = new Color("#00d4ff")
const MUTED  = new Color("#6b8a87")
const DANGER = new Color("#ff4e4e")
const GREEN  = new Color("#00e5c0")
const BG     = new Color("#07090a")

async function fetchFax() {
  try {
    const now   = new Date()
    const thisStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()
    const lastStart = new Date(now.getFullYear(), now.getMonth()-1, 1).toISOString()
    const lastEnd   = thisStart
    const headers   = { Authorization: "Bearer " + TELNYX_KEY }
    const [r1, r2] = await Promise.all([
      new Request("https://api.telnyx.com/v2/faxes?filter[created_at][gte]=" + thisStart + "&page[size]=100"),
      new Request("https://api.telnyx.com/v2/faxes?filter[created_at][gte]=" + lastStart + "&filter[created_at][lt]=" + lastEnd + "&page[size]=100")
    ].map(r => { r.headers = headers; return r.loadJSON() }))
    if (r1.errors) throw new Error(r1.errors[0].detail)
    return { thisMonth: r1.data?.length ?? 0, lastMonth: r2.data?.length ?? 0 }
  } catch(e) { return { error: e.message } }
}

const w = new ListWidget()
w.backgroundColor = BG
w.setPadding(14, 16, 14, 16)
w.url = "https://fax.harborprivacy.com"

const d = await fetchFax()

const title = w.addText("harbor/fax")
title.font = Font.boldMonospacedSystemFont(10)
title.textColor = MUTED

w.addSpacer(8)

if (d.error) {
  const err = w.addText(d.error)
  err.font = Font.monospacedSystemFont(11)
  err.textColor = DANGER
} else {
  const val = w.addText(String(d.thisMonth))
  val.font = Font.boldSystemFont(48)
  val.textColor = ACCENT

  w.addSpacer(2)

  const label = w.addText("faxes this month")
  label.font = Font.monospacedSystemFont(11)
  label.textColor = MUTED

  w.addSpacer(6)

  const diff = d.thisMonth - d.lastMonth
  const diffStr = (diff >= 0 ? "+" : "") + diff + " vs last month (" + d.lastMonth + ")"
  const cmp = w.addText(diffStr)
  cmp.font = Font.monospacedSystemFont(10)
  cmp.textColor = diff >= 0 ? GREEN : DANGER
}

w.addSpacer()
const ts = w.addText("updated " + new Date().toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"}))
ts.font = Font.monospacedSystemFont(9)
ts.textColor = new Color("#3a4a48")

Script.setWidget(w)
Script.complete()
w.presentMedium()
