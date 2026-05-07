// Brazer Family — Updates Widget
// Scriptable medium widget · latest family updates feed
// CONFIG ─────────────────────────────────────────────────────────────
const BRAZER_KEY = "YOUR_BRAZER_WIDGET_KEY"
const BASE       = "https://start.brazer.us"
// ─────────────────────────────────────────────────────────────────────

const TIM_CLR     = new Color("#1a56db")
const MEAGHAN_CLR = new Color("#9b1fbd")
const ACCENT      = new Color("#ff8c69")
const MUTED       = new Color("#888888")
const URGENT      = new Color("#e76f51")
const BG          = new Color("#fff8f0")
const TEXT        = new Color("#2d2d2d")

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
const title = hdr.addText("brazer/updates")
title.font = Font.boldMonospacedSystemFont(10)
title.textColor = ACCENT
hdr.addSpacer()
const ts = hdr.addText(new Date().toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"}))
ts.font = Font.monospacedSystemFont(9)
ts.textColor = MUTED

w.addSpacer(8)

if (d.error) {
  const err = w.addText(d.error)
  err.font = Font.monospacedSystemFont(10)
  err.textColor = URGENT
} else {
  const updates = d.updates || []
  if (!updates.length) {
    const empty = w.addText("No updates yet.")
    empty.font = Font.systemFont(12)
    empty.textColor = MUTED
  } else {
    for (const u of updates.slice(0,3)) {
      const authorColor = u.author === "Tim" ? TIM_CLR : u.author === "Meaghan" ? MEAGHAN_CLR : MUTED
      const row = w.addStack()
      row.layoutHorizontally()
      row.spacing = 5
      const chip = row.addText(u.author)
      chip.font = Font.boldMonospacedSystemFont(9)
      chip.textColor = authorColor
      if (u.flag) {
        const flag = row.addText("🚩")
        flag.font = Font.systemFont(9)
      }
      w.addSpacer(2)
      const msg = w.addText(u.message)
      msg.font = Font.systemFont(11)
      msg.textColor = TEXT
      msg.lineLimit = 2
      const meta = w.addText(u.timestamp)
      meta.font = Font.monospacedSystemFont(9)
      meta.textColor = MUTED
      w.addSpacer(6)
    }
  }
}

Script.setWidget(w)
Script.complete()
w.presentMedium()
