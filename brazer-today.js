// Brazer Family — Today Widget
// Scriptable medium widget · upcoming reminders + pending to-dos
// CONFIG ─────────────────────────────────────────────────────────────
const BRAZER_KEY = "YOUR_BRAZER_WIDGET_KEY"
const BASE       = "https://start.brazer.us"
// ─────────────────────────────────────────────────────────────────────

const ACCENT  = new Color("#ff8c69")
const SAGE    = new Color("#5a9e64")
const MUTED   = new Color("#888888")
const URGENT  = new Color("#e76f51")
const BG      = new Color("#fff8f0")
const TEXT    = new Color("#2d2d2d")

async function fetchData() {
  try {
    const req = new Request(BASE + "/api/widget?k=" + BRAZER_KEY)
    return await req.loadJSON()
  } catch(e) { return { error: e.message } }
}

function fmtDt(iso) {
  const d = new Date(iso)
  const today = new Date(); today.setHours(0,0,0,0)
  const tom   = new Date(today); tom.setDate(tom.getDate()+1)
  if (d < tom && d >= today) return "Today " + d.toLocaleTimeString("en-US",{hour:"numeric",minute:"2-digit"})
  if (d < new Date(tom.getTime()+86400000)) return "Tomorrow " + d.toLocaleTimeString("en-US",{hour:"numeric",minute:"2-digit"})
  return d.toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"})
}

const w = new ListWidget()
w.backgroundColor = BG
w.setPadding(12, 14, 12, 14)
w.url = BASE

const d = await fetchData()

const hdr = w.addStack()
hdr.layoutHorizontally()
const t = hdr.addText("brazer/today")
t.font = Font.boldMonospacedSystemFont(10)
t.textColor = ACCENT
hdr.addSpacer()
const ts = hdr.addText(new Date().toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"}))
ts.font = Font.monospacedSystemFont(9)
ts.textColor = MUTED

w.addSpacer(8)

if (d.error) {
  const err = w.addText(d.error)
  err.font = Font.monospacedSystemFont(10)
  err.textColor = URGENT
} else {
  const reminders = d.reminders || []
  const todos     = d.todos     || []

  if (reminders.length) {
    const rl = w.addText("REMINDERS")
    rl.font = Font.boldMonospacedSystemFont(8)
    rl.textColor = MUTED
    w.addSpacer(3)
    for (const r of reminders.slice(0,3)) {
      const row = w.addStack()
      row.layoutHorizontally()
      row.spacing = 4
      const dot = row.addText("●")
      dot.font = Font.systemFont(8)
      dot.textColor = ACCENT
      const txt = row.addText(r.title)
      txt.font = Font.systemFont(11)
      txt.textColor = TEXT
      txt.lineLimit = 1
      row.addSpacer()
      const dt = row.addText(fmtDt(r.datetime))
      dt.font = Font.monospacedSystemFont(9)
      dt.textColor = MUTED
      w.addSpacer(2)
    }
  }

  if (todos.length) {
    w.addSpacer(6)
    const tl = w.addText("TO-DO (" + todos.length + " pending)")
    tl.font = Font.boldMonospacedSystemFont(8)
    tl.textColor = MUTED
    w.addSpacer(3)
    for (const t of todos.slice(0,3)) {
      const row = w.addStack()
      row.layoutHorizontally()
      row.spacing = 4
      const dot = row.addText("○")
      dot.font = Font.systemFont(8)
      dot.textColor = SAGE
      const txt = row.addText(t.text)
      txt.font = Font.systemFont(11)
      txt.textColor = TEXT
      txt.lineLimit = 1
      w.addSpacer(2)
    }
  }

  if (!reminders.length && !todos.length) {
    const empty = w.addText("All clear today ✓")
    empty.font = Font.systemFont(13)
    empty.textColor = SAGE
  }
}

Script.setWidget(w)
Script.complete()
w.presentMedium()
