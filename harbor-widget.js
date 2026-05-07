// Harbor Privacy — iOS Status Widget
// Install: Scriptable app → paste this script → add Medium widget to home screen
// Widget param: leave blank for all services

const BASE = "https://start.harborprivacy.com"
const F2B_KEY = "Zdxm6giU-EjMHIR8uOt2GK0ibTEbq2cm"
const ACCENT = new Color("#00e5c0")
const DANGER = new Color("#ff4e4e")
const WARN   = new Color("#f59e0b")
const MUTED  = new Color("#6b8a87")
const BG     = new Color("#07090a")
const SURF   = new Color("#111618")

const SERVERS = [
  { id: "doh",    label: "DoH",     url: "https://doh.harborprivacy.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", accept: "application/dns-message" },
  { id: "vm3",    label: "VM3",     url: "https://harborprivacy.com" },
  { id: "brazer", label: "Brazer",  url: "https://start.brazer.us" },
  { id: "book",   label: "Booking", url: "https://booking.harborprivacy.com" },
  { id: "fax",    label: "Fax",     url: "https://fax.harborprivacy.com" },
  { id: "career", label: "Career",  url: "https://career.harborprivacy.com" },
]

async function ping(server) {
  const t0 = Date.now()
  try {
    const req = new Request(server.url)
    req.method = "HEAD"
    req.timeoutInterval = 6
    if (server.accept) req.headers = { Accept: server.accept }
    await req.load()
    return { ok: true, ms: Date.now() - t0 }
  } catch {
    return { ok: false, ms: Date.now() - t0 }
  }
}

async function fetchJSON(path) {
  try {
    const req = new Request(BASE + path + "?k=" + F2B_KEY + "&_=" + Date.now())
    return await req.loadJSON()
  } catch { return null }
}

async function main() {
  const [f2b3, f2b1, ...pings] = await Promise.all([
    fetchJSON("/fail2ban.json"),
    fetchJSON("/vm1-fail2ban.json"),
    ...SERVERS.map(s => ping(s))
  ])

  const vm1Age = f2b1?.updated
    ? (Date.now() - new Date(f2b1.updated).getTime()) / 60000
    : 999
  const vm1Ok = vm1Age < 15

  const w = new ListWidget()
  w.backgroundColor = BG
  w.setPadding(12, 14, 12, 14)

  // Title row
  const titleRow = w.addStack()
  titleRow.layoutHorizontally()
  titleRow.centerAlignContent()
  const title = titleRow.addText("harbor/privacy")
  title.font = Font.boldMonospacedSystemFont(11)
  title.textColor = ACCENT
  titleRow.addSpacer()
  const ts = titleRow.addText(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }))
  ts.font = Font.regularMonospacedSystemFont(10)
  ts.textColor = MUTED

  w.addSpacer(6)

  // Server dots row
  const dotsStack = w.addStack()
  dotsStack.layoutHorizontally()
  dotsStack.spacing = 6

  const serverResults = pings
  SERVERS.forEach((s, i) => {
    const col = dotsStack.addStack()
    col.layoutVertically()
    col.spacing = 2

    const dot = col.addText(serverResults[i].ok ? "●" : "●")
    dot.font = Font.systemFont(10)
    dot.textColor = serverResults[i].ok ? ACCENT : DANGER

    const lbl = col.addText(s.label)
    lbl.font = Font.regularMonospacedSystemFont(8)
    lbl.textColor = MUTED
  })

  // VM1 dot
  dotsStack.addSpacer(2)
  const vm1col = dotsStack.addStack()
  vm1col.layoutVertically()
  vm1col.spacing = 2
  const vm1dot = vm1col.addText("●")
  vm1dot.font = Font.systemFont(10)
  vm1dot.textColor = vm1Ok ? ACCENT : (vm1Age < 30 ? WARN : DANGER)
  const vm1lbl = vm1col.addText("VM1")
  vm1lbl.font = Font.regularMonospacedSystemFont(8)
  vm1lbl.textColor = MUTED

  dotsStack.addSpacer()

  w.addSpacer(8)

  // Fail2ban row
  const f2bRow = w.addStack()
  f2bRow.layoutHorizontally()
  f2bRow.spacing = 4

  function f2bChip(label, banned, failed) {
    const chip = f2bRow.addStack()
    chip.layoutVertically()
    chip.spacing = 1
    const lbl = chip.addText(label)
    lbl.font = Font.regularMonospacedSystemFont(8)
    lbl.textColor = MUTED
    const val = chip.addText(`${banned}ban ${failed}fail`)
    val.font = Font.boldMonospacedSystemFont(9)
    val.textColor = banned > 0 ? DANGER : ACCENT
  }

  if (f2b3) f2bChip("VM3", f2b3.banned ?? 0, f2b3.failed ?? 0)
  f2bRow.addSpacer(8)
  if (f2b1?.updated) f2bChip("VM1", f2b1.banned ?? 0, f2b1.failed ?? 0)
  f2bRow.addSpacer()

  // Tap → open dashboard
  w.url = BASE

  Script.setWidget(w)
  Script.complete()
  w.presentMedium()
}

await main()
