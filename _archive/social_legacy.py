# Archived from dashboard.py on 2026-06-04
# Legacy social generator UI + OpenAI image fallback, retired when /social became send-history.


# ===== _generate_image_openai (was lines 3585-3657) =====

def _generate_image_openai(brand, topic):
    if not SOCIAL_IMAGES_ENABLED:
        return None
    import requests as _req
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if not openai_key:
        return None
    import random as _random
    scenes = {
        "career": [
            f"Photorealistic lifestyle photograph, young professional woman reviewing documents at a bright cafe table, coffee and laptop nearby, confident optimistic mood, natural light, cinematic, topic: {topic}",
            f"Photorealistic lifestyle photograph, man in business casual at a standing desk in a modern open office, looking confident, warm light, shallow depth of field, topic: {topic}",
            f"Photorealistic lifestyle photograph, person celebrating at their desk, fist pump moment, home office with plants and natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, close-up of hands typing on a laptop on a clean wooden desk, coffee mug and notebook beside it, warm morning light, topic: {topic}",
            f"Photorealistic lifestyle photograph, diverse professional team in a bright modern conference room, collaborative mood, natural light, topic: {topic}",
        ],
        "fax": [
            f"Photorealistic lifestyle photograph, doctor's office reception desk, medical folders and forms organized neatly, calm clinical atmosphere, soft light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person's hands on a clean desk beside an envelope and printed document, private calm atmosphere, soft sidelight, topic: {topic}",
            f"Photorealistic lifestyle photograph, attorney's office desk with legal documents, pen and coffee, professional serious mood, warm lamp light, topic: {topic}",
            f"Photorealistic lifestyle photograph, medical records room, organized filing system, clean and professional, soft overhead light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person at a home desk carefully folding a document into an envelope, focused calm expression, natural window light, topic: {topic}",
        ],
        "booking": [
            f"Photorealistic lifestyle photograph, modern hair salon interior, stylists working with clients in background, clean bright atmosphere, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, busy restaurant front of house, host stand with organized reservation book, warm evening light, topic: {topic}",
            f"Photorealistic lifestyle photograph, yoga studio reception area, clean minimal desk, plants and natural light, welcoming calm atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, small medical clinic waiting room, organized and welcoming, warm light, a receptionist at the desk smiling, topic: {topic}",
            f"Photorealistic lifestyle photograph, spa reception desk with candles and fresh flowers, elegant calm atmosphere, warm soft light, topic: {topic}",
            f"Photorealistic lifestyle photograph, auto repair shop front desk, organized professional, owner smiling confidently, topic: {topic}",
        ],
        "tim": [
            f"Photorealistic lifestyle photograph, healthcare administrator walking confidently through a hospital corridor, professional attire, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, medical office manager at a desk reviewing printed reports, focused professional expression, warm light, topic: {topic}",
            f"Photorealistic lifestyle photograph, healthcare team huddle in a bright conference room, collaborative leadership mood, topic: {topic}",
            f"Photorealistic lifestyle photograph, radiology department hallway, professional in scrubs walking purposefully, clean clinical light, topic: {topic}",
            f"Photorealistic lifestyle photograph, hospital administrator shaking hands with a colleague, confident professional setting, natural light, topic: {topic}",
        ],
        "harbor": [
            f"Photorealistic lifestyle photograph, family watching TV together in a cozy living room, warm evening light, relaxed safe atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, parent helping child with homework on a kitchen table, warm home environment, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person relaxing on a couch with a book, phone face-down on coffee table, calm private mood, warm lamp light, topic: {topic}",
            f"Photorealistic lifestyle photograph, home office setup, person working focused at a clean desk, plants and natural light, peaceful productive atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, couple sitting together at a kitchen table with coffee, comfortable home morning atmosphere, warm natural light, topic: {topic}",
        ],
        "auto": [
            f"Photorealistic lifestyle photograph, minimal modern workspace, person focused at a clean desk, coffee and plant, natural morning light, topic: {topic}",
            f"Photorealistic lifestyle photograph, entrepreneur at a standing desk in a bright loft office, confident mood, topic: {topic}",
            f"Photorealistic lifestyle photograph, clean home office with organized bookshelf, person typing at laptop, warm focused atmosphere, topic: {topic}",
        ],
    }
    scene_list = scenes.get(brand, scenes["harbor"])
    img_prompt = _random.choice(scene_list)
    try:
        r = _req.post("https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"},
            json={"model": "gpt-image-1", "prompt": img_prompt, "n": 1, "size": "1024x1024", "quality": "medium"},
            timeout=90)
        import base64 as _b64, time as _t, pathlib
        resp_json = r.json()
        if "error" in resp_json:
            import logging; logging.getLogger(__name__).error(f"OpenAI image error: {resp_json['error']}")
            return None
        img_b64 = resp_json["data"][0]["b64_json"]
        img_data = _b64.b64decode(img_b64)
        img_dir = pathlib.Path("/var/www/network/social-images")
        img_dir.mkdir(exist_ok=True)
        fname = f"social-{brand}-{int(_t.time())}.png"
        (img_dir / fname).write_bytes(img_data)
        return f"https://dashboard.harborprivacy.com/social-images/{fname}"
    except Exception:
        return None


# ===== SOCIAL_HTML (was lines 4304-5265) =====

SOCIAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>Social Scheduler -- Harbor Privacy</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<script defer src="https://stats.harborprivacy.com/script.js" data-website-id="51ad61cf-3e3b-4d74-818b-98df4af99183"></script>
<link rel="manifest" href="/social-app.webmanifest">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="HP Social">
<meta name="theme-color" content="#00e5c0">
<link rel="apple-touch-icon" href="/social-icon-192.png">
<script>
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/social-sw.js").catch(function(){});
}
(function(){
  var TOKEN = "{{ csrf_token }}";
  window.__CSRF = TOKEN;
  var _f = window.fetch;
  window.__originalFetch = _f;
  window.__refreshCSRF = async function(){
    try {
      var r = await _f("/api/csrf", {credentials:"same-origin"});
      var j = await r.json();
      if (j && j.csrf) { window.__CSRF = j.csrf; return j.csrf; }
    } catch(e){}
    return "";
  };
  window.fetch = async function(url, opts){
    opts = opts || {};
    var m = (opts.method || 'GET').toUpperCase();
    if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') {
      var u = String(url || '');
      if (u.charAt(0) === '/' || u.indexOf(location.origin) === 0) {
        opts.headers = opts.headers || {};
        var cur = window.__CSRF || "";
        if (!cur) cur = await window.__refreshCSRF();
        if (!opts.headers['X-CSRF'] && !opts.headers['x-csrf']) opts.headers['X-CSRF'] = cur;
        if (!opts.headers['X-CSRF']) opts.headers['X-CSRF'] = cur;
        if (opts.credentials === undefined) opts.credentials = 'same-origin';
        var resp = await _f(url, opts);
        if (resp.status === 403) {
          var fresh = await window.__refreshCSRF();
          if (fresh) {
            opts.headers['X-CSRF'] = fresh;
            return _f(url, opts);
          }
        }
        return resp;
      }
    }
    return _f(url, opts);
  };
})();
</script>
<style>
:root{--bg:#0a0e0f;--surface:#111618;--border:#1e2a2d;--accent:#00e5c0;--text:#e8f0ef;--muted:#6b8a87;--accent-hover:#00ffda;}
.career-mode{--bg:#f7f9f8;--surface:#ffffff;--border:#d4e8e2;--accent:#34d399;--text:#0f2921;--muted:#4b7263;}
.tim-mode{--bg:#0f1923;--surface:#121e28;--border:#1e3040;--accent:#4a9edd;--text:#e8eef3;--muted:#7a9bb5;}
.booking-mode{--bg:#0f0e09;--surface:#1a1700;--border:#2a2510;--accent:#f59e0b;--text:#f5f0e8;--muted:#8a7d5a;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:"DM Sans",sans-serif;line-height:1.7;transition:background 0.3s,color 0.3s;}
body::before{content:"";position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:0.3;pointer-events:none;z-index:0;}
nav{padding:0;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;background:var(--surface);}
.nav-top{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);}
.logo{font-family:"DM Mono",monospace;font-size:14px;color:var(--accent);letter-spacing:0.1em;text-decoration:none;}
.logo span{color:var(--muted);}
.nav-links{display:flex;gap:20px;align-items:center;padding:10px 24px;}
.nav-links a{font-family:"DM Mono",monospace;font-size:11px;color:var(--muted);text-decoration:none;letter-spacing:0.06em;}
.nav-links a:hover,.nav-links a.active{color:var(--accent);}
.badge-admin{background:#7c3aed;color:#fff;font-family:"DM Mono",monospace;font-size:9px;padding:2px 8px;letter-spacing:0.1em;}
.container{max-width:860px;margin:0 auto;padding:32px 20px;position:relative;z-index:1;}
h1{font-family:"DM Serif Display",serif;font-size:34px;font-weight:400;margin-bottom:6px;}
.sub{color:var(--muted);font-size:14px;margin-bottom:28px;}
.card{background:var(--surface);border:1px solid var(--border);padding:24px;margin-bottom:20px;border-radius:10px;}
label{font-family:"DM Mono",monospace;font-size:11px;color:var(--accent);letter-spacing:0.15em;display:block;margin-bottom:10px;}
input,textarea,select{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:"DM Mono",monospace;font-size:13px;padding:10px 14px;margin-bottom:16px;outline:none;border-radius:2px;}
input:focus,textarea:focus{border-color:var(--accent);}
.btn{background:var(--accent);color:var(--bg);border:none;padding:14px 28px;font-family:"DM Mono",monospace;font-size:13px;letter-spacing:0.08em;cursor:pointer;font-weight:700;border-radius:8px;transition:opacity 0.2s;}
.btn:hover{opacity:0.88;}
.btn:disabled{background:var(--muted);cursor:not-allowed;opacity:0.6;}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);padding:12px 20px;font-family:"DM Mono",monospace;font-size:11px;cursor:pointer;border-radius:2px;transition:all 0.2s;}
.btn-outline:hover{border-color:var(--accent);color:var(--accent);}
.btn-copy{background:transparent;border:1px solid var(--accent);color:var(--accent);padding:10px 18px;font-family:"DM Mono",monospace;font-size:11px;cursor:pointer;border-radius:2px;margin-top:8px;transition:background 0.2s;}
.btn-copy:hover{background:rgba(0,229,192,0.08);}
.btn-linkedin{background:#0a66c2;color:#fff;border:none;padding:14px 24px;font-family:"DM Mono",monospace;font-size:11px;letter-spacing:0.08em;cursor:pointer;border-radius:2px;display:inline-flex;align-items:center;gap:8px;font-weight:600;transition:background 0.2s;}
.btn-linkedin:hover{background:#0958a8;}
.btn-linkedin svg{width:16px;height:16px;fill:#fff;flex-shrink:0;}
.post-box{background:var(--bg);border:1px solid var(--border);padding:16px;font-size:14px;color:var(--text);line-height:1.7;white-space:pre-wrap;min-height:80px;margin-bottom:8px;border-radius:2px;cursor:text;}
.post-box:focus{outline:1px solid var(--accent);}
.img-preview{width:100%;max-width:360px;border:1px solid var(--border);display:block;margin:12px 0;border-radius:2px;}
.platform-label{font-family:"DM Mono",monospace;font-size:10px;color:var(--muted);letter-spacing:0.15em;margin-bottom:8px;}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;vertical-align:middle;margin-right:8px;}
@keyframes spin{to{transform:rotate(360deg);}}
.topics{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;}
.topic-chip{background:transparent;border:1px solid var(--border);color:var(--muted);padding:9px 16px;font-family:"DM Mono",monospace;font-size:12px;cursor:pointer;letter-spacing:0.04em;border-radius:8px;transition:all 0.15s;}
.topic-chip:hover,.topic-chip.selected{border-color:var(--accent);color:var(--accent);background:rgba(0,229,192,0.05);}
.brand-switcher{display:grid;grid-template-columns:repeat(5,1fr);gap:0;margin-bottom:28px;border:1px solid var(--border);border-radius:10px;overflow:hidden;}
.brand-btn{padding:13px 6px;font-family:"DM Mono",monospace;font-size:11px;letter-spacing:0.06em;cursor:pointer;border:none;border-right:1px solid var(--border);background:transparent;color:var(--muted);transition:all 0.2s;white-space:nowrap;}
.brand-btn:last-child{border-right:none;}
.brand-btn.active{background:var(--accent);color:var(--bg);font-weight:600;}
.platform-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);}
.platform-row:last-child{border-bottom:none;}
.platform-name{font-size:14px;color:var(--text);display:flex;align-items:center;gap:8px;}
.platform-icon{font-size:16px;}
.toggle-btn{font-family:"DM Mono",monospace;font-size:10px;padding:6px 16px;border:1px solid var(--accent);color:var(--accent);background:transparent;cursor:pointer;border-radius:2px;letter-spacing:0.1em;transition:all 0.2s;min-width:48px;}
.toggle-btn.off{border-color:var(--border);color:var(--muted);}
.results-grid{display:grid;gap:20px;}
.platform-card{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:18px;}
.action-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:20px;padding-top:20px;border-top:1px solid var(--border);}
.status-msg{font-family:monospace;font-size:12px;color:var(--muted);flex:1;min-width:0;}
.status-msg.ok{color:var(--accent);}
.status-msg.err{color:#f87171;}
.autopost-bar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;}
.char-count{font-family:"DM Mono",monospace;font-size:10px;color:var(--muted);text-align:right;margin-top:4px;}
</style>

<style id="hp-injected-styles">

@supports(padding:env(safe-area-inset-bottom)){}



@media print{}

/* Dashboard bottom tab bar (fix: override element selector nav{position:sticky;top:0}) */
:root{--hp-bnav-h:0px;}
@media all and (display-mode:standalone) and (max-width:768px){:root{--hp-bnav-h:108px;}}
nav.hp-bottom-tabs{display:none;position:fixed !important;top:auto !important;left:0 !important;right:0 !important;bottom:0 !important;border-bottom:0 !important;background:rgba(17,22,24,0.96) !important;border-top:1px solid #1e2a2d !important;padding:6px 4px calc(6px + env(safe-area-inset-bottom)) 4px !important;justify-content:space-around !important;align-items:stretch !important;z-index:60 !important;backdrop-filter:saturate(160%) blur(14px);-webkit-backdrop-filter:saturate(160%) blur(14px);}
@media all and (display-mode:standalone) and (max-width:768px){nav.hp-bottom-tabs{display:flex !important;}}
nav.hp-bottom-tabs .hp-bottom-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:6px 4px;color:#6b8a87;text-decoration:none;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:.08em;font-weight:600;background:transparent;border:0;cursor:pointer;min-height:44px;-webkit-tap-highlight-color:transparent;transition:color .12s;}
nav.hp-bottom-tabs .hp-bottom-tab svg{stroke:currentColor;}
nav.hp-bottom-tabs .hp-bottom-tab.active{color:#00e5c0;}
nav.hp-bottom-tabs .hp-bottom-tab:active{transform:scale(.94);}

/* hp-hm-zoom-lift: lift native .hm-zoom above .hp-bottom-tabs in PWA standalone on phones */
@media all and (display-mode:standalone) and (max-width:768px){
  .hm-zoom{bottom:calc(108px + env(safe-area-inset-bottom)) !important;}
}
</style>
<script id="hp-injected-scripts">
(function(){
// Bottom tab bar (admin-gated via meta tag)
function bnav(){
  if(document.getElementById('hp-bottom-tabs'))return;
  var meta=document.querySelector('meta[name="hp-is-admin"]');
  var isAdmin=meta && meta.getAttribute('content')==='yes';
  var p=location.pathname;
  function tab(label,href,active,icon,external){
    var a=document.createElement('a');a.className='hp-bottom-tab'+(active?' active':'');a.href=href;
    if(external){a.target='_blank';a.rel='noopener';}
    a.innerHTML=icon+'<span>'+label+'</span>';return a;
  }
  var I={
    dash:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
    help:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    settings:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    signout:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    customers:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    assets:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>'
  };
  var ts=[];
  ts.push(tab('Dashboard','/dashboard',p==='/dashboard'||p==='/',I.dash));
  if(isAdmin){ts.push(tab('Customers','/admin',p.indexOf('/admin')===0,I.customers));ts.push(tab('Assets','https://assets.harborprivacy.com/',false,I.assets,true));}
  ts.push(tab('Help','https://harborprivacy.com/docs.html',false,I.help,true));
  ts.push(tab('Settings','/settings',p.indexOf('/settings')===0,I.settings));
  ts.push(tab('Sign Out','/logout',false,I.signout));
  var n=document.createElement('nav');n.id='hp-bottom-tabs';n.className='hp-bottom-tabs';n.setAttribute('aria-label','Primary');
  ts.forEach(function(t){n.appendChild(t);});
  document.body.appendChild(n);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bnav);else bnav();
})();
</script>
</head>
<body>
<nav>
  <div class="nav-top">
    <a href="/admin" class="logo">harbor<span>/</span>privacy</a>
    <span class="badge-admin">ADMIN</span>
  </div>
  <div class="nav-links">
    <a href="https://harborprivacy.com" style="font-size:10px;">&#8592; Site</a>
    <a href="/admin">Customers</a>
    <a href="/social" class="active">Social</a>
    <a href="/settings">Settings</a>
    <a href="/logout" style="margin-left:auto;">Sign Out</a>
  </div>
</nav>

<div class="container">
  <h1 id="pageTitle">Social Scheduler</h1>
  <p class="sub" id="pageSub">Generate posts for Facebook, Instagram, and LinkedIn.</p>

  <!-- Brand tabs -->
  <div class="brand-switcher">
    <button class="brand-btn active" id="btnHarbor" onclick="setBrand('harbor')">HARBOR DNS</button>
    <button class="brand-btn" id="btnCareer" onclick="setBrand('career')">CAREER</button>
    <button class="brand-btn" id="btnFax" onclick="setBrand('fax')">FAX</button>
    <button class="brand-btn" id="btnBooking" onclick="setBrand('booking')">BOOKING</button>
    <button class="brand-btn" id="btnMoney" onclick="setBrand('money')">MONEY</button>
    <button class="brand-btn" id="btnTim" onclick="setBrand('tim')">TIM BRAZER</button>
    <button class="brand-btn" id="btnAuto" onclick="setBrand('auto')">AUTO</button>
  </div>

  <!-- Auto-post toggle (hidden for tim brand) -->
  <div class="card" id="autopostCard">
    <div class="autopost-bar">
      <div>
        <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;margin-bottom:4px;">DAILY AUTO-POST</div>
        <div style="font-size:13px;color:var(--muted);" id="autoPostLabel">Loading...</div>
      </div>
      <button id="toggleBtn" onclick="toggleAutoPost()" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;letter-spacing:0.08em;">...</button>
    </div>
  </div>

  <!-- Compose card -->
  <div class="card">
    <label>TOPIC</label>
    <div class="topics" id="topicChips"></div>
    <input type="text" id="topicInput" placeholder="Or type a custom topic...">

    <label style="margin-top:4px;">PLATFORMS</label>
    <div id="platformRows">
      <div class="platform-row" id="rowFacebook">
        <span class="platform-name"><span class="platform-icon">&#128196;</span> Facebook</span>
        <button onclick="togglePlatform(this,'facebook')" data-platform="facebook" data-on="true" class="toggle-btn">ON</button>
      </div>
      <div class="platform-row" id="rowInstagram">
        <span class="platform-name"><span class="platform-icon">&#128247;</span> Instagram</span>
        <button onclick="togglePlatform(this,'instagram')" data-platform="instagram" data-on="true" class="toggle-btn">ON</button>
      </div>
      <div class="platform-row" id="rowLinkedin">
        <span class="platform-name"><span class="platform-icon">&#128188;</span> LinkedIn</span>
        <button onclick="togglePlatform(this,'linkedin')" data-platform="linkedin" data-on="false" class="toggle-btn off">OFF</button>
      </div>
    </div>

    <div style="margin-top:20px;">
      <button class="btn" id="generateBtn" onclick="generate()" style="width:100%;padding:16px;">&#9889; Generate Post</button>
    </div>
  </div>

  <!-- Results -->
  <div id="resultsCard" style="display:none;">

    <!-- Image first on mobile (hidden: image generation disabled) -->
    <div class="card" id="imgCard" style="display:none;">
      <div class="platform-label" style="margin-bottom:12px;">GENERATED IMAGE</div>
      <div id="imgLoading" style="font-family:monospace;font-size:12px;color:var(--muted);display:none;padding:20px 0;"><span class="spinner"></span>Generating image...</div>
      <div id="imgOverlayWrap" style="display:none;position:relative;width:100%;border-radius:10px;overflow:hidden;aspect-ratio:1/1;">
        <img id="imgPreview" style="width:100%;height:100%;object-fit:cover;display:block;">
        <div id="imgOverlay" style="position:absolute;inset:0;display:flex;flex-direction:column;justify-content:flex-start;align-items:flex-start;padding:14px;">
          <div id="imgOverlayTop" style="font-family:'DM Mono',monospace;font-size:10px;letter-spacing:0.15em;color:rgba(255,255,255,0.9);text-transform:uppercase;background:rgba(0,0,0,0.35);padding:4px 10px;border-radius:20px;">harbor privacy</div>
          <div id="imgOverlayHook" style="display:none;"></div>
          <div id="imgOverlaySub" style="display:none;"></div>
        </div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
        <a id="imgDownload" class="btn-copy" style="display:none;text-decoration:none;" download="harbor-post.png">&#8595; Download</a>
      </div>
    </div>

    <!-- Platform results -->
    <div class="results-grid">
      <div class="platform-card" id="fbSection">
        <div class="platform-label">&#128196; FACEBOOK</div>
        <div class="post-box" id="fbPost" contenteditable="true"></div>
        <div class="char-count" id="fbCount">0 chars</div>
        <button class="btn-copy" onclick="copyText('fbPost', this)">Copy</button>
      </div>
      <div class="platform-card" id="igSection">
        <div class="platform-label">&#128247; INSTAGRAM</div>
        <div class="post-box" id="igPost" contenteditable="true"></div>
        <div class="char-count" id="igCount">0 chars</div>
        <button class="btn-copy" onclick="copyText('igPost', this)">Copy</button>
      </div>
      <div class="platform-card" id="liSection">
        <div class="platform-label">&#128188; LINKEDIN</div>
        <div class="post-box" id="liPost" contenteditable="true"></div>
        <div class="char-count" id="liCount">0 chars</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;align-items:center;">
          <button class="btn-copy" onclick="copyText('liPost', this)">Copy</button>
          <button class="btn-linkedin" onclick="openLinkedIn()">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
            Open LinkedIn
          </button>
        </div>
      </div>
    </div>

    <!-- Action bar -->
    <div class="card" style="margin-top:20px;">
      <div class="action-bar">
        <button class="btn-outline" onclick="generate()">&#8635; Regenerate</button>
        <button class="btn" id="postMakeBtn" onclick="postToMake()" id="fbigOnly" style="display:none;">&#8679; Post FB + IG</button>
        <span class="status-msg" id="makeStatus"></span>
      </div>
    </div>
  </div>
</div>

<script>
var currentBrand = "harbor";
var currentImageUrl = "";

var harborTopics = [
  "ISP selling your browsing history",
  "ad blockers only work on one device",
  "kids tablet tracking",
  "incognito mode myth",
  "smart TV data collection",
  "malware on home networks",
  "free trial offer"
];
var bookingTopics = [
  "let clients book appointments online 24/7",
  "stop losing customers to phone tag",
  "employee scheduling that actually works",
  "time tracking for small business owners",
  "PTO management without spreadsheets",
  "shift scheduling made simple",
  "reduce no-shows with automatic reminders",
  "one app for booking and employee scheduling",
  "free booking software for small businesses",
  "salon scheduling software that is actually free",
  "medical office scheduling made simple",
  "how to set up online booking in 5 minutes",
  "why your business needs online booking in 2026"
];
var careerTopics = [
  "ATS filtering out your resume",
  "sending the same resume everywhere",
  "blank cover letter problem",
  "AI tools storing your resume data",
  "not hearing back after applying",
  "resume keyword matching",
  "job search privacy"
];
var faxTopics = [
  "Send a fax anonymously -- no account needed",
  "HIPAA conduit exception explained",
  "Why lawyers still fax in 2026",
  "Send medical records from your phone",
  "No phone line needed",
  "Your fax document is deleted on delivery",
  "Anonymous fax for legal documents",
  "Privacy-first faxing for healthcare"
];
var timTopics = [
  "Servant leadership in healthcare operations",
  "Why front-end ops make or break revenue cycle",
  "20 years in diagnostic imaging -- what I learned",
  "Epic Cadence and Radiant -- real world tips",
  "Building a privacy startup while job searching",
  "Healthcare operations and patient access",
  "MBA lessons applied to healthcare management",
  "Transformational leadership in multi-site ops",
  "Why I founded Harbor Privacy",
  "Practice administrator skills that matter most"
];
var moneyTopics = [
  "Budgeting without your bank login",
  "Why Plaid is a privacy risk",
  "Forward receipts -- we do the rest",
  "Private alternative to Mint and YNAB",
  "Track spending from email alerts",
  "Savings goals without a bank connection",
  "Categorize spending automatically",
  "What happens when a budgeting app dies"
];

function setBrand(brand) {
  currentBrand = brand;
  var isCareer = brand === "career";
  var isTim = brand === "tim";
  var isAuto = brand === "auto";
  var isBooking = brand === "booking";
  document.body.className = isCareer ? "career-mode" : isTim ? "tim-mode" : isBooking ? "booking-mode" : "";
  ["harbor","booking","career","fax","money","tim","auto"].forEach(function(b) {
    document.getElementById("btn" + b.charAt(0).toUpperCase() + b.slice(1)).className =
      "brand-btn" + (brand === b ? " active" : "");
  });
  var titles = {
    harbor: ["Social Scheduler", "Harbor Privacy DNS -- Facebook & Instagram."],
    booking: ["Harbor Booking", "Scheduling app posts -- small business, appointments, workforce."],
    career: ["Career by Harbor", "Career tool posts -- light theme, problem-first."],
    fax: ["Harbor Fax", "Fax service posts -- anonymous, HIPAA, privacy angle."],
    money: ["Harbor Money", "Budgeting without bank logins -- privacy-first personal finance."],
    tim: ["Tim Brazer", "Personal LinkedIn content -- healthcare ops & leadership."],
    booking: ["Harbor Booking", "Free scheduling platform -- salons, clinics, small business."],
    auto: ["Auto-Post", "Daily automated posting settings."]
  };
  document.getElementById("pageTitle").textContent = titles[brand][0];
  document.getElementById("pageSub").textContent = titles[brand][1];
  // Topic chips
  var topicMap = {harbor: harborTopics, career: careerTopics, fax: faxTopics, booking: bookingTopics, money: moneyTopics, tim: timTopics, auto: []};
  renderChips(topicMap[brand] || []);
  if ((topicMap[brand] || []).length) document.getElementById("topicInput").value = topicMap[brand][0];
  // Platform toggles for tim -- LinkedIn only on by default
  if (isBooking) {
    setPlatformVisible("facebook", true);
    setPlatformVisible("instagram", true);
    setPlatformVisible("linkedin", true);
    setPlatformOn("facebook", true);
    setPlatformOn("instagram", true);
    setPlatformOn("linkedin", false);
  } else if (isTim) {
    setPlatformVisible("facebook", false);
    setPlatformVisible("instagram", false);
    setPlatformVisible("linkedin", true);
    setPlatformOn("linkedin", true);
  } else {
    setPlatformVisible("facebook", true);
    setPlatformVisible("instagram", true);
    setPlatformVisible("linkedin", brand !== "harbor");
    setPlatformOn("facebook", true);
    setPlatformOn("instagram", true);
  }
  // Post button visibility
  document.getElementById("postMakeBtn").style.display = (isTim || isBooking) ? "none" : "inline-flex";
  document.getElementById("autopostCard").style.display = (isTim || isBooking || isAuto) ? "none" : "block";
  document.getElementById("resultsCard").style.display = "none";
}

function setPlatformVisible(p, show) {
  var row = document.getElementById("row" + p.charAt(0).toUpperCase() + p.slice(1));
  if (row) row.style.display = show ? "flex" : "none";
}
function setPlatformOn(p, on) {
  var btn = document.querySelector("[data-platform='" + p + "']");
  if (!btn) return;
  btn.dataset.on = on.toString();
  btn.textContent = on ? "ON" : "OFF";
  btn.className = "toggle-btn" + (on ? "" : " off");
}

function renderChips(topics) {
  var el = document.getElementById("topicChips");
  el.innerHTML = "";
  topics.forEach(function(t) {
    var btn = document.createElement("button");
    btn.className = "topic-chip";
    btn.textContent = t;
    btn.onclick = function() {
      document.querySelectorAll(".topic-chip").forEach(function(c){c.classList.remove("selected");});
      btn.classList.add("selected");
      document.getElementById("topicInput").value = t;
    };
    el.appendChild(btn);
  });
}

function togglePlatform(btn, platform) {
  var on = btn.dataset.on === "true";
  btn.dataset.on = (!on).toString();
  btn.textContent = on ? "OFF" : "ON";
  btn.className = "toggle-btn" + (on ? " off" : "");
}

function updateCharCount(boxId, countId, limit) {
  var text = document.getElementById(boxId).textContent || "";
  var el = document.getElementById(countId);
  el.textContent = text.length + " chars" + (limit ? " / " + limit : "");
  el.style.color = (limit && text.length > limit) ? "#f87171" : "var(--muted)";
}

async function generate() {
  var btn = document.getElementById("generateBtn");
  var topic = document.getElementById("topicInput").value || harborTopics[0];
  var platforms = {};
  document.querySelectorAll("[data-platform]").forEach(function(b) {
    platforms[b.dataset.platform] = b.dataset.on === "true";
  });
  // Tim brand always LinkedIn only
  if (currentBrand === "tim") { platforms = {facebook: false, instagram: false, linkedin: true}; }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Generating...';
  document.getElementById("resultsCard").style.display = "none";
  document.getElementById("imgLoading").style.display = "none";
  document.getElementById("imgPreview").style.display = "none";
  document.getElementById("imgDownload").style.display = "none";
  document.getElementById("makeStatus").textContent = "";
  document.getElementById("makeStatus").className = "status-msg";

  try {
    var r = await fetch("/api/social/generate", {
      method: "POST",
      headers: {"Content-Type":"application/json","X-CSRF":window.__CSRF||""},
      credentials: "same-origin",
      body: JSON.stringify({topic: topic, brand: currentBrand, platforms: platforms, csrf: window.__CSRF||""})
    });
    if (!r.ok) {
      var errText = "";
      try { var err = await r.json(); errText = err.error || ("HTTP " + r.status); } catch(e) { errText = "HTTP " + r.status; }
      document.getElementById("makeStatus").className = "status-msg error";
      document.getElementById("makeStatus").textContent = "Generate failed: " + errText;
      document.getElementById("generateBtn").disabled = false;
      document.getElementById("generateBtn").innerHTML = "Generate Posts";
      return;
    }
    var data = await r.json();
    var showFb = platforms.facebook !== false;
    var showIg = platforms.instagram !== false;
    var showLi = platforms.linkedin === true;
    document.getElementById("fbSection").style.display = showFb ? "block" : "none";
    document.getElementById("igSection").style.display = showIg ? "block" : "none";
    document.getElementById("liSection").style.display = showLi ? "block" : "none";
    if (showFb) { document.getElementById("fbPost").textContent = data.facebook || ""; updateCharCount("fbPost","fbCount",63206); }
    if (showIg) { document.getElementById("igPost").textContent = data.instagram || ""; updateCharCount("igPost","igCount",2200); }
    if (showLi) { document.getElementById("liPost").textContent = data.linkedin || ""; updateCharCount("liPost","liCount",3000); }
    document.getElementById("resultsCard").style.display = "block";
    document.getElementById("imgLoading").style.display = "none";
    // Image generation disabled (Gemini free-tier quota exhausted) -- always hide
    document.getElementById("imgCard").style.display = "none";
    if (data.image_url && currentBrand !== "tim") {
      var img = document.getElementById("imgPreview");
      // Pull text before setting src so it's ready when image loads
      var fbText = document.getElementById("fbPost").textContent || "";
      var sentences = fbText.split(/(?<=[.!?])\s+/);
      var hook = sentences[0] || "";
      var sub = sentences[1] || "";
      document.getElementById("imgOverlayHook").textContent = hook;
      document.getElementById("imgOverlaySub").textContent = sub;
      var brandLabels = {harbor:"harbor privacy", career:"career by harbor", fax:"harbor fax", booking:"harbor booking", tim:"tim brazer", auto:"harbor privacy"};
      document.getElementById("imgOverlayTop").textContent = brandLabels[currentBrand] || "harbor privacy";
      img.onerror = function() { document.getElementById("imgOverlayWrap").style.display="block"; document.getElementById("imgOverlayWrap").textContent="Image load failed."; };
      img.onload = function() {
        document.getElementById("imgOverlayWrap").style.display = "block";
        currentImageUrl = data.image_url;
        // Canvas composite for download
        var dl = document.getElementById("imgDownload");
        var canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
        var ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        // Gradient scrim
        var grad = ctx.createLinearGradient(0, 0, 0, canvas.height);
        grad.addColorStop(0, "rgba(0,0,0,0.18)");
        grad.addColorStop(0.3, "rgba(0,0,0,0.05)");
        grad.addColorStop(0.7, "rgba(0,0,0,0.55)");
        grad.addColorStop(1, "rgba(0,0,0,0.82)");
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        // Brand label top
        ctx.fillStyle = "rgba(255,255,255,0.7)";
        ctx.font = "bold " + Math.round(canvas.width * 0.025) + "px monospace";
        ctx.fillText((brandLabels[currentBrand] || "harbor privacy").toUpperCase(), canvas.width * 0.06, canvas.height * 0.07);
        // Hook text bottom
        var hookSize = Math.round(canvas.width * 0.065);
        ctx.fillStyle = "#ffffff";
        ctx.font = "bold " + hookSize + "px serif";
        ctx.shadowColor = "rgba(0,0,0,0.5)";
        ctx.shadowBlur = 8;
        // Word wrap hook
        var words = hook.split(" ");
        var lines = [];
        var line = "";
        var maxW = canvas.width * 0.88;
        words.forEach(function(w) {
          var test = line + (line ? " " : "") + w;
          if (ctx.measureText(test).width > maxW && line) { lines.push(line); line = w; }
          else { line = test; }
        });
        if (line) lines.push(line);
        var lineH = hookSize * 1.25;
        var totalH = lines.length * lineH + (sub ? hookSize * 0.8 : 0);
        var startY = canvas.height * 0.78 - totalH / 2;
        lines.forEach(function(l, i) { ctx.fillText(l, canvas.width * 0.06, startY + i * lineH); });
        // Sub text
        if (sub) {
          ctx.font = Math.round(canvas.width * 0.038) + "px sans-serif";
          ctx.fillStyle = "rgba(255,255,255,0.85)";
          ctx.fillText(sub.length > 60 ? sub.substring(0,57)+"..." : sub, canvas.width * 0.06, startY + lines.length * lineH + hookSize * 0.6);
        }
        canvas.toBlob(function(blob) {
          dl.href = URL.createObjectURL(blob);
          dl.style.display = "inline-block";
        }, "image/png");
      };
      img.crossOrigin = "anonymous";
      img.src = data.image_url + "?t=" + Date.now();
    }
  } catch(e) {
    alert("Error: " + e.message);
    document.getElementById("imgLoading").style.display = "none";
  } finally {
    btn.disabled = false;
    btn.innerHTML = "&#9889; Generate Post + Image";
  }
}

function copyText(id, btn) {
  var text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(function() { btn.textContent = orig; }, 2000);
  });
}

function openLinkedIn() {
  var text = encodeURIComponent(document.getElementById("liPost").textContent || "");
  // Try LinkedIn app deep link first, fall back to web share
  var appUrl = "linkedin://";
  var webUrl = "https://www.linkedin.com/feed/?shareActive=true";
  // Copy to clipboard then open
  navigator.clipboard.writeText(document.getElementById("liPost").textContent || "").then(function() {
    var status = document.getElementById("makeStatus");
    status.className = "status-msg ok";
    status.textContent = "Copied! Opening LinkedIn...";
    setTimeout(function() {
      window.location.href = appUrl;
      setTimeout(function() { window.open(webUrl, "_blank"); }, 1200);
    }, 400);
  });
}

async function postToMake() {
  var btn = document.getElementById("postMakeBtn");
  var status = document.getElementById("makeStatus");
  var imageUrl = currentImageUrl || document.getElementById("imgPreview").src;
  var fbText = document.getElementById("fbPost").textContent;
  var igText = document.getElementById("igPost").textContent;
  if (!fbText && !igText) { status.textContent = "No post content."; return; }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Posting...';
  status.textContent = "";
  try {
    var r = await fetch("/api/social/post-to-make", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({image_url: imageUrl, facebook_text: fbText, instagram_text: igText, brand: currentBrand})
    });
    var data = await r.json();
    if (data.ok) {
      status.className = "status-msg ok";
      status.textContent = "&#10003; Posted to Make!";
    } else {
      status.className = "status-msg err";
      status.textContent = "Error: " + (data.error || "unknown");
    }
  } catch(e) {
    status.className = "status-msg err";
    status.textContent = "Failed: " + e.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = "&#8679; Post FB + IG";
  }
}


async function loadStatus() {
  try {
    var r = await fetch("/api/social/status");
    var data = await r.json();
    updateToggleUI(data.enabled);
  } catch(e) {}
}

function updateToggleUI(enabled) {
  var btn = document.getElementById("toggleBtn");
  var label = document.getElementById("autoPostLabel");
  if (enabled) {
    btn.textContent = "Turn Off";
    btn.style.borderColor = "var(--accent)";
    btn.style.color = "var(--accent)";
    label.textContent = "Harbor: 9am daily -- Career: 12pm daily";
  } else {
    btn.textContent = "Turn On";
    btn.style.borderColor = "var(--border)";
    btn.style.color = "var(--muted)";
    label.textContent = "Auto-posting is paused";
  }
}

async function toggleAutoPost() {
  var r = await fetch("/api/social/toggle", {method: "POST"});
  var data = await r.json();
  updateToggleUI(data.enabled);
}

setBrand("harbor");
loadStatus();
</script>
</body>
</html>"""

# ============================================================
# start.harborprivacy.com magic-link auth
# ============================================================
START_TOKENS_PATH = "/var/log/harbor-start-tokens.json"
HARBOR_HOME_IPS = {"75.67.22.175"}
START_TOKEN_TTL = 90 * 24 * 3600
START_RECIPIENT = "admin@harborprivacy.com"
_START_RATELIMIT = {}

def _load_start_tokens():
    try:
        with open(START_TOKENS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_start_tokens(d):
    try:
        with open(START_TOKENS_PATH, "w") as f:
            json.dump(d, f)
    except Exception:
        pass

def _start_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "https://start.harborprivacy.com"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Vary"] = "Origin"
    return resp

def _client_ip():
    return request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or ""

# ════════════════════════════════════════════════════════════
# SECTION 21 — ROUTES: START MAGIC (brazer startpage auth)
# /api/start-magic, /api/start-verify
# Magic-link email auth for start.brazer.us
# CSRF-exempt (own token in URL)
# ════════════════════════════════════════════════════════════

@app.route("/api/start-magic", methods=["POST", "OPTIONS"])
def api_start_magic():
    if request.method == "OPTIONS":
        return _start_cors(make_response("", 204))
    ip = _client_ip()
    now = int(_time.time())
    last = _START_RATELIMIT.get(ip, 0)
    if now - last < 300:
        return _start_cors(jsonify({"ok": False, "error": "rate_limited"}))
    data = request.get_json(silent=True) or {}
    ts = data.get("cf_turnstile_response") or data.get("turnstile") or ""
    if not _verify_turnstile(ts, ip):
        return _start_cors(jsonify({"ok": False, "error": "captcha"}))
    tokens = _load_start_tokens()
    tokens = {k: v for k, v in tokens.items() if v.get("expires", 0) > now}
    token = secrets.token_urlsafe(32)
    tokens[token] = {"created": now, "expires": now + START_TOKEN_TTL, "ip": ip}
    _save_start_tokens(tokens)
    _START_RATELIMIT[ip] = now
    link = f"https://start.harborprivacy.com/?access={token}"
    html = f'<p>Click to access start.harborprivacy.com (valid 90 days):</p><p><a href="{link}">{link}</a></p><p style="color:#666;font-size:12px">Requested from IP {ip}</p>'
    send_email(START_RECIPIENT, "Harbor Start access link", html)
    return _start_cors(jsonify({"ok": True}))

@app.route("/api/start-verify", methods=["POST", "OPTIONS"])
def api_start_verify():
    if request.method == "OPTIONS":
        return _start_cors(make_response("", 204))
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    ip = _client_ip()
    now = int(_time.time())
    tokens = _load_start_tokens()
    entry = tokens.get(token)
    if not entry or entry.get("expires", 0) < now:
        if token in tokens:
            del tokens[token]
            _save_start_tokens(tokens)
        return _start_cors(jsonify({"ok": False}))
    if ip in HARBOR_HOME_IPS:
        entry["expires"] = now + START_TOKEN_TTL
        tokens[token] = entry
        _save_start_tokens(tokens)
    return _start_cors(jsonify({"ok": True, "expires": entry["expires"]}))

# ════════════════════════════════════════════════════════════
# SECTION 22 — HEALTH
# /health — simple "ok" for monitoring
# ════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    return {"status": "ok"}

# ════════════════════════════════════════════════════════════
# SECTION 23 — HARBOR SCAN
# /admin/scan                       — overview (findings, opt-outs, brokers)
# /admin/scan/profile/<id>          — per-profile detail (timeline)
# ════════════════════════════════════════════════════════════
# Decoupled from harbor-scan's DB via subprocess so harbor-scan can move to
# vm4 later by swapping the subprocess call for an ssh exec. Adds no new
# dependencies to harbor-backend's venv.

import subprocess as _hs_subprocess

_HS_DIR = "/home/ubuntu/harbor-scan"
_HS_PY = f"{_HS_DIR}/.venv/bin/python"

def _hs_env():
    if hasattr(_hs_env, "_cache"):
        return _hs_env._cache
    env = dict(os.environ)
    try:
        with open(f"{_HS_DIR}/.env") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k] = v
    except Exception:
        pass
    _hs_env._cache = env
    return env

def _hs_summary(profile_id=None):
    cmd = [_HS_PY, "worker.py", "scan-summary"]
    if profile_id is not None:
        cmd += ["--profile-id", str(profile_id)]
    try:
        out = _hs_subprocess.run(
            cmd, cwd=_HS_DIR, capture_output=True, text=True,
            timeout=20, env=_hs_env(),
        )
    except Exception as e:
        return {"error": f"subprocess: {e}"}
    if out.returncode != 0:
        return {"error": (out.stderr or "non-zero exit").strip()[:400]}
    try:
        return json.loads(out.stdout)
    except Exception as e:
        return {"error": f"json: {e}", "raw": out.stdout[:400]}

_HS_OVERVIEW_TMPL = """<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin</p>
    <h1>Harbor Scan</h1>
  </div>
  {% if data.error %}
    <div class="card" style="border-color:#ff4e4e;color:#ff4e4e;"><strong>error:</strong> {{ data.error }}</div>
  {% else %}
  <div class="stat-grid" style="margin-bottom:20px;">
    <div class="stat"><div class="stat-num">{{ data.totals.profiles_total }}</div><div class="stat-label">Profiles</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--accent);">{{ data.totals.profiles_authorized }}</div><div class="stat-label">Authorized</div></div>
    <div class="stat"><div class="stat-num" style="color:#ff4e4e;">{{ data.totals.findings_found }}</div><div class="stat-label">Open Findings</div></div>
    <div class="stat"><div class="stat-num" style="color:#22c55e;">{{ data.totals.findings_removed }}</div><div class="stat-label">Removed</div></div>
    <div class="stat"><div class="stat-num">{{ data.totals.brokers_enabled }}</div><div class="stat-label">Brokers Enabled</div></div>
    <div class="stat"><div class="stat-num">{{ data.totals.clicks_queued }}</div><div class="stat-label">Clicks Queued</div></div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Worker Status</div>
    {% set ws = data.worker_status %}
    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:13px;">
      <span><span style="font-family:DM Mono,monospace;color:var(--muted);">Pi SOCKS tunnel</span></span>
      <span>{% if ws.socks.ok %}<span class="badge badge-on">up</span>{% elif ws.socks.proxy %}<span class="badge badge-off">down</span> <span style="font-family:DM Mono,monospace;font-size:11px;color:#ff4e4e;">{{ ws.socks.error or 'no SOCKS5 reply' }}</span>{% else %}<span class="badge">no proxy</span>{% endif %}</span>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:6px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">worker</th><th>state</th><th>last run</th><th>next run</th><th>last invocation</th><th style="text-align:right;">errors</th>
      </tr>
      {% for w in ws.workers %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;">{{ w.name }}</td>
        <td>{% if w.active == 'active' %}<span class="badge badge-on">{{ w.active }}</span>{% else %}<span class="badge badge-off">{{ w.active }}</span>{% endif %}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ w.last_run or '-' }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ w.next_run or '-' }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{% if w.last_invocation_at %}{% if w.last_succeeded %}<span style="color:#22c55e;">●</span>{% else %}<span style="color:#ff4e4e;">●</span>{% endif %} {{ w.last_invocation_at }}{% else %}never{% endif %}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;{% if w.recent_errors %}color:#ff4e4e;{% else %}color:#22c55e;{% endif %}">{{ w.recent_errors|length }}</td>
      </tr>
      {% if w.recent_errors %}
        {% for e in w.recent_errors %}
        <tr><td colspan="6" style="padding:6px 0 6px 18px;font-family:DM Mono,monospace;font-size:11px;color:#ff4e4e;border-top:none;word-break:break-word;">
          <span style="color:var(--muted);">{{ e.broker_id or e.url or '' }}</span> {{ (e.error or '')[:200] }}
        </td></tr>
        {% endfor %}
      {% endif %}
      {% endfor %}
    </table>
    <p style="font-size:11px;color:var(--muted);margin-top:8px;font-family:DM Mono,monospace;">● green = last invocation succeeded · ● red = last invocation had errors · errors clear when next run is clean</p>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Opt-Out Pipeline</div>
    {% if data.optouts_by_status %}
      {% for r in data.optouts_by_status %}
        <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);">
          <span>{{ r.status }}</span>
          <span style="font-family:DM Mono,monospace;font-size:12px;color:var(--muted);">{{ r.n }}</span>
        </div>
      {% endfor %}
    {% else %}
      <div style="color:var(--muted);padding:10px 0;">No opt-out requests yet.</div>
    {% endif %}
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Brokers</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">id</th><th>name</th><th>tier</th><th>enabled</th>
        <th style="text-align:right;padding-right:20px;">open</th><th style="text-align:right;padding-right:20px;">removed</th><th style="padding-left:24px;">last verified</th>
      </tr>
      {% for b in data.brokers %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;">{{ b.id }}</td>
        <td>{{ b.name }}</td>
        <td><span class="badge">{{ b.optout_tier }}</span></td>
        <td>{% if b.enabled %}<span class="badge badge-on">on</span>{% else %}<span class="badge badge-off">off</span>{% endif %}</td>
        <td style="text-align:right;padding-right:20px;font-family:DM Mono,monospace;">{{ b.findings_open }}</td>
        <td style="text-align:right;padding-right:20px;font-family:DM Mono,monospace;color:#22c55e;">{{ b.findings_removed }}</td>
        <td style="padding-left:24px;font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ b.last_verified or '-' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Profiles</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">id</th><th>name</th><th>customer</th><th>auth</th>
        <th style="text-align:right;">emails</th><th style="text-align:right;">phones</th>
        <th style="text-align:right;">addrs</th><th style="text-align:right;">aliases</th>
        <th style="text-align:right;">open</th><th style="text-align:right;">removed</th>
      </tr>
      {% for p in data.profiles %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;"><a href="/admin/scan/profile/{{ p.id }}" style="color:var(--accent);text-decoration:none;">#{{ p.id }}</a></td>
        <td>{{ p.full_name }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ p.customer_id }}</td>
        <td>{% if p.authorization_signed_at %}<span class="badge badge-on">signed</span>{% else %}<span class="badge badge-off">unsigned</span>{% endif %}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.emails_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.phones_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.addresses_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.aliases_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;color:#ff4e4e;">{{ p.findings_open }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;color:#22c55e;">{{ p.findings_removed }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Recent Opt-Out Activity</div>
    {% if data.recent_optouts %}
      {% for r in data.recent_optouts %}
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px;">
          <span><span style="color:var(--muted);font-family:DM Mono,monospace;">#{{ r.request_id }}</span> <a href="/admin/scan/profile/{{ r.profile_id }}" style="color:var(--text);text-decoration:none;">profile {{ r.profile_id }}</a> via <span style="color:var(--accent);">{{ r.broker_id }}</span></span>
          <span style="font-family:DM Mono,monospace;color:var(--muted);">{{ r.status }} ({{ r.attempts }})</span>
        </div>
      {% endfor %}
    {% else %}
      <div style="color:var(--muted);padding:10px 0;">No opt-out activity yet.</div>
    {% endif %}
  </div>
  {% endif %}
  <a href="/admin" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;">← Back to Admin</a>
</div>
"""
