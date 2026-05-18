"""
harbor_lib.agh — AdGuard Home REST API client.
Calls degrade to last-known snapshot on timeout/error.
"""
import json, logging, requests
from datetime import datetime
from .config import (
    ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS, AGH_TIMEOUT,
    AGH_SNAPSHOT_FILE, CUSTOMERS_LOG,
)

log = logging.getLogger(__name__)


def _save_agh_snapshot(path, payload):
    try:
        try:
            with open(AGH_SNAPSHOT_FILE) as f:
                snap = json.load(f)
        except Exception:
            snap = {}
        snap[path] = {"ts": datetime.utcnow().isoformat() + "Z", "data": payload}
        with open(AGH_SNAPSHOT_FILE, "w") as f:
            json.dump(snap, f)
    except Exception:
        pass


def _load_agh_snapshot(path):
    try:
        with open(AGH_SNAPSHOT_FILE) as f:
            return json.load(f).get(path, {}).get("data", {})
    except Exception:
        return {}


def agh_get(path):
    try:
        r = requests.get(f"{ADGUARD_URL}{path}", auth=(ADGUARD_USER, ADGUARD_PASS), timeout=AGH_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            _save_agh_snapshot(path, data)
            return data
        log.warning(f"agh_get {path} -> {r.status_code}, returning cached snapshot")
        return _load_agh_snapshot(path)
    except Exception as e:
        log.warning(f"agh_get {path} failed: {e}, returning cached snapshot")
        return _load_agh_snapshot(path)


def agh_post(path, data):
    try:
        r = requests.post(f"{ADGUARD_URL}{path}", json=data, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=AGH_TIMEOUT)
        return r.status_code == 200
    except Exception as e:
        log.warning(f"agh_post {path} failed: {e}")
        return False


def get_allowed_clients():
    access = agh_get("/control/access/list")
    return access.get("allowed_clients", [])


def get_client(client_id):
    clients = agh_get("/control/clients")
    for c in (clients.get("clients") or []):
        if client_id in c.get("ids", []):
            return c
    return {}


def is_client_allowed(client_id):
    return client_id in get_allowed_clients()


def get_stats():
    return agh_get("/control/stats")


def get_client_stats(client_id):
    try:
        stats = agh_get("/control/stats")
        top_clients = stats.get("top_clients", [])
        total = 0
        for entry in top_clients:
            if client_id in entry:
                total = entry[client_id]
                break
        global_total = stats.get("num_dns_queries", 0)
        global_blocked = stats.get("num_blocked_filtering", 0) + stats.get("num_replaced_safebrowsing", 0) + stats.get("num_replaced_parental", 0)
        global_pct = round(global_blocked / max(global_total, 1) * 100, 1)
        blocked = round(total * global_pct / 100)
        pct = global_pct
        return {"total": total, "blocked": blocked, "pct": pct, "top_blocked": []}
    except Exception:
        return {"total": 0, "blocked": 0, "pct": 0, "top_blocked": []}


def get_all_blocked_services():
    data = agh_get("/control/blocked_services/all")
    services = data.get("blocked_services", [])
    groups = {}
    for s in services:
        g = s.get("group_id", "other")
        if g not in groups:
            groups[g] = []
        groups[g].append({"id": s["id"], "name": s["name"]})
    return groups


def get_client_blocked_services(client_id):
    client = get_client(client_id)
    if not client:
        return []
    return client.get("blocked_services") or []


PROFILES = {
    "kid": {
        "name": "Kid Mode",
        "icon": "👧",
        "desc": "Blocks social media, adult content, dating apps, gambling and streaming",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","tumblr",
                     "tinder","discord","youtube","twitch","4chan","9gag",
                     "amino","bigo_live","vk","wechat","telegram","whatsapp","viber","signal",
                     "dailymotion","vimeo","bluesky","clubhouse","wizz","chatgpt","deepseek",
                     "copilot","claude","betano","betfair","betway","blaze"]
    },
    "work": {
        "name": "Work Focus",
        "icon": "💼",
        "desc": "Blocks social media, streaming and gaming to keep you focused",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","youtube",
                     "twitch","netflix","disneyplus","amazon_streaming","spotify","spotify_video",
                     "steam","discord","dailymotion","vimeo","crunchyroll","plex","pluto_tv",
                     "apple_streaming","tidal","soundcloud","deezer","bilibili",
                     "activision_blizzard","battle_net","epic_games","electronic_arts",
                     "riot_games","roblox","rockstar_games","ubisoft","xboxlive"]
    },
    "gaming": {
        "name": "Gaming Mode",
        "icon": "🎮",
        "desc": "Blocks social media and distractions, leaves gaming services open",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","youtube",
                     "amazon_streaming","netflix","disneyplus","tinder","tumblr",
                     "dailymotion","vimeo","bilibili","shein","temu","betano","betfair","betway"]
    }
}


def save_profile_snapshot(client_id, services):
    lines = []
    updated = False
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    if r.get("client_id") == client_id:
                        r["custom_services_snapshot"] = services
                        updated = True
                    lines.append(json.dumps(r))
                except Exception:
                    lines.append(line)
        if updated:
            with open(CUSTOMERS_LOG, "w") as f:
                f.write("\n".join(lines) + "\n")
    except Exception as e:
        log.error(f"Snapshot save error: {e}")


def save_active_profile(client_id, profile_name):
    lines = []
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    if r.get("client_id") == client_id:
                        r["active_profile"] = profile_name
                    lines.append(json.dumps(r))
                except Exception:
                    lines.append(line)
        with open(CUSTOMERS_LOG, "w") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        log.error(f"Profile save error: {e}")


def set_client_blocked_services(client_id, services):
    client = get_client(client_id)
    if not client:
        return False
    updated = {**client, "blocked_services": services, "use_global_blocked_services": False}
    try:
        r = requests.post(
            f"{ADGUARD_URL}/control/clients/update",
            json={"name": client.get("name", client_id), "data": updated},
            auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10,
        )
        return r.status_code == 200
    except Exception as e:
        log.error(f"set_client_blocked error: {e}")
        return False


def add_custom_rule(client_id, domain, block=True):
    prefix = "||" if block else "@@||"
    rule = f"{prefix}{domain}^$client={client_id}"
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        if rule not in rules:
            rules.append(rule)
            return agh_post("/control/filtering/set_rules", {"rules": rules})
        return True
    except Exception as e:
        log.error(f"add_custom_rule error: {e}")
        return False


def get_client_rules(client_id):
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        return [r for r in rules if f"$client={client_id}" in r]
    except Exception:
        return []


def remove_custom_rule(client_id, rule):
    full_rule = rule if f"$client={client_id}" in rule else f"{rule}$client={client_id}"
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        new_rules = [r for r in rules if r != full_rule and r != rule]
        return agh_post("/control/filtering/set_rules", {"rules": new_rules})
    except Exception as e:
        log.error(f"remove_custom_rule error: {e}")
        return False
