const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, txt) => { const n = document.createElement(tag);
    if (cls) n.className = cls; if (txt != null) n.textContent = txt; return n; };

const state = { findingId: null, history: [] };
const MAX_HISTORY = 16;

const sevClass = (s) => s >= 8 ? "sev-high" : s >= 6 ? "sev-med" : "sev-low";

async function api(path, opts) {
    const res = await fetch(window.API_BASE + path, opts);
    if (!res.ok) {
        let detail = res.statusText;
        try { detail = (await res.json()).detail || detail; } catch (_) {}
        const err = new Error(detail); err.status = res.status; throw err;
    }
    return res.json();
}

async function loadAlerts() {
    const list = $("#alert-list");
    list.innerHTML = "";
    let data;
    try { data = await api("/alerts"); }
    catch (_) { list.appendChild(el("div", "error", "Could not load alerts. Refresh to retry.")); return; 
    }
    $("#alert-count").textContent = data.count;
    for (const a of data.alerts) {
        const item = el("button", "alert-item");
        item.dataset.id = a.finding_id;
        const sev = el("span", "sev " + sevClass(a.severity), (a.severity ?? "-").toString());
        const fid = el("span", "mono fid", a.finding_id);
        const title = el("span", "title", a.title || a.finding_type || "");
        if (a.is_known_bad_ip) title.appendChild(el("span", "badip", " ●"));
        item.append(sev, fid, title);
        item.onclick = () => selectAlert(a.finding_id);
        list.appendChild(item);
    }
}

window.addEventListener("DOMContentLoaded", loadAlerts);