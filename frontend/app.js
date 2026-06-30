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

async function selectAlert(id) {
    state.findingId = id; state.history = [];
    location.hash = id;
    document.querySelectorAll(".alert-item")
        .forEach(n => n.classList.toggle("active", n.dataset.id === id));
    const detail = $("#detail");
    detail.innerHTML = '<div class="skeleton"></div>';
    let rec;
    try { rec = await api("/alerts/" + encodeURIComponent(id)); }
    catch (_) { detail.innerHTML = ""; detail.appendChild(el("div", "error", "Could not load this report.")); return; }
    renderDetail(rec);
}

function groundednessPill(g) {
    if (g == null) return null;
    const ok = g >= 0.999;
    return el("span", "pill " + (ok ? "pill-ok" : "pill-warn"),
            `groundedness ${g.toFixed(2)}${ok ? " ✓" : ""}`);
}

function renderMarkdown(node, text) {
    node.innerHTML = DOMPurify.sanitize(marked.parse(text || ""));
}

function renderDetail(rec) {
    const detail = $("#detail");
    detail.innerHTML = "";
    const head = el("div", "report-head");
    head.appendChild(el("h2", null, rec.finding_id));
    const pill = groundednessPill(rec.groundedness);
    if (pill) head.appendChild(pill);
    head.appendChild(el("span", "meta", rec.model || ""));
    const honest = el("button", "link", "How this is kept honest");
    honest.onClick = toggleHonest;
    head.appendChild(honest);
    detail.appendChild(head);

    const report = el("div", "report markdown");
    renderMarkdown(report, rec.report);
    detail.appendChild(report);

    detail.appendChild(buildChat());
}

function buildChat() {
    const chat = el("div", "chat");
    chat.appendChild(el("div", "chat-label", "Ask about this alert"));
    chat.appendChild(el("div", null, "")).id = "transcript";
    const form = el("form", "ask-form");
    const input = el("input", "ask-input"); input.placeholder = "type a question..."; input.maxLength = 1000;
    const send = el("button", "send", "Send"); send.type = "submit";
    form.append(input, send);
    form.onsubmit = (e) => { e.preventDefault(); const q = input.value.trim(); if (q) { input.value = ""; ask(q); } };
        chat.appendChild(form);
        return chat;
}

function toggleHonest() {}

window.addEventListener("DOMContentLoaded", async () => {
    await loadAlerts();
    const id = location.hash.replace(/^#/, "");
    if (id) selectAlert(id);
});