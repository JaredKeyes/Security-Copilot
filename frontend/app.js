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

function addTurn(role, node) {
    const t = $("#transcript");
    const turn = el("div", "turn turn-" + role);
    turn.appendChild(node);
    t.appendChild(turn);
    t.scrollTop = t.scrollHeight;
    return turn;
}

async function ask(question) {
    addTurn("user", el("div", "bubble", question));
    const thinking = addTurn("ai",
        el("div", "bubble thinking", "Investigating... (the first question can take ~15-20s while the model warms up)"));
    const send = $(".send"); send.disabled = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    let data;
    try {
        data = await api("/ask", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ finding_id: state.findingId, question, history: state.history }),
            signal: controller.signal,
        });
    }   catch (e) {
        clearTimeout(timer); thinking.remove();
        const msg = e.name === "AbortError" ? "That took too long - please try again."
            : e.status === 400 ? e.message
            : "Something went wrong - please try again.";
        addTurn("ai", el("div", "bubble error", msg));
        send.disabled = false; return;
    }
    clearTimeout(timer); thinking.remove();

    if (data.budget_exceeded) {
        addTurn("ai", el("div", "bubble budget", "Daily demo budget reached - showing the precomputed report instead."));
        send.disabled = false; return;
    }

    const bubble = el("div", "bubble");
    renderMarkdown(bubble, data.answer);
    if (data.review_required) {
        const pill = el("span", "pill pill-warn", "⚠ REVIEW_REQUIRED");
        pill.title = "Entities not found in the evidence: " + (data.uncited_entities || []).join(", ");
        bubble.appendChild(pill);
    }
    addTurn("ai", bubble);

    state.history.push({ role: "user", context: question });
    state.history.push({ role: "assistant", context: data.answer });
    state.history = state.history.slice(-MAX_HISTORY);
    send.disabled = false;
}

function toggleHonest() {
  const existing = $("#honest-panel");
  if (existing) { existing.remove(); return; }
  const panel = el("div", "honest-panel"); panel.id = "honest-panel";
  panel.innerHTML = `
    <h3>How this demo is kept honest</h3>
    <p>Every served report passes a deterministic <strong>citation-coverage</strong> guardrail:
    each IP, finding ID, and service account named in the text must appear in the underlying
    evidence, or the output is flagged <code>REVIEW_REQUIRED</code>. The same check runs live on
    every answer above, and groundedness is the fraction of named entities found in evidence.</p>
    <p><strong>Regression demo — catching a fabrication:</strong></p>
    <table class="honest-table">
      <tr><th></th><th>Groundedness</th><th>Guardrail</th></tr>
      <tr><td>Original report</td><td>1.00</td><td class="ok">PASS</td></tr>
      <tr><td>+ injected fake IP <code>203.0.113.99</code></td><td>&lt; 1.00</td><td class="warn">REVIEW_REQUIRED</td></tr>
    </table>
    <p class="muted small">Offline, a Sonnet LLM-as-judge scores faithfulness/correctness; judge-vs-ground-truth
    meta-eval agreement is 1.0 on the seeded set.</p>`;
  $("#detail").appendChild(panel);
}

window.addEventListener("DOMContentLoaded", async () => {
    await loadAlerts();
    const id = location.hash.replace(/^#/, "");
    if (id) selectAlert(id);
});