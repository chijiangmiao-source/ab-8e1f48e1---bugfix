/* 星载姿控参数页恢复审计 — 前端逻辑 */
"use strict";

const $ = (sel) => document.querySelector(sel);

const els = {
  auditId: $("#auditId"),
  payload: $("#payload"),
  submit: $("#submit"),
  status: $("#status"),
  loadSample: $("#loadSample"),
  formatJson: $("#formatJson"),
  verdictCard: $("#verdictCard"),
  verdictSummary: $("#verdictSummary"),
  pagesBody: $("#pagesTable tbody"),
  traceBody: $("#traceTable tbody"),
  filters: document.querySelectorAll(".filters input[data-phase]"),
  onlyChanged: $("#onlyChanged"),
  lookup: $("#lookup"),
  lookupId: $("#lookupId"),
};

let sampleCache = null;

function setStatus(kind, text) {
  els.status.className = `status ${kind}`;
  els.status.textContent = text;
}

function esc(s) {
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function lsn(v) {
  return v === null || v === undefined ? "—" : String(v);
}

function shortSha(sha) {
  if (!sha) return "—";
  return `${sha.slice(0, 16)}…${sha.slice(-8)}`;
}

function renderVerdict(v) {
  window._lastTrace = v.trace;
  els.verdictCard.classList.remove("hidden");
  const dptText = Object.entries(v.dirtyPageTableAtEnd)
    .map(([p, l]) => `${p}:${l}`)
    .join(", ") || "∅（全部已落盘）";
  els.verdictSummary.innerHTML = `
    <div class="summ-grid">
      <div class="summ-item"><div class="k">审计标识</div><div class="v">${esc(v.auditId)}</div></div>
      <div class="summ-item"><div class="k">已提交事务</div><div class="v">${esc(v.committedTransactions.join(", ") || "—")}</div></div>
      <div class="summ-item"><div class="k">显式 abort 事务</div><div class="v">${esc(v.abortedTransactions.join(", ") || "—")}</div></div>
      <div class="summ-item"><div class="k">失败（撤销）事务</div><div class="v">${esc(v.loserTransactions.join(", ") || "—")}</div></div>
      <div class="summ-item"><div class="k">重做起点 min recLSN</div><div class="v">${lsn(v.redoStartLSN)}</div></div>
      <div class="summ-item"><div class="k">实际重做条数</div><div class="v">${v.redone}</div></div>
      <div class="summ-item"><div class="k">实际撤销条数</div><div class="v">${v.undone}</div></div>
      <div class="summ-item"><div class="k">恢复末脏页表</div><div class="v" style="font-size:13px">${esc(dptText)}</div></div>
    </div>`;

  els.pagesBody.innerHTML = "";
  for (const p of v.pages) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="monospace">${p.page}</td>
      <td><span class="pill ${p.changed ? "altered" : "unchanged"}">${p.changed ? "已改写" : "未改变"}</span></td>
      <td class="monospace">${lsn(p.pageLSNBefore)}</td>
      <td class="monospace">${lsn(p.pageLSNAfter)}</td>
      <td class="monospace" title="${esc(p.sha256Before)}">${shortSha(p.sha256Before)}</td>
      <td class="monospace" title="${esc(p.sha256After)}">${shortSha(p.sha256After)}</td>`;
    els.pagesBody.appendChild(tr);
  }

  renderTrace(v.trace);
}

function renderTrace(trace) {
  const phases = new Set(
    Array.from(els.filters).filter((c) => c.checked).map((c) => c.dataset.phase)
  );
  const onlyChanged = els.onlyChanged.checked;
  els.traceBody.innerHTML = "";
  for (const t of trace) {
    if (!phases.has(t.phase)) continue;
    if (onlyChanged && !t.changed) continue;
    const tr = document.createElement("tr");
    const changedPill = t.changed
      ? '<span class="pill altered">改写</span>'
      : (t.type === "redo-start" || t.type === "undo-start" || t.type === "checkpoint")
        ? ""
        : '<span class="pill unchanged">未写页</span>';
    tr.innerHTML = `
      <td><span class="pill ${t.phase}">${t.phase}</span></td>
      <td class="monospace">${lsn(t.lsn)}</td>
      <td>${esc(t.type)} ${changedPill}</td>
      <td>${esc(t.xid || "—")}</td>
      <td class="monospace">${lsn(t.page)}</td>
      <td style="max-width:430px">${esc(t.criterion)}</td>
      <td style="max-width:430px">${esc(t.decision)}</td>
      <td class="monospace">${lsn(t.pageLSNBefore)}</td>
      <td class="monospace">${lsn(t.pageLSNAfter)}</td>`;
    els.traceBody.appendChild(tr);
  }
  if (!els.traceBody.children.length) {
    els.traceBody.innerHTML = '<tr><td colspan="9" style="color:var(--muted)">当前过滤条件下无记录</td></tr>';
  }
}

async function submitRecovery() {
  let payload;
  try {
    payload = JSON.parse(els.payload.value);
  } catch (e) {
    setStatus("err", `JSON 解析失败：${e.message}`);
    return;
  }
  const id = els.auditId.value.trim();
  if (!id) {
    setStatus("err", "请先填写稳定审计标识");
    return;
  }
  if (payload && typeof payload === "object") payload.auditId = id;

  setStatus("info", "恢复执行中…");
  try {
    const resp = await fetch("/api/recover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (resp.ok && data.status === "accepted") {
      setStatus("ok", `恢复完成，裁决已冻结（auditId=${data.verdict.auditId}）。可随时用该标识重新读取。`);
      renderVerdict(data.verdict);
    } else {
      els.verdictCard.classList.add("hidden");
      setStatus("err", `稳定拒绝（HTTP ${resp.status}）：${data.error}`);
    }
  } catch (e) {
    setStatus("err", `请求失败：${e.message}`);
  }
}

async function lookupVerdict() {
  const id = els.lookupId.value.trim() || els.auditId.value.trim();
  if (!id) {
    setStatus("err", "请输入要读取的 auditId");
    return;
  }
  setStatus("info", `读取 ${id} 的冻结裁决…`);
  try {
    const resp = await fetch(`/api/audit?auditId=${encodeURIComponent(id)}`);
    const data = await resp.json();
    if (resp.status === 404) {
      els.verdictCard.classList.add("hidden");
      setStatus("info", data.error || "无冻结裁决");
      return;
    }
    if (data.status === "accepted") {
      setStatus("ok", `已读取冻结裁决（auditId=${data.verdict.auditId}）。`);
      renderVerdict(data.verdict);
    } else {
      els.verdictCard.classList.add("hidden");
      setStatus("err", `该标识的记录为稳定拒绝：${data.error}`);
    }
  } catch (e) {
    setStatus("err", `请求失败：${e.message}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  els.submit.addEventListener("click", submitRecovery);
  els.lookup.addEventListener("click", lookupVerdict);
  els.loadSample.addEventListener("click", () => {
    if (sampleCache) {
      els.payload.value = JSON.stringify(sampleCache, null, 2);
      els.auditId.value = sampleCache.auditId;
      setStatus("info", "已载入样例。");
    }
  });
  els.formatJson.addEventListener("click", () => {
    try {
      els.payload.value = JSON.stringify(JSON.parse(els.payload.value), null, 2);
      setStatus("info", "JSON 已格式化。");
    } catch (e) {
      setStatus("err", `无法格式化：${e.message}`);
    }
  });
  for (const c of els.filters) c.addEventListener("change", () => {
    const card = els.verdictCard;
    if (!card.classList.contains("hidden") && window._lastTrace) {
      renderTrace(window._lastTrace);
    }
  });
  els.onlyChanged.addEventListener("change", () => {
    if (window._lastTrace) renderTrace(window._lastTrace);
  });

  fetch("/api/sample")
    .then((r) => r.json())
    .then((s) => {
      sampleCache = s;
      els.payload.value = JSON.stringify(s, null, 2);
      els.auditId.value = s.auditId;
    })
    .catch(() => {
      els.payload.value = "{}";
    });
});
