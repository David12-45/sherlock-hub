(() => {
  "use strict";

  const TYPE_LABELS = {
    auto: "Авто",
    username: "Username",
    email: "Email",
    phone: "Телефон",
    domain: "Домен",
  };

  const CATEGORY_LABELS = {
    all: "Все",
    multi: "≥2 движка",
    coding: "Код и Dev",
    social: "Соцсети",
    forum: "Форумы",
    media: "Медиа",
    identity: "Идентичность",
    email: "Email",
    phone: "Телефон",
    dns: "DNS / Домен",
    other: "Другое",
  };

  const state = {
    engines: [],
    selectedEngines: new Set(),
    queryType: "auto",
    detectedType: "username",
    depth: "standard",
    activeCategory: "all",
    filterText: "",
    currentReportId: null,
    findings: [],
    summary: null,
    engineRuns: new Map(),
    eventSource: null,
    history: [],
  };

  const $ = (id) => document.getElementById(id);

  const els = {
    searchSection: $("search-section"),
    form: $("search-form"),
    input: $("query-input"),
    detectedTag: $("detected-tag"),
    btnSubmit: $("btn-submit"),
    btnStop: $("btn-stop"),
    typeSeg: $("type-segmented"),
    depthSeg: $("depth-segmented"),
    enginesInline: $("engines-inline"),
    enginesBadge: $("engines-badge"),
    historyBadge: $("history-badge"),
    progressStrip: $("progress-strip"),
    runDot: $("run-dot"),
    progressHeading: $("progress-heading"),
    progressMeta: $("progress-meta"),
    engineChips: $("engine-chips"),
    dossierBar: $("dossier-bar"),
    dossierAvatar: $("dossier-avatar"),
    dossierType: $("dossier-type"),
    dossierTime: $("dossier-time"),
    dossierTitle: $("dossier-title"),
    dossierBio: $("dossier-bio"),
    dossierFacts: $("dossier-facts"),
    metricUnique: $("metric-unique"),
    metricMulti: $("metric-multi"),
    exportGroup: $("export-group"),
    resultsSection: $("results-section"),
    filterTabs: $("filter-tabs"),
    resultsFilter: $("results-filter"),
    resultsList: $("results-list"),
    emptyState: $("empty-state"),
    drawerBackdrop: $("drawer-backdrop"),
    drawer: $("drawer"),
    drawerTitle: $("drawer-title"),
    drawerBody: $("drawer-body"),
    drawerClose: $("drawer-close"),
    btnEngines: $("btn-engines"),
    btnHistory: $("btn-history"),
    brandReset: $("brand-reset"),
  };

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function detectLocalType(raw) {
    const v = raw.trim();
    if (!v) return "auto";
    if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return "email";
    const digits = v.replace(/\D/g, "");
    if (/^\+?[\d][\d\s\-().]{6,20}\d$/.test(v) && digits.length >= 7 && digits.length <= 15 && !/[a-zA-Z]/.test(v)) {
      return "phone";
    }
    if (!v.startsWith("@") && /^(?:https?:\/\/)?(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}\/?$/.test(v)) {
      return "domain";
    }
    return "username";
  }

  function effectiveType() {
    if (state.queryType !== "auto") return state.queryType;
    const d = detectLocalType(els.input.value);
    return d === "auto" ? "username" : d;
  }

  function updateDetectedBadge() {
    const raw = els.input.value.trim();
    if (state.queryType !== "auto") {
      els.detectedTag.textContent = TYPE_LABELS[state.queryType];
      els.detectedTag.classList.add("is-detected");
    } else if (!raw) {
      els.detectedTag.textContent = "Авто";
      els.detectedTag.classList.remove("is-detected");
    } else {
      const det = detectLocalType(raw);
      els.detectedTag.textContent = TYPE_LABELS[det] || "Username";
      els.detectedTag.classList.add("is-detected");
    }
    renderInlineEngines();
  }

  function renderInlineEngines() {
    const qtype = effectiveType();
    const relevant = state.engines.filter((e) => {
      if (e.supported_types.includes(qtype)) return true;
      // For email, also show username engines used for cross-check
      if (qtype === "email" && ["direct-apis", "sherlock", "maigret"].includes(e.id)) return true;
      return false;
    });

    els.enginesInline.innerHTML = relevant
      .map((e) => {
        const checked = e.available && state.selectedEngines.has(e.id);
        const cls = `engine-toggle ${checked ? "checked" : ""} ${!e.available ? "unavailable" : ""}`;
        return `
          <label class="${cls}" title="${escapeHtml(e.available ? e.description : (e.availability_note || "Не установлен"))}">
            <input type="checkbox" data-engine="${escapeHtml(e.id)}" ${checked ? "checked" : ""} ${!e.available ? "disabled" : ""}>
            <span>${escapeHtml(e.name)}</span>
          </label>
        `;
      })
      .join("");

    els.enginesInline.querySelectorAll("input[data-engine]").forEach((cb) => {
      cb.addEventListener("change", () => {
        const id = cb.dataset.engine;
        if (cb.checked) state.selectedEngines.add(id);
        else state.selectedEngines.delete(id);
        cb.closest(".engine-toggle").classList.toggle("checked", cb.checked);
      });
    });
  }

  async function loadEngines() {
    try {
      const res = await fetch("/api/engines");
      state.engines = await res.json();
      state.selectedEngines = new Set(
        state.engines.filter((e) => e.available && e.default_enabled).map((e) => e.id)
      );
      const avail = state.engines.filter((e) => e.available).length;
      els.enginesBadge.textContent = `${avail}/${state.engines.length}`;
      renderInlineEngines();
    } catch (err) {
      els.enginesBadge.textContent = "!";
    }
  }

  async function loadHistory() {
    try {
      const res = await fetch("/api/history?limit=40");
      state.history = await res.json();
      els.historyBadge.textContent = String(state.history.length);
    } catch (_) {}
  }

  function stopStream() {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
    els.btnSubmit.disabled = false;
    els.btnStop.classList.add("hidden");
    els.runDot.classList.remove("running");
  }

  function renderEngineChips() {
    const items = Array.from(state.engineRuns.values());
    els.engineChips.innerHTML = items
      .map((e) => {
        const sec = e.elapsed_ms ? `${(e.elapsed_ms / 1000).toFixed(1)}s` : "…";
        const stat =
          e.status === "running"
            ? "поиск…"
            : e.status === "error"
            ? "ошибка"
            : `${e.findings_count} · ${sec}`;
        return `
          <div class="engine-chip ${escapeHtml(e.status)}" title="${escapeHtml(e.message || "")}">
            <span>${escapeHtml(e.engine_name)}</span>
            <span class="chip-stat">${escapeHtml(stat)}</span>
          </div>
        `;
      })
      .join("");
  }

  function renderDossier(query, detectedType, summary, totalUnique, multiCount, elapsedMs, reportId) {
    els.dossierBar.classList.remove("hidden");
    els.dossierType.textContent = TYPE_LABELS[detectedType] || detectedType;
    els.dossierTitle.textContent = query;
    els.dossierTime.textContent = elapsedMs != null ? `Завершено за ${(elapsedMs / 1000).toFixed(1)}s` : "Сканирование…";
    els.metricUnique.textContent = String(totalUnique || 0);
    els.metricMulti.textContent = String(multiCount || 0);

    if (reportId) {
      state.currentReportId = reportId;
      els.exportGroup.classList.remove("hidden");
    } else {
      els.exportGroup.classList.add("hidden");
    }

    const s = summary || {};
    if (s.avatars && s.avatars.length > 0) {
      els.dossierAvatar.src = s.avatars[0];
      els.dossierAvatar.classList.remove("hidden");
      els.dossierAvatar.onerror = () => els.dossierAvatar.classList.add("hidden");
    } else {
      els.dossierAvatar.classList.add("hidden");
    }

    if (s.bios && s.bios.length > 0) {
      els.dossierBio.textContent = s.bios[0];
      els.dossierBio.classList.remove("hidden");
    } else {
      els.dossierBio.classList.add("hidden");
    }

    const facts = [];
    if (s.display_names && s.display_names.length) {
      facts.push(["Имена", s.display_names.join(", ")]);
    }
    if (s.locations && s.locations.length) {
      facts.push(["Локация", s.locations.join(", ")]);
    }
    if (s.websites && s.websites.length) {
      facts.push(["Сайт", s.websites[0]]);
    }
    if (s.extra && s.extra.mail_provider) {
      facts.push(["Почтовый сервер", s.extra.mail_provider]);
    }
    if (s.extra && s.extra.phone) {
      const p = s.extra.phone;
      if (p.location) facts.push(["Регион", p.location]);
      if (p.carrier && p.carrier !== "Не определён") facts.push(["Оператор", p.carrier]);
      if (p.line_type) facts.push(["Тип линии", p.line_type]);
    }
    if (s.extra && s.extra.registrar) {
      facts.push(["Регистратор", s.extra.registrar]);
    }

    els.dossierFacts.innerHTML = facts
      .map(([k, v]) => `<span class="fact-item"><strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)}</span>`)
      .join("");
  }

  function renderFilterTabs() {
    const counts = { all: state.findings.length, multi: 0 };
    for (const f of state.findings) {
      if ((f.sources || []).length > 1) counts.multi += 1;
      counts[f.category] = (counts[f.category] || 0) + 1;
    }

    const order = ["all", "multi", "coding", "social", "forum", "media", "identity", "email", "phone", "dns", "other"];
    const tabs = order.filter((k) => k === "all" || (counts[k] || 0) > 0);

    if (!tabs.includes(state.activeCategory)) state.activeCategory = "all";

    els.filterTabs.innerHTML = tabs
      .map(
        (cat) => `
        <button type="button" class="tab-btn ${state.activeCategory === cat ? "active" : ""}" data-cat="${cat}">
          <span>${escapeHtml(CATEGORY_LABELS[cat] || cat)}</span>
          <span class="tab-count">${counts[cat] || 0}</span>
        </button>
      `
      )
      .join("");

    els.filterTabs.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.activeCategory = btn.dataset.cat;
        renderFilterTabs();
        renderResultsList();
      });
    });
  }

  function renderResultsList() {
    els.resultsSection.classList.remove("hidden");
    const q = state.filterText.trim().toLowerCase();

    const filtered = state.findings.filter((f) => {
      if (state.activeCategory === "multi" && (f.sources || []).length < 2) return false;
      if (state.activeCategory !== "all" && state.activeCategory !== "multi" && f.category !== state.activeCategory) {
        return false;
      }
      if (q) {
        const hay = `${f.site} ${f.url || ""} ${f.snippet || ""} ${(f.sources || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      els.resultsList.innerHTML = "";
      els.emptyState.classList.remove("hidden");
      return;
    }
    els.emptyState.classList.add("hidden");

    els.resultsList.innerHTML = filtered
      .map((f, idx) => {
        const multi = (f.sources || []).length > 1;
        const hasMeta = f.metadata && Object.keys(f.metadata).length > 0;
        const confPct = Math.round((f.confidence || 0.75) * 100);
        const urlHtml = f.url
          ? `<a class="finding-url" href="${escapeHtml(f.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(f.url)}</a>`
          : `<span class="mono muted" style="font-size:12px;">Пассивная запись (без URL)</span>`;
        const snippetHtml = f.snippet ? `<p class="finding-snippet">${escapeHtml(f.snippet)}</p>` : "";
        const metaHtml = hasMeta
          ? `
            <button type="button" class="finding-meta-toggle" data-meta-idx="${idx}">+ Подробные метаданные</button>
            <pre class="finding-meta-pre hidden" id="meta-pre-${idx}">${escapeHtml(JSON.stringify(f.metadata, null, 2))}</pre>
          `
          : "";
        const badgesHtml = (f.sources || [])
          .map((s) => `<span class="source-badge ${multi ? "multi" : ""}">${escapeHtml(s)}</span>`)
          .join("");

        return `
          <div class="finding-row">
            <div class="finding-site-col">
              <span class="finding-site">${escapeHtml(f.site)}</span>
              <span class="finding-cat">${escapeHtml(CATEGORY_LABELS[f.category] || f.category)}</span>
            </div>
            <div class="finding-body">
              ${urlHtml}
              ${snippetHtml}
              ${metaHtml}
            </div>
            <div class="finding-right">
              <div class="source-badges">${badgesHtml}</div>
              <span class="conf-text">${confPct}% уверенность</span>
            </div>
          </div>
        `;
      })
      .join("");

    els.resultsList.querySelectorAll(".finding-meta-toggle").forEach((btn) => {
      btn.addEventListener("click", () => {
        const pre = $(`meta-pre-${btn.dataset.metaIdx}`);
        const isHidden = pre.classList.toggle("hidden");
        btn.textContent = isHidden ? "+ Подробные метаданные" : "− Скрыть метаданные";
      });
    });
  }

  function startSearch(query) {
    stopStream();

    const cleaned = query.trim();
    if (!cleaned) return;

    els.searchSection.classList.add("compact");
    els.btnSubmit.disabled = true;
    els.btnStop.classList.remove("hidden");
    els.progressStrip.classList.remove("hidden");
    els.runDot.classList.remove("error");
    els.runDot.classList.add("running");
    els.progressHeading.textContent = `Запуск движков для «${cleaned}»…`;
    els.progressMeta.textContent = "";

    state.findings = [];
    state.summary = null;
    state.currentReportId = null;
    state.activeCategory = "all";
    state.engineRuns.clear();

    const params = new URLSearchParams({
      q: cleaned,
      query_type: state.queryType,
      depth: state.depth,
    });
    if (state.selectedEngines.size > 0) {
      params.set("engines", Array.from(state.selectedEngines).join(","));
    }

    const es = new EventSource(`/api/search/stream?${params.toString()}`);
    state.eventSource = es;

    es.addEventListener("started", (ev) => {
      const data = JSON.parse(ev.data);
      state.detectedType = data.detected_type;
      state.engineRuns.clear();
      for (const e of data.engines || []) {
        state.engineRuns.set(e.engine_id, e);
      }
      renderEngineChips();
      els.progressHeading.textContent = `Поиск «${data.query}» по ${data.engines.length} движкам…`;
      els.progressMeta.textContent = `0 / ${data.engines.length}`;
      renderDossier(data.query, data.detected_type, null, 0, 0, null, null);
    });

    es.addEventListener("engine_update", (ev) => {
      const data = JSON.parse(ev.data);
      state.engineRuns.set(data.engine.engine_id, data.engine);
      state.findings = data.findings || [];
      state.summary = data.summary || null;

      renderEngineChips();
      els.progressMeta.textContent = `${data.completed} / ${data.total}`;
      renderDossier(
        els.dossierTitle.textContent || cleaned,
        state.detectedType,
        state.summary,
        data.total_unique,
        data.multi_source_confirmed,
        null,
        null
      );
      renderFilterTabs();
      renderResultsList();
    });

    es.addEventListener("completed", (ev) => {
      const report = JSON.parse(ev.data);
      state.findings = report.findings || [];
      state.summary = report.summary || null;
      state.engineRuns.clear();
      for (const e of report.engines || []) {
        state.engineRuns.set(e.engine_id, e);
      }
      renderEngineChips();
      els.progressHeading.textContent = `Поиск завершён · ${report.total_unique} уникальных находок`;
      els.progressMeta.textContent = `${(report.elapsed_ms / 1000).toFixed(1)}s`;
      renderDossier(
        report.query,
        report.detected_type,
        report.summary,
        report.total_unique,
        report.multi_source_confirmed,
        report.elapsed_ms,
        report.id
      );
      renderFilterTabs();
      renderResultsList();
      stopStream();
      loadHistory();
    });

    es.onerror = () => {
      if (state.eventSource) {
        els.progressHeading.textContent = "Соединение прервано";
        els.runDot.classList.add("error");
        stopStream();
      }
    };
  }

  async function openReportById(id) {
    closeDrawer();
    const res = await fetch(`/api/reports/${encodeURIComponent(id)}`);
    if (!res.ok) return;
    const report = await res.json();
    els.input.value = report.query;
    updateDetectedBadge();
    els.searchSection.classList.add("compact");
    els.progressStrip.classList.remove("hidden");
    els.runDot.classList.remove("running", "error");
    els.progressHeading.textContent = `Загружен сохранённый отчёт (${report.created_at.slice(0, 16).replace("T", " ")} UTC)`;
    els.progressMeta.textContent = `${(report.elapsed_ms / 1000).toFixed(1)}s`;

    state.engineRuns.clear();
    for (const e of report.engines || []) state.engineRuns.set(e.engine_id, e);
    renderEngineChips();

    state.findings = report.findings || [];
    state.summary = report.summary || null;
    state.activeCategory = "all";
    renderDossier(
      report.query,
      report.detected_type,
      report.summary,
      report.total_unique,
      report.multi_source_confirmed,
      report.elapsed_ms,
      report.id
    );
    renderFilterTabs();
    renderResultsList();
  }

  function openDrawer(title, htmlContent) {
    els.drawerTitle.textContent = title;
    els.drawerBody.innerHTML = htmlContent;
    els.drawerBackdrop.classList.remove("hidden");
    els.drawer.classList.remove("hidden");
  }

  function closeDrawer() {
    els.drawerBackdrop.classList.add("hidden");
    els.drawer.classList.add("hidden");
  }

  function showEnginesDrawer() {
    const html = state.engines
      .map(
        (e) => `
        <div class="drawer-item">
          <div class="drawer-item-head">
            <span class="drawer-item-title">${escapeHtml(e.name)}</span>
            <span class="status-pill ${e.available ? "ok" : "off"}">${e.available ? "Активен" : "Опционально"}</span>
          </div>
          <p class="drawer-item-desc">${escapeHtml(e.description)}</p>
          <div class="drawer-item-meta">
            типы: ${e.supported_types.join(", ")} · режим: ${escapeHtml(e.mode)}
            ${!e.available && e.availability_note ? `<br>${escapeHtml(e.availability_note)}` : ""}
          </div>
        </div>
      `
      )
      .join("");
    openDrawer("Реестр OSINT-движков", html);
  }

  async function showHistoryDrawer() {
    await loadHistory();
    if (!state.history.length) {
      openDrawer("История поисков", `<div class="empty-state">История пока пуста. Выполните первый поиск.</div>`);
      return;
    }
    const html = state.history
      .map(
        (h) => `
        <div class="drawer-item history-item" data-report-id="${escapeHtml(h.id)}">
          <div class="drawer-item-head">
            <span class="drawer-item-title mono">${escapeHtml(h.query)}</span>
            <button type="button" class="history-del" data-del-id="${escapeHtml(h.id)}" title="Удалить">Удалить</button>
          </div>
          <div class="drawer-item-meta">
            ${escapeHtml(TYPE_LABELS[h.detected_type] || h.detected_type)} · ${h.total_unique} находок (${h.multi_source_confirmed} ≥2) · ${(h.elapsed_ms / 1000).toFixed(1)}s
            <br>${escapeHtml(h.created_at.slice(0, 19).replace("T", " "))} UTC
          </div>
        </div>
      `
      )
      .join("");
    openDrawer("История поисков", html);

    els.drawerBody.querySelectorAll(".history-item").forEach((el) => {
      el.addEventListener("click", (ev) => {
        if (ev.target.closest(".history-del")) return;
        openReportById(el.dataset.reportId);
      });
    });

    els.drawerBody.querySelectorAll(".history-del").forEach((btn) => {
      btn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        await fetch(`/api/reports/${encodeURIComponent(btn.dataset.delId)}`, { method: "DELETE" });
        showHistoryDrawer();
      });
    });
  }

  // Wire events
  els.input.addEventListener("input", updateDetectedBadge);

  els.typeSeg.querySelectorAll(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      els.typeSeg.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.queryType = btn.dataset.type;
      updateDetectedBadge();
    });
  });

  els.depthSeg.querySelectorAll(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      els.depthSeg.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.depth = btn.dataset.depth;
    });
  });

  document.querySelectorAll(".example-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      els.input.value = chip.dataset.sample;
      updateDetectedBadge();
      startSearch(chip.dataset.sample);
    });
  });

  els.form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    startSearch(els.input.value);
  });

  els.btnStop.addEventListener("click", () => {
    els.progressHeading.textContent = "Поиск остановлен пользователем";
    stopStream();
  });

  els.resultsFilter.addEventListener("input", () => {
    state.filterText = els.resultsFilter.value;
    renderResultsList();
  });

  els.exportGroup.querySelectorAll("[data-export]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (!state.currentReportId) return;
      const fmt = btn.dataset.export;
      window.location.href = `/api/reports/${encodeURIComponent(state.currentReportId)}/export?fmt=${fmt}`;
    });
  });

  els.btnEngines.addEventListener("click", showEnginesDrawer);
  els.btnHistory.addEventListener("click", showHistoryDrawer);
  els.drawerClose.addEventListener("click", closeDrawer);
  els.drawerBackdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeDrawer();
  });

  els.brandReset.addEventListener("click", (ev) => {
    ev.preventDefault();
    stopStream();
    els.searchSection.classList.remove("compact");
    els.progressStrip.classList.add("hidden");
    els.dossierBar.classList.add("hidden");
    els.resultsSection.classList.add("hidden");
    els.input.value = "";
    updateDetectedBadge();
    els.input.focus();
  });

  // Boot
  loadEngines();
  loadHistory();
})();
