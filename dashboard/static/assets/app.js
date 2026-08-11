(() => {
  const $ = (id) => document.getElementById(id);

  const els = {
    modePill: $("modePill"),
    modeLabel: $("modeLabel"),
    clock: $("clock"),
    countTotal: $("countTotal"),
    countLow: $("countLow"),
    countMedium: $("countMedium"),
    countHigh: $("countHigh"),
    feed: $("feed"),
    feedHint: $("feedHint"),
    streams: $("streams"),
    inputs: $("inputs"),
    uptime: $("uptime"),
    spark: $("spark"),
    netDevices: $("netDevices"),
    netFlows: $("netFlows"),
    netBytesOut: $("netBytesOut"),
    netBytesIn: $("netBytesIn"),
    protoBars: $("protoBars"),
    flowBody: $("flowBody"),
    talkers: $("talkers"),
    netHint: $("netHint"),
  };

  let seen = new Set();
  const sparkCtx = els.spark.getContext("2d");

  function fmtTime(iso) {
    try {
      return new Date(iso).toISOString().slice(11, 19) + "Z";
    } catch {
      return "--:--:--Z";
    }
  }

  function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v < 1024) return `${v} B`;
    if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
    if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
    return `${(v / 1024 ** 3).toFixed(2)} GB`;
  }

  function renderSpark(points) {
    const ctx = sparkCtx;
    const w = els.spark.width;
    const h = els.spark.height;
    ctx.clearRect(0, 0, w, h);
    if (!points.length) return;
    const vals = points.map((p) => p.n || 0);
    const max = Math.max(3, ...vals);
    ctx.strokeStyle = "rgba(61,255,154,0.9)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    vals.forEach((v, i) => {
      const x = (i / Math.max(vals.length - 1, 1)) * (w - 4) + 2;
      const y = h - 4 - (v / max) * (h - 12);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.lineTo(w - 2, h - 2);
    ctx.lineTo(2, h - 2);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "rgba(61,255,154,0.25)");
    grad.addColorStop(1, "rgba(61,255,154,0)");
    ctx.fillStyle = grad;
    ctx.fill();
  }

  function renderFeed(events) {
    const frag = document.createDocumentFragment();
    let fresh = 0;
    for (const event of events.slice(0, 60)) {
      if (!seen.has(event.id)) {
        seen.add(event.id);
        fresh += 1;
      }
      const li = document.createElement("li");
      li.className = "feed-item";
      li.dataset.sev = event.severity;
      li.innerHTML = `
        <div class="sev">${event.severity}</div>
        <div class="body">
          <div class="meta">${fmtTime(event.ts)} · ${escapeHtml(event.source)} · ${escapeHtml(event.origin || "")}</div>
          <div class="msg">${escapeHtml(event.message)}</div>
        </div>`;
      frag.appendChild(li);
    }
    els.feed.replaceChildren(frag);
    els.feedHint.textContent = fresh ? `+${fresh} this update` : "streaming";
  }

  function renderStreams(streams, counts) {
    const total = Math.max(1, counts.total || 1);
    els.streams.innerHTML = streams
      .map((s) => {
        const matches = s.matches || counts[s.severity] || 0;
        const pct = s.severity === "network"
          ? Math.min(100, Math.round((matches / Math.max(1, matches + (counts.total || 0))) * 100) || (matches ? 40 : 0))
          : Math.min(100, Math.round((matches / total) * 100));
        return `<li class="stream-row">
          <span>${escapeHtml(s.name)}</span>
          <div class="bar ${s.severity}"><span style="width:${pct}%"></span></div>
          <strong>${matches}</strong>
        </li>`;
      })
      .join("");
  }

  function renderInputs(inputs) {
    els.inputs.innerHTML = inputs
      .map((i) => {
        const st = (i.status || "unknown").toLowerCase();
        return `<li class="input-row">
          <span>${escapeHtml(i.name)}${i.port ? ` :${i.port}` : ""}</span>
          <span class="status-dot ${st}" title="${st}"></span>
        </li>`;
      })
      .join("");
  }

  function renderProtocols(protocols) {
    const entries = Object.entries(protocols || {});
    const sum = Math.max(1, entries.reduce((a, [, v]) => a + (v || 0), 0));
    els.protoBars.innerHTML = entries
      .map(([name, value]) => {
        const pct = Math.round(((value || 0) / sum) * 100);
        return `<div class="proto-row">
          <span>${escapeHtml(name)}</span>
          <div class="bar network"><span style="width:${pct}%"></span></div>
          <strong>${pct}%</strong>
        </div>`;
      })
      .join("");
  }

  function renderFlows(flows) {
    if (!flows.length) {
      els.flowBody.innerHTML = `<tr><td colspan="7" class="empty">No home network flows yet — run generate-home-traffic.sh or use demo mode</td></tr>`;
      return;
    }
    els.flowBody.innerHTML = flows
      .slice(0, 24)
      .map((f) => {
        const arrow = `${escapeHtml(f.src)} → ${escapeHtml(f.dst)}`;
        return `<tr data-sev="${escapeHtml(f.severity || "low")}" class="flow-row">
          <td>${fmtTime(f.ts)}</td>
          <td>${escapeHtml(f.device || "—")}</td>
          <td class="mono-tight">${arrow}</td>
          <td>${escapeHtml(f.proto || "")}</td>
          <td>${escapeHtml(String(f.dport ?? ""))}</td>
          <td>${fmtBytes(f.bytes)}</td>
          <td>${escapeHtml(f.dns || "—")}</td>
        </tr>`;
      })
      .join("");
  }

  function renderTalkers(talkers) {
    if (!talkers.length) {
      els.talkers.innerHTML = `<li class="empty">No talkers yet</li>`;
      return;
    }
    const max = Math.max(1, ...talkers.map((t) => t.bytes || 0));
    els.talkers.innerHTML = talkers
      .map((t) => {
        const pct = Math.min(100, Math.round(((t.bytes || 0) / max) * 100));
        return `<li class="talker-row">
          <div class="talker-meta">
            <strong>${escapeHtml(t.name)}</strong>
            <span>${escapeHtml(t.ip)} · ${escapeHtml(t.role || "host")} · ${t.flows || 0} flows</span>
          </div>
          <div class="bar network"><span style="width:${pct}%"></span></div>
          <div class="talker-bytes">${fmtBytes(t.bytes)}</div>
        </li>`;
      })
      .join("");
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function applySnapshot(data) {
    const mode = data.mode || "demo";
    els.modePill.dataset.mode = mode;
    els.modeLabel.textContent = mode === "live" ? "LIVE GRAYLOG" : "DEMO FEED";
    els.clock.textContent = fmtTime(data.server_time);
    els.countTotal.textContent = data.counts?.total ?? 0;
    els.countLow.textContent = data.counts?.low ?? 0;
    els.countMedium.textContent = data.counts?.medium ?? 0;
    els.countHigh.textContent = data.counts?.high ?? 0;
    els.uptime.textContent = `uptime ${formatUptime(data.uptime_s || 0)} · ${data.graylog_ok ? "Graylog reachable" : "Graylog offline — demo mode"}`;
    renderFeed(data.events || []);
    renderStreams(data.streams || [], data.counts || {});
    renderInputs(data.inputs || []);
    renderSpark(data.throughput || []);

    const net = data.network || {};
    els.netDevices.textContent = net.active_devices ?? 0;
    els.netFlows.textContent = net.flows_seen ?? 0;
    els.netBytesOut.textContent = fmtBytes(net.bytes_out);
    els.netBytesIn.textContent = fmtBytes(net.bytes_in);
    renderProtocols(net.protocols || {});
    renderFlows(net.flows || []);
    renderTalkers(net.top_talkers || []);
    els.netHint.textContent = mode === "live"
      ? `${net.flows?.length || 0} recent flows · live`
      : `${net.flows?.length || 0} recent flows · demo LAN`;
  }

  function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h}h ${m}m ${s}s`;
  }

  function connectSSE() {
    const es = new EventSource("/api/stream");
    es.onmessage = (ev) => {
      try {
        applySnapshot(JSON.parse(ev.data));
      } catch (_) {
        /* ignore malformed frames */
      }
    };
    es.onerror = () => {
      els.feedHint.textContent = "reconnecting…";
      els.netHint.textContent = "reconnecting…";
      es.close();
      setTimeout(connectSSE, 2000);
    };
  }

  // First paint via snapshot, then SSE
  fetch("/api/snapshot")
    .then((r) => r.json())
    .then(applySnapshot)
    .catch(() => {
      els.feedHint.textContent = "waiting for API…";
      els.netHint.textContent = "waiting for API…";
    })
    .finally(connectSSE);
})();
