(function () {
    const meta = JSON.parse(document.getElementById("scanMeta").textContent);
    const consoleEl = document.getElementById("console");
    let lastLogId = 0;
    let polling = true;
    let startTime = Date.now();

    const LEVEL_PREFIX = {
        info: "[*]", success: "[+]", warning: "[!]", error: "[x]", cmd: "",
    };

    function appendLogs(logs) {
        const atBottom = consoleEl.scrollTop + consoleEl.clientHeight >=
            consoleEl.scrollHeight - 40;
        for (const log of logs) {
            const p = document.createElement("p");
            p.className = "ln ln-" + log.level;
            const prefix = LEVEL_PREFIX[log.level] ?? "[*]";
            const phase = log.phase ? `<span class="phase">${log.phase}</span> ` : "";
            p.innerHTML = `<span class="phase">${log.ts}</span> ${phase}` +
                escapeHtml((prefix ? prefix + " " : "") + log.message);
            consoleEl.appendChild(p);
            lastLogId = Math.max(lastLogId, log.id);
        }
        if (atBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    function escapeHtml(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    function fmt(sec) {
        sec = Math.max(0, Math.round(sec));
        if (sec < 60) return sec + "s";
        const m = Math.floor(sec / 60), s = sec % 60;
        if (m < 60) return `${m}m ${s}s`;
        const h = Math.floor(m / 60);
        return `${h}h ${m % 60}m`;
    }

    function update(data) {
        document.getElementById("phaseLabel").textContent = data.phase;
        document.getElementById("progressPct").textContent = data.progress + "%";
        document.getElementById("progressBar").style.width = data.progress + "%";
        document.getElementById("statusPill").textContent =
            data.status.charAt(0).toUpperCase() + data.status.slice(1);
        document.getElementById("currentTask").textContent = data.current_task || "";
        document.getElementById("mTasks").textContent =
            data.completed_tasks + "/" + data.total_tasks;
        document.getElementById("mReq").textContent = data.total_requests;
        document.getElementById("mUrls").textContent = data.total_urls;
        document.getElementById("mElapsed").textContent = data.duration || "0s";

        // ETA from progress rate.
        const elapsed = (Date.now() - startTime) / 1000;
        if (data.progress > 3 && data.progress < 100) {
            const est = elapsed / data.progress * (100 - data.progress);
            document.getElementById("mEta").textContent = fmt(est);
        } else if (data.progress >= 100) {
            document.getElementById("mEta").textContent = "0s";
        }

        const c = data.severity_counts || {};
        for (const k of ["critical", "high", "medium", "low", "info"]) {
            const el = document.getElementById("c-" + k);
            if (el) el.textContent = c[k] || 0;
        }

        if (data.logs && data.logs.length) appendLogs(data.logs);

        if (data.done) {
            polling = false;
            document.getElementById("radarIcon").classList.remove("spin");
            document.getElementById("progressBar").classList.remove(
                "progress-bar-animated", "progress-bar-striped");
            if (data.status === "completed") {
                document.getElementById("progressBar").classList.add("bg-success");
                const btn = document.getElementById("reportBtn");
                btn.classList.remove("d-none");
                btn.href = data.report_url;
                setTimeout(() => { window.location.href = data.report_url; }, 1200);
            } else {
                document.getElementById("progressBar").classList.add("bg-danger");
            }
        }
    }

    function poll() {
        if (!polling) return;
        fetch(meta.statusUrl + "?after=" + lastLogId)
            .then(r => r.json())
            .then(update)
            .catch(() => {})
            .finally(() => { if (polling) setTimeout(poll, 1500); });
    }

    poll();
})();
