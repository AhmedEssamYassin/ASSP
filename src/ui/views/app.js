/**
 * Authenticated Secure Stream Protocol — client-side controller.
 * Bridges pywebview API calls with the transmission UI.
 */

let isTransmitting = false;
let progressPoller = null;
let pipelineStartTime = null;
let pipelineTimerInterval = null;

// Live timestamp
function updateTimestamp() {
    const el = document.getElementById("timestamp");
    if (el) el.textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
setInterval(updateTimestamp, 1000);
updateTimestamp();

const plaintextArea = document.getElementById("plaintext");
const charCount = document.getElementById("charCount");
function updateCharCount() {
    const n = plaintextArea.value.length;
    charCount.textContent = `${n} char${n !== 1 ? "s" : ""}`;
}
plaintextArea.addEventListener("input", updateCharCount);
updateCharCount();

let attachedLongText = null;

plaintextArea.addEventListener("paste", (e) => {
    const paste = (e.clipboardData || window.clipboardData).getData("text");
    if (paste.length > 5000) {
        e.preventDefault();
        attachedLongText = paste;
        
        plaintextArea.value = "";
        plaintextArea.placeholder = `[Long text attached: ${formatBytes(paste.length)}]\nClick here to remove attachment and type normally.`;
        plaintextArea.disabled = true;
        plaintextArea.style.cursor = "pointer";
        
        addLog("txLogs", `Long text detected (${formatBytes(paste.length)}). Attached as a file for streaming.`, "info");
        updateCharCount();
    }
});

plaintextArea.addEventListener("click", () => {
    if (attachedLongText) {
        attachedLongText = null;
        plaintextArea.disabled = false;
        plaintextArea.style.cursor = "text";
        plaintextArea.placeholder = "Enter the message to encrypt and transmit...";
        plaintextArea.value = "";
        updateCharCount();
        addLog("txLogs", "Long text attachment removed.", "info");
    }
});

// ─── Transmission ──────────────────────────────────────────────────────────

async function startTransmission() {
    if (isTransmitting) return;

    const plaintext = document.getElementById("plaintext").value.trim();
    const serverIp  = document.getElementById("serverIp").value.trim();
    const serverPort = document.getElementById("serverPort").value.trim();

    if (!plaintext && !attachedLongText) {
        addLog("txLogs", "Empty message — nothing to transmit.", "error");
        return;
    }
    if (!serverIp || !serverPort) {
        addLog("txLogs", "Server address or port is missing.", "error");
        return;
    }

    const portNum = parseInt(serverPort, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        addLog("txLogs", "Invalid port — must be a number between 1 and 65535.", "error");
        return;
    }

    if (attachedLongText) {
        isTransmitting = true;
        setStatus("transmitting", "Streaming");
        clearLogs();
        
        document.getElementById("transmitBtn").disabled = true;
        document.getElementById("sendFileBtn").disabled = true;

        try {
            const init = await callApi("sendLongText", attachedLongText, serverIp, serverPort);
            if (!init || init.status === "cancelled") {
                isTransmitting = false;
                return;
            }

            showFilePipeline(init.filename, init.size);
            addLog("txLogs", `Long text queued for stream pipeline (${formatBytes(init.size)})`, "info");

            pipelineStageComplete("file", `${escHtml(init.filename)} · ${formatBytes(init.size)}`);
            pipelineStageActivate("read", "Processing text buffer...");

            pipelineStartTime = Date.now();
            pipelineTimerInterval = setInterval(() => {
                const s = ((Date.now() - pipelineStartTime) / 1000).toFixed(1);
                const el = document.getElementById("fpTimer");
                if (el) el.textContent = s + "s";
            }, 100);

            progressPoller = setInterval(async () => {
                try {
                    const events = await callApi("fetchProgress");
                    if (events && events.length > 0) {
                        for (const evt of events) handleProgressEvent(evt);
                    }
                } catch (e) { console.error("Poll error:", e); }
            }, 150);
            
            // clear attachment
            attachedLongText = null;
            plaintextArea.disabled = false;
            plaintextArea.style.cursor = "text";
            plaintextArea.placeholder = "Enter the message to encrypt and transmit...";
            updateCharCount();

        } catch (err) {
            addLog("txLogs", `Error: ${err.message}`, "error");
            setStatus("error", "Error");
            isTransmitting = false;
            document.getElementById("transmitBtn").disabled = false;
            document.getElementById("sendFileBtn").disabled = false;
        }
        return;
    }

    isTransmitting = true;

    const btn = document.getElementById("transmitBtn");
    const lblEl = btn.querySelector(".btn-label");
    const ldrEl = btn.querySelector(".btn-loader");
    lblEl.style.display = "none";
    ldrEl.style.display = "flex";
    ldrEl.style.alignItems = "center";
    ldrEl.style.justifyContent = "center";
    ldrEl.style.width = "100%";
    btn.disabled = true;

    setStatus("transmitting", "Transmitting");
    clearLogs();
    resetStream();

    addLog("txLogs", `Connecting to ${serverIp}:${serverPort}`, "info");

    try {
        progressPoller = setInterval(async () => {
            try {
                const evts = await callApi("fetchProgress");
                if (evts && evts.length > 0) {
                    for (const evt of evts) handleProgressEvent(evt);
                }
            } catch (e) { console.error("Poll error:", e); }
        }, 150);

        const result = await callApi("runTransmission", plaintext, serverIp, serverPort);
        
        stopProgressPoller();

        if (result.success) {
            addLog("txLogs", "Handshake complete — keys exchanged.", "info");
            addLog("txLogs", "Ciphertext transmitted successfully.", "success");
            displayChunks(plaintext, result.cipherChunks || []);
            setStatus("active", "Transmitted");
        } else {
            addLog("txLogs", result.error || "Transmission failed.", "error");
            setStatus("error", "Failed");
        }
    } catch (err) {
        addLog("txLogs", `Unexpected error: ${err.message}`, "error");
        setStatus("error", "Error");
    } finally {
        btn.querySelector(".btn-label").style.display = "flex";
        btn.querySelector(".btn-loader").style.display = "none";
        btn.disabled = false;
        isTransmitting = false;
    }
}

async function startFileTransmission() {
    if (isTransmitting) return;

    const serverIp   = document.getElementById("serverIp").value.trim();
    const serverPort = document.getElementById("serverPort").value.trim();

    if (!serverIp || !serverPort) {
        addLog("txLogs", "Server address or port is missing.", "error");
        return;
    }

    const portNum = parseInt(serverPort, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        addLog("txLogs", "Invalid port — must be a number between 1 and 65535.", "error");
        return;
    }

    isTransmitting = true;
    setStatus("transmitting", "Selecting File");
    clearLogs();

    document.getElementById("transmitBtn").disabled  = true;
    const fileBtn = document.getElementById("sendFileBtn");
    fileBtn.disabled = true;

    try {
        // Opens the file dialog — blocks until user selects or cancels
        const init = await callApi("selectAndSendFile", serverIp, serverPort);

        if (!init || init.status === "cancelled") {
            addLog("txLogs", "No file selected.", "info");
            setStatus("", "Standby");
            return;
        }

        // Show the pipeline panel
        showFilePipeline(init.filename, init.size);
        addLog("txLogs", `File queued: ${init.filename} (${formatBytes(init.size)})`, "info");

        // Mark stage 1 done immediately (file was already selected)
        pipelineStageComplete("file", `${escHtml(init.filename)} · ${formatBytes(init.size)}`);
        pipelineStageActivate("read", "Loading file into memory...");

        // Start the live timer and the polling loop
        pipelineStartTime = Date.now();
        pipelineTimerInterval = setInterval(() => {
            const s = ((Date.now() - pipelineStartTime) / 1000).toFixed(1);
            document.getElementById("fpTimer").textContent = s + "s";
        }, 100);

        progressPoller = setInterval(async () => {
            try {
                const events = await callApi("fetchProgress");
                if (events && events.length > 0) {
                    for (const evt of events) handleProgressEvent(evt);
                }
            } catch (e) { console.error("Poll error:", e); }
        }, 150);

    } catch (err) {
        addLog("txLogs", `Error: ${err.message}`, "error");
        setStatus("error", "Error");
        isTransmitting = false;
        document.getElementById("transmitBtn").disabled  = false;
        document.getElementById("sendFileBtn").disabled = false;
    }
}

function handleProgressEvent(evt) {
    switch (evt.stage) {
        case "reading":
            pipelineStageActivate("read", "Reading bytes...");
            break;
        case "reading_done":
            pipelineStageComplete("read", `${formatBytes(evt.bytes)} loaded`);
            pipelineStageActivate("handshake", "Connecting to server...");
            addLog("txLogs", `Read ${formatBytes(evt.bytes)} from disk.`, "info");
            break;
        case "connected":
            pipelineStageDetail("handshake", "TCP connected — exchanging keys...");
            break;
        case "handshake":
            pipelineStageDetail("handshake", "X25519 ECDH + Ed25519 in progress...");
            break;
        case "sas_cached":
            pipelineStageDetail("handshake", "X25519 ECDH + Ed25519 (Cached)");
            addLog("txLogs", "Server identity verified (Cached from earlier).", "success");
            break;
        case "sas_verified":
            addLog("txLogs", "SAS Verification successful.", "success");
            break;
        case "sas_verification":
            showSasModal(evt.sas);
            break;
        case "handshake_done":
            pipelineStageComplete("handshake", "Keys verified · Seed vault delivered");
            pipelineStageActivate("encrypt", "Ready to stream...");
            addLog("txLogs", "Handshake complete — shared key derived.", "info");
            break;
        case "stream_start": {
            const n = evt.total_chunks;
            // Both stages activate together — they run in lock-step
            pipelineStageActivate("encrypt", `Streaming ${formatBytes(evt.total_bytes)} · ${n.toLocaleString()} chunks`);
            pipelineBarShow("encrypt");
            pipelineStageActivate("transmit", "Receiving encrypted frames...");
            pipelineBarShow("transmit");
            addLog("txLogs", `Streaming ${n.toLocaleString()} chunks — encrypt & send in lock-step.`, "info");
            break;
        }
        case "stream_progress": {
            const pct = Math.round((evt.sent / evt.total) * 100);
            // Update both bars with the same value
            pipelineBarUpdate("encrypt", pct);
            pipelineStageDetail("encrypt", `Chunk ${evt.sent.toLocaleString()} / ${evt.total.toLocaleString()}  ·  ${pct}%`);
            pipelineBarUpdate("transmit", pct);
            pipelineStageDetail("transmit", `Frame ${evt.sent.toLocaleString()} / ${evt.total.toLocaleString()}  ·  ${pct}%`);
            break;
        }
        case "stream_done": {
            const n = evt.total_chunks;
            pipelineStageComplete("encrypt",   `${n.toLocaleString()} chunks encrypted`);
            pipelineStageComplete("transmit",  `${n.toLocaleString()} frames transmitted`);
            pipelineBarUpdate("encrypt", 100);
            pipelineBarUpdate("transmit", 100);
            break;
        }
        case "complete":
            stopProgressPoller();
            if (evt.success) {
                pipelineStageComplete("transmit", `All ${(evt.total_chunks || 0).toLocaleString()} frames sent`);
                pipelineBarUpdate("transmit", 100);
                const elapsed = ((Date.now() - pipelineStartTime) / 1000).toFixed(2);
                showPipelineResult(true,
                    "File Received on Server ✓",
                    `${evt.filename} · ${(evt.total_chunks || 0).toLocaleString()} chunks · ${elapsed}s`);
                addLog("txLogs", "File transmitted and saved on server.", "success");
                setStatus("active", "Transmitted");
            } else {
                showPipelineResult(false,
                    "Transmission Failed",
                    evt.error || "Unknown error");
                addLog("txLogs", evt.error || "Transmission failed.", "error");
                setStatus("error", "Failed");
            }
            isTransmitting = false;
            document.getElementById("transmitBtn").disabled  = false;
            document.getElementById("sendFileBtn").disabled = false;
            break;
    }
}

function stopProgressPoller() {
    if (progressPoller)       clearInterval(progressPoller);
    if (pipelineTimerInterval) clearInterval(pipelineTimerInterval);
    progressPoller = pipelineTimerInterval = null;
}

// ─── Pipeline Helpers ────────────────────────────────────────────────────────

function showFilePipeline(filename, size) {
    // Reset all stages to pending
    ["file","read","handshake","encrypt","transmit"].forEach(id => {
        const s = document.getElementById(`fps-${id}`);
        if (s) s.dataset.state = "pending";
    });
    ["fpd-file","fpd-read","fpd-handshake","fpd-encrypt","fpd-transmit"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = "—";
    });
    ["fpb-encrypt","fpb-transmit"].forEach(id => {
        document.getElementById(id)?.classList.add("hidden");
    });
    ["fpbf-encrypt","fpbf-transmit"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.width = "0%";
    });
    document.getElementById("fpResult")?.classList.add("hidden");
    document.getElementById("fpTimer").textContent = "0.0s";
    document.getElementById("fpFilename").textContent = filename;
    document.getElementById("fpFilesize").textContent = formatBytes(size);

    // Switch stream panel content
    document.getElementById("pipeVisualizer").classList.add("hidden");
    document.getElementById("chunkDisplay").classList.add("hidden");
    document.getElementById("streamCounter").style.display = "none";
    document.getElementById("filePipeline").classList.remove("hidden");
}

function pipelineStageActivate(stageId, detail) {
    const el = document.getElementById(`fps-${stageId}`);
    if (el) el.dataset.state = "active";
    pipelineStageDetail(stageId, detail);
}

function pipelineStageComplete(stageId, detail) {
    const el = document.getElementById(`fps-${stageId}`);
    if (el) el.dataset.state = "done";
    if (detail !== undefined) pipelineStageDetail(stageId, detail);
}

function pipelineStageDetail(stageId, text) {
    const el = document.getElementById(`fpd-${stageId}`);
    if (el) el.textContent = text;
}

function pipelineBarShow(stageId) {
    document.getElementById(`fpb-${stageId}`)?.classList.remove("hidden");
}

function pipelineBarUpdate(stageId, pct) {
    const fill = document.getElementById(`fpbf-${stageId}`);
    if (fill) fill.style.width = pct + "%";
}

function showPipelineResult(success, title, sub) {
    const el      = document.getElementById("fpResult");
    const icon    = document.getElementById("fpResultIcon");
    const text    = document.getElementById("fpResultText");
    const subEl   = document.getElementById("fpResultSub");
    icon.className = `fp-result-icon ${success ? "success" : "error"}`;
    icon.textContent = success ? "✓" : "✗";
    text.textContent = title;
    subEl.textContent = sub;
    el.classList.remove("hidden");
}

function formatBytes(bytes) {
    if (bytes < 1024)        return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}


// ─── API Bridge ─────────────────────────────────────────────────────────────

async function callApi(method, ...args) {
    if (window.pywebview && window.pywebview.api) {
        return await window.pywebview.api[method](...args);
    }
    return simulateBackend(method, ...args);
}

async function simulateBackend(method, ...args) {
    await new Promise(r => setTimeout(r, 400));
    switch (method) {
        case "runTransmission": {
            const plaintext = args[0] ?? "";
            const CHUNK = 10;
            const chunks = [];
            for (let i = 0; i < plaintext.length; i += CHUNK) {
                chunks.push(btoa(plaintext.slice(i, i + CHUNK)).replace(/=/g, "").toLowerCase());
            }
            return { success: true, cipherChunks: chunks };
        }
        case "fetchMonitorData":
            return { metrics: { total_transmissions: 0, total_bytes_encrypted: 0, failed_transmissions: 0 }, history: [] };
        case "fetchProgress":
            return [];
        case "selectAndSendFile":
            return { status: "cancelled" };
        default:
            return null;
    }
}

// ─── Display Helpers ─────────────────────────────────────────────────────────

function displayChunks(plaintext, cipherChunks) {
    const idle = document.getElementById("pipeVisualizer");
    const table = document.getElementById("chunkDisplay");
    const tbody = document.getElementById("chunkRows");
    const counter = document.getElementById("streamCounter");
    const chunkCount = document.getElementById("chunkCount");

    idle.classList.add("hidden");
    table.classList.remove("hidden");
    counter.style.display = "flex";
    chunkCount.textContent = cipherChunks.length;
    tbody.innerHTML = "";

    cipherChunks.forEach((chunk, i) => {
        // Handle both shapes: plain string OR {index, plain, cipher} object
        const isObj = chunk && typeof chunk === "object";
        const idx = isObj ? (chunk.index ?? i + 1) : i + 1;
        const plainSlice = isObj ? (chunk.plain ?? "") : slicePlain(plaintext, i);
        const hexStr = isObj ? (chunk.cipher ?? "") : String(chunk);

        const row = document.createElement("tr");
        row.className = "hover:bg-surface-container-high transition-colors text-on-surface-variant";
        
        row.innerHTML = `
            <td class="py-2 px-3 border-b border-outline-variant whitespace-nowrap text-outline">${String(idx).padStart(2, "0")}</td>
            <td class="py-2 px-3 border-b border-outline-variant text-on-surface truncate max-w-[150px] font-mono">${escHtml(plainSlice)}</td>
            <td class="py-2 px-3 border-b border-outline-variant text-primary break-all font-mono">${escHtml(hexStr)}</td>
        `;
        tbody.appendChild(row);
    });
}

/** Slice plaintext bytes for chunk index i (10-byte chunks), returns safe ASCII repr. */
function slicePlain(plaintext, i) {
    const CHUNK = 10;
    const bytes = new TextEncoder().encode(plaintext);
    const slice = bytes.slice(i * CHUNK, i * CHUNK + CHUNK);
    return new TextDecoder("utf-8", { fatal: false }).decode(slice).replace(/[\x00-\x1f\x7f-\x9f]/g, "·");
}

/** Safe for text-node content only — does NOT escape quotes for attribute contexts. */
function escHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function setStatus(state, text) {
    document.getElementById("statusDot").className = `status-dot ${state}`;
    document.getElementById("statusText").textContent = text;
}

function resetStream() {
    document.getElementById("pipeVisualizer").classList.remove("hidden");
    document.getElementById("chunkDisplay").classList.add("hidden");
    document.getElementById("filePipeline").classList.add("hidden");
    document.getElementById("chunkRows").innerHTML = "";
    const counter = document.getElementById("streamCounter");
    if (counter) counter.style.display = "none";
}

function addLog(containerId, message, type = "info") {
    const container = document.getElementById(containerId);

    // Remove empty-state placeholder on first real log
    const empty = container.querySelector(".log-empty");
    if (empty) empty.remove();

    const entry = document.createElement("div");
    entry.className = `log-entry ${type}`;
    const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
    entry.innerHTML = `<span class="ts">${ts}</span><span>${message}</span>`;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
}

function clearLogs() {
    const container = document.getElementById("txLogs");
    container.innerHTML = "";
}

// ─── Tab Navigation ─────────────────────────────────────────────────────────

function switchTab(tabId) {
    const navTransmit = document.getElementById("navTransmit");
    const navMonitor = document.getElementById("navMonitor");
    const wsTransmit = document.getElementById("workspaceTransmit");
    const wsMonitor = document.getElementById("workspaceMonitor");

    if (tabId === "transmit") {
        navTransmit.classList.add("active");
        navMonitor.classList.remove("active");
        wsTransmit.classList.remove("hidden");
        wsMonitor.classList.add("hidden");
    } else if (tabId === "monitor") {
        navMonitor.classList.add("active");
        navTransmit.classList.remove("active");
        wsMonitor.classList.remove("hidden");
        wsTransmit.classList.add("hidden");
        
        // Auto-refresh monitor data when switching to it
        loadMonitorData();
    }
}

// ─── Monitor Data ───────────────────────────────────────────────────────────

async function loadMonitorData() {
    try {
        const data = await callApi("fetchMonitorData");
        if (!data || !data.metrics) return;

        // Update Stats
        document.getElementById("statTxTotal").textContent = data.metrics.total_transmissions || 0;
        document.getElementById("statBytesTotal").textContent = data.metrics.total_bytes_encrypted || 0;
        document.getElementById("statTxFailed").textContent = data.metrics.failed_transmissions || 0;

        // Update History Table
        const tbody = document.getElementById("historyTableBody");
        const emptyState = document.getElementById("historyEmpty");
        tbody.innerHTML = "";

        if (data.history && data.history.length > 0) {
            emptyState.style.display = "none";
            data.history.forEach(tx => {
                const tr = document.createElement("tr");
                const badgeClass = tx.status.toLowerCase() === "success" ? "success" : "failed";
                
                tr.innerHTML = `
                    <td class="col-txid py-3 px-6">${escHtml(tx.id)}</td>
                    <td class="col-ts py-3 px-6">${escHtml(tx.timestamp)}</td>
                    <td class="col-target py-3 px-6">${escHtml(tx.target)}</td>
                    <td class="col-size py-3 px-6">${tx.bytes} B</td>
                    <td class="py-3 px-6"><span class="status-badge ${badgeClass}">${escHtml(tx.status)}</span></td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            emptyState.style.display = "block";
        }
    } catch (err) {
        console.error("Failed to load monitor data:", err);
    }
}

// ─── SAS Verification ────────────────────────────────────────────────────────

function showSasModal(sasStr) {
    document.getElementById("sasWords").textContent = sasStr;
    document.getElementById("sasModal").classList.remove("hidden");
}

async function submitSas(approved) {
    document.getElementById("sasModal").classList.add("hidden");
    if (!approved) {
        addLog("txLogs", "MITM detected! Transmission aborted by user.", "error");
        setStatus("error", "Aborted");
    }
    await callApi("submitSas", approved);
}
