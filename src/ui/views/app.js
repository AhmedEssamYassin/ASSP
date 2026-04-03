/**
 * Brutalist terminal UI controller for OTP Stream Cipher.
 */

let isTransmitting = false;

function updateTimestamp() {
    const el = document.getElementById("timestamp");
    if (el) el.textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
setInterval(updateTimestamp, 1000);
updateTimestamp();

async function startTransmission() {
    if (isTransmitting) return;

    const plaintext = document.getElementById("plaintext").value.trim();
    if (!plaintext) {
        addLog("txLogs", "ERROR: Empty plaintext input", "error");
        return;
    }

    isTransmitting = true;
    const btn = document.getElementById("transmitBtn");
    const btnLabel = btn.querySelector(".btn-label");
    const btnLoader = btn.querySelector(".btn-loader");

    btn.disabled = true;
    btnLabel.style.display = "none";
    btnLoader.style.display = "flex";

    setStatus("ping", "TRANSMITTING");

    clearAllLogs();
    resetDisplays();

    addLog("txLogs", "Initiating transmission sequence...", "info");
    addLog("rxLogs", "Receiver standing by...", "info");

    try {
        const result = await callApi("runTransmission", plaintext);

        if (result.success) {
            addLog("txLogs", "Transmission complete", "success");
            addLog("rxLogs", "Decryption complete", "success");

            displayChunks(result.cipherChunks || []);
            displayDecrypted(result.decryptedText || "");

            const match = result.decryptedText === plaintext;
            displayVerification(match);

            addLog("txLogs", `Verification: ${match ? "PASS" : "FAIL"}`, match ? "success" : "error");
            setStatus(match ? "active" : "error", match ? "VERIFIED" : "MISMATCH");
        } else {
            addLog("txLogs", `ERROR: ${result.error || "Unknown error"}`, "error");
            addLog("rxLogs", "Transmission failed", "error");
            setStatus("error", "FAILED");
        }
    } catch (error) {
        addLog("txLogs", `API ERROR: ${error.message}`, "error");
        setStatus("error", "ERROR");
    } finally {
        btn.disabled = false;
        btnLabel.style.display = "inline";
        btnLoader.style.display = "none";
        isTransmitting = false;
    }
}

async function callApi(methodName, ...args) {
    if (window.pywebview && window.pywebview.api) {
        return await window.pywebview.api[methodName](...args);
    }
    return simulateBackend(methodName, ...args);
}

async function simulateBackend(methodName, plaintext) {
    await new Promise(resolve => setTimeout(resolve, 1500));

    const chunks = [];
    const maxChunkSize = 10;
    for (let i = 0; i < plaintext.length; i += maxChunkSize) {
        const chunk = plaintext.slice(i, i + maxChunkSize);
        chunks.push({
            index: Math.floor(i / maxChunkSize) + 1,
            plain: chunk,
            cipher: btoa(chunk).slice(0, 20) + "...",
        });
    }

    return {
        success: true,
        cipherChunks: chunks,
        decryptedText: plaintext,
    };
}

function displayChunks(chunks) {
    const pipeVis = document.getElementById("pipeVisualizer");
    const chunkDisp = document.getElementById("chunkDisplay");
    const chunkRows = document.getElementById("chunkRows");

    pipeVis.classList.add("hidden");
    chunkDisp.classList.remove("hidden");
    chunkRows.innerHTML = "";

    chunks.forEach((chunk, index) => {
        const row = document.createElement("div");
        row.className = "chunk-row";
        row.style.animationDelay = `${index * 0.1}s`;
        row.innerHTML = `
            <span class="chunk-idx">${String(chunk.index || index + 1).padStart(2, "0")}</span>
            <span class="chunk-plain">${chunk.plain || chunk}</span>
            <span class="chunk-cipher">${chunk.cipher || ""}</span>
        `;
        chunkRows.appendChild(row);
    });
}

function displayDecrypted(text) {
    const output = document.getElementById("receiverOutput");
    const disp = document.getElementById("decryptedDisplay");
    const txt = document.getElementById("decryptedText");

    output.classList.add("hidden");
    disp.classList.remove("hidden");
    txt.textContent = text;
}

function displayVerification(match) {
    const disp = document.getElementById("verificationDisplay");
    const result = document.getElementById("verificationResult");

    disp.classList.remove("hidden");
    result.className = `verification-result ${match ? "success" : "error"}`;
    result.textContent = match ? "[ OK ] PLAINTEXT VERIFIED - INTEGRITY CONFIRMED" : "[ FAIL ] PLAINTEXT MISMATCH - INTEGRITY COMPROMISED";
}

function setStatus(state, text) {
    const dot = document.querySelector(".status-dot");
    const txt = document.querySelector(".status-text");
    dot.className = `status-dot ${state}`;
    txt.textContent = text;

    if (state === "ping") {
        setTimeout(() => {
            dot.className = "status-dot active";
        }, 600);
    }
}

function resetDisplays() {
    document.getElementById("pipeVisualizer").classList.remove("hidden");
    document.getElementById("chunkDisplay").classList.add("hidden");
    document.getElementById("receiverOutput").classList.remove("hidden");
    document.getElementById("decryptedDisplay").classList.add("hidden");
    document.getElementById("verificationDisplay").classList.add("hidden");
    document.getElementById("chunkRows").innerHTML = "";
}

function addLog(containerId, message, type = "info") {
    const container = document.getElementById(containerId);
    const entry = document.createElement("div");
    entry.className = `log-entry ${type}`;

    const ts = new Date().toLocaleTimeString("en-US", { hour12: false });
    entry.innerHTML = `<span class="ts">${ts}</span> ${message}`;

    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
}

function clearAllLogs() {
    document.getElementById("txLogs").innerHTML = "";
    document.getElementById("rxLogs").innerHTML = "";
}
