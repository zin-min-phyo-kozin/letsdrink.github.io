let lastResults = {
  secrets: [],
  urls: [],
  domains: [],
  paths: []
};

document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("fileInput");
  const scanFileBtn = document.getElementById("scanFileBtn");
  const scanUrlBtn = document.getElementById("scanUrlBtn");
  const urlInput = document.getElementById("urlInput");
  const statusEl = document.getElementById("status");

  const downloadJsonBtn = document.getElementById("downloadJsonBtn");
  const downloadTextBtn = document.getElementById("downloadTextBtn");

  scanFileBtn.addEventListener("click", () => {
    if (!fileInput.files || !fileInput.files[0]) {
      setStatus("Please choose a .js file first.", "warn");
      return;
    }
    const file = fileInput.files[0];
    const reader = new FileReader();
    setStatus(`Reading file "${file.name}"...`, "info");
    reader.onload = async e => {
      const code = e.target.result;
      await runAnalysis(code);
    };
    reader.onerror = () => setStatus("Error reading file.", "error");
    reader.readAsText(file);
  });

  scanUrlBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) {
      setStatus("Please enter a JS file URL.", "warn");
      return;
    }
    setStatus(`Fetching ${url} ...`, "info");
    try {
      const res = await fetch(url);
      if (!res.ok) {
        setStatus(`Fetch error: ${res.status} ${res.statusText}`, "error");
        return;
      }
      const text = await res.text();
      await runAnalysis(text);
    } catch (err) {
      setStatus("Fetch failed. Possibly blocked by CORS or network error.", "error");
      console.error(err);
    }
  });

  downloadJsonBtn.addEventListener("click", () => {
    downloadFile(JSON.stringify(lastResults, null, 2), "scan-results.json", "application/json");
  });

  downloadTextBtn.addEventListener("click", () => {
    const report = buildTextReport(lastResults);
    downloadFile(report, "scan-results.txt", "text/plain");
  });

  function setStatus(msg, type = "info") {
    statusEl.textContent = msg;
    statusEl.style.color = (type === "error")
      ? "#ef9a9a"
      : (type === "warn")
      ? "#ffcc80"
      : "#90caf9";
  }

  async function runAnalysis(code) {
    setStatus("Analyzing code...", "info");
    // In case you add async later
    const results = await analyzeCode(code);
    lastResults = results;
    renderResults(results);
    setStatus("Analysis complete.", "info");
  }

  function renderResults(results) {
    setList("secretsList", results.secrets.map(s => s.value));
    setList("urlsList", results.urls);
    setList("domainsList", results.domains);
    setList("pathsList", results.paths);

    document.getElementById("secretsCount").textContent = results.secrets.length;
    document.getElementById("urlsCount").textContent = results.urls.length;
    document.getElementById("domainsCount").textContent = results.domains.length;
    document.getElementById("pathsCount").textContent = results.paths.length;
  }

  function setList(listId, items) {
    const ul = document.getElementById(listId);
    ul.innerHTML = "";
    if (!items || !items.length) {
      const li = document.createElement("li");
      li.textContent = "(none)";
      li.style.opacity = "0.7";
      ul.appendChild(li);
      return;
    }
    for (const v of items) {
      const li = document.createElement("li");
      li.textContent = v;
      ul.appendChild(li);
    }
  }

  function downloadFile(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }
});

async function analyzeCode(jsCode) {
  const strings = extractStrings(jsCode);
  const results = {
    secrets: [],
    urls: new Set(),
    domains: new Set(),
    paths: new Set()
  };

  extractUrlsAndPathsFromCode(jsCode, results);

  for (const s of strings) {
    if (!s) continue;

    // URL-like
    if (/^https?:\/\//i.test(s)) {
      results.urls.add(s);
      try {
        const u = new URL(s);
        results.domains.add(u.hostname);
        if (u.pathname && u.pathname !== "/") {
          results.paths.add(u.pathname);
        }
      } catch (_) {}
      continue;
    }

    // Domains inside strings
    const domRe = /\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
    let dm;
    while ((dm = domRe.exec(s)) !== null) {
      results.domains.add(dm[0]);
    }

    // Paths inside strings
    const pathRe = /\/[a-zA-Z0-9_\-\/\.]+/g;
    let pm;
    while ((pm = pathRe.exec(s)) !== null) {
      const p = pm[0];
      if (!p.startsWith("//")) {
        results.paths.add(p);
      }
    }

    // Potential secrets
    if (looksLikeSecret(s)) {
      results.secrets.push({ value: s, length: s.length });
    }
  }

  return {
    secrets: results.secrets,
    urls: [...results.urls],
    domains: [...results.domains],
    paths: [...results.paths]
  };
}

function extractStrings(jsCode) {
  const regex = /(["'`])((?:\\.|(?!\1).)*?)\1/g;
  const res = [];
  let m;
  while ((m = regex.exec(jsCode)) !== null) {
    res.push(m[2]);
  }
  return res;
}

function extractUrlsAndPathsFromCode(jsCode, results) {
  const urlRegex = /\bhttps?:\/\/[^\s"'`]+/gi;
  let m;
  while ((m = urlRegex.exec(jsCode)) !== null) {
    results.urls.add(m[0]);
  }

  const pathRegex = /\/[a-zA-Z0-9_\-\/\.]+/g;
  while ((m = pathRegex.exec(jsCode)) !== null) {
    const p = m[0];
    if (!p.startsWith("//")) {
      results.paths.add(p);
    }
  }

  const domainRegex = /\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
  while ((m = domainRegex.exec(jsCode)) !== null) {
    results.domains.add(m[0]);
  }
}

function looksLikeSecret(str) {
  if (str.length < 10) return false;
  if (/^\s*$/.test(str)) return false;
  if (/^[0-9]+$/.test(str)) return false;

  let classes = 0;
  if (/[a-z]/.test(str)) classes++;
  if (/[A-Z]/.test(str)) classes++;
  if (/[0-9]/.test(str)) classes++;
  if (/[^a-zA-Z0-9]/.test(str)) classes++;

  if (classes >= 3 && str.length >= 16) return true;

  return false;
}

function buildTextReport(results) {
  let out = "";

  out += `Secrets (${results.secrets.length}):\n`;
  results.secrets.forEach((s, i) => {
    out += `${i + 1}. ${s.value}\n`;
  });

  out += `\nURLs (${results.urls.length}):\n`;
  results.urls.forEach((u, i) => {
    out += `${i + 1}. ${u}\n`;
  });

  out += `\nDomains (${results.domains.length}):\n`;
  results.domains.forEach((d, i) => {
    out += `${i + 1}. ${d}\n`;
  });

  out += `\nPaths (${results.paths.length}):\n`;
  results.paths.forEach((p, i) => {
    out += `${i + 1}. ${p}\n`;
  });

  return out;
}
