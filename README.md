# Free Serp
A free, light, and simple Serp API using JSON for responses, Python for server side compute, Worked for runtime, and JS for clients (with inline HTML capabilities and usability in TS) using Microsoft Bing

## Deploy

As stated, this projects is intended for the worked runtime due to its low compute cost. you can deploy this project to Cloudflare Workers using the button below

> [!NOTE]
> If you like this project, please consider giving this repository a star!

## Clients

For quick deploytment / Addition to your applacation, you can use this simple inline HTML Java script

```html
<script>
// Add your full backend url here with the api extension
    const API_URL = "/api";
    // Replace with your real passkey. Anyone who can read this page can read the
    // passkey, so for production use a per-user passkey issued by a real backend.
    const PASSKEY = "replace-with-first-key";
    // Keep the rest of the script the exact same
    async function searchSerp(query, options) {
        options = options || {};
        const trimmed = String(query == null ? "" : query).trim();
        if (!trimmed) {
            throw new Error("query must not be empty");
        }
        const body = {
            query: trimmed,
            results: Number.isFinite(options.results) ? options.results : 1,
            includeSummary: Boolean(options.includeSummary),
            includeWikibox: Boolean(options.includeWikibox),
            includeDefinition: Boolean(options.includeDefinition),
            passkey: PASSKEY,
        };
        let response;
        try {
            response = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
        } catch (networkErr) {
            throw new Error("network error: " + networkErr.message);
        }
        let payload = null;
        if (response.status !== 204) {
            try {
                payload = await response.json();
            } catch (jsonErr) {
            }
        }
        if (!response.ok) {
            const message = (payload && payload.error)
                ? payload.error
                : ("request failed (HTTP " + response.status + ")");
            throw new Error(message);
        }
        if (payload === null) {
            throw new Error("server returned an empty or non-JSON body");
        }
        return payload;
    }
    const form         = document.getElementById("search-form");
    const queryInput   = document.getElementById("query");
    const resultsInput = document.getElementById("results");
    const summaryBox   = document.getElementById("summary");
    const wikiboxBox   = document.getElementById("wikibox");
    const definitionBox = document.getElementById("definition");
    const submitBtn    = form.querySelector("button[type=submit]");
    const output       = document.getElementById("output");
    let inflight = false;
    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (inflight) return;
        inflight = true;
        const previousLabel = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = "Searching...";
        output.classList.remove("error");
        output.textContent = "Loading...";
        try {
            const data = await searchSerp(
                queryInput.value,
                {
                    results: parseInt(resultsInput.value, 10) || 1,
                    includeSummary:   summaryBox.checked,
                    includeWikibox:    wikiboxBox.checked,
                    includeDefinition: definitionBox.checked,
                }
            );
            output.textContent = JSON.stringify(data, null, 2);
        } catch (err) {
            output.classList.add("error");
            output.textContent = "Error: " + err.message;
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = previousLabel;
            inflight = false;
        }
    });
    </script>
```
