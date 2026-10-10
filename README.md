# RAG Supply-Chain Security Demo

A Ignisia Inccubex Hackathon Protoype developed for demonstrating how retrieved instructions can try to make an AI agent misuse tools. The local policy gateway checks each proposed tool call, records where argument values came from, and applies trust labels to retrieved documents.

## Open in VS Code

1. Open this `prototype` folder in VS Code.
2. In the VS Code terminal run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   streamlit run app.py
   ```

3. In the browser page, choose **Guided demo** and click **Run demo**. This deterministic mode works without an API key and is useful for rehearsing the security story.

## Live OpenRouter mode

Guided demo is a scripted demonstration, not an LLM evaluation. To let a model choose tool calls:

1. Copy `.env.example` to `.env` and replace `paste_your_openrouter_key_here` with your OpenRouter API key.
2. Keep `.env` private; it is ignored by Git.
3. Restart Streamlit, select **Live model**, and run a prompt.

Live model mode uses OpenRouter's OpenAI-compatible API and function calling. The default model is `openrouter/free`; change `OPENROUTER_MODEL` in `.env` to use another model available to your account. The free plan has request limits and free model availability can change. OpenRouter receives the user request and retrieved sample documents over the internet. The tools use local fictional data, and email is still simulated; nothing is actually sent.

Never paste the API key into chat or into `app.py`. Keep it only in `.env`; that file is excluded from Git.

## What makes this a real application, and what is still prototype scope

Live OpenRouter mode sends requests to a selected model and handles its function-call proposals locally. Every proposed tool call is checked by the policy gateway before dispatch. Requests and records stay fictional for this prototype: email, HTTP requests, and database writes are simulations only. No real email is sent, no network request is made, and no database is changed.

## What is included

- `app.py`: demo screen, small retrieval function, deterministic sample run, optional model tool-call loop, policy gate, and run log display.
- `policy.py`: centralized tool authorization rules and exact-match provenance tracking.
- `data/documents.json`: two ordinary fake documents and one tier-3 poisoned document.
- `data/customers.json`: fictional records only.
- `logs/`: JSONL audit logs are created here when a run is saved.

## What the guard checks

All tool calls pass through `policy.py`. With the guard enabled:

- `search_docs` can only search the local sample corpus.
- `query_db` allows one known customer ID at a time and returns only the ID, issue, and status. Bulk reads are blocked; contact fields are withheld.
- `db_write` is denied because the prototype has no human-approval workflow.
- `http_request` only allows simulated HTTPS GETs to `support.example.test` or `status.example.test`; write methods, other hosts, and request bodies are blocked.
- `send_email` is restricted to the fictional internal domain and detected customer data cannot be emailed.
- Unknown tools and malformed required arguments are blocked regardless of the guard toggle.

When the guard is off, allow-listed side effects are still simulations; there is no real network/email/database connection. The toggle demonstrates the policy decision, not permission to connect production systems.

Argument provenance tracks exact identifiers and phrases such as email addresses, customer IDs, and document IDs through the user request, retrieved documents, and local tool results. The UI shows the source, trust tier, matched value, and policy reason next to each proposed action. The model is also asked to cite document IDs and customer IDs in square brackets; the app resolves those citations back to their sources. Unmatched text is labeled unresolved rather than assigned a guessed source. Semantic paraphrases are not reliably traced yet, so this remains a teaching prototype, not a complete security product. A live model may also refuse an attack before proposing a tool call; use the guided scenarios to show repeatable gate decisions.

## Guided scenarios

- **Poisoned document attack:** traces one permitted, redacted customer lookup into an attempted email to the untrusted address.
- **Bulk database read attempt:** shows the guard denying a full-table customer read.
- **Benign incident summary:** retrieves the support incident without a risky action.
- **HTTP data-exfiltration attempt:** reads a permitted fictional record, then proposes an external POST carrying that data.
- **Database write attempt:** proposes a mutation to the fictional customer record.

Run each with the guard on and off. In guard-off cases, the UI explicitly labels every side effect as simulated.
