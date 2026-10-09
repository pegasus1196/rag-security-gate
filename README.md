# RAG Supply-Chain Security Demo

A small, local hackathon prototype: a suspicious knowledge-base page tries to persuade an assistant to email fake customer data to an outside address. Run it with the guard off, then on, and inspect the source labels and decision reason.

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

Live OpenRouter mode sends requests to a selected model, gets model-selected tool calls, runs local document search and a local customer lookup, and enforces the Python policy gate before the email action. The data is still sample data, retrieval is a small keyword search, and email is intentionally simulated. A production version would need your authorized real data sources, proper user login and permissions, durable database/vector storage, stronger provenance tracking, and an email service with explicit human approval. Do not connect real customer data until those controls are designed.

## What is included

- `app.py`: demo screen, small retrieval function, deterministic sample run, optional model tool-call loop, policy gate, and run log display.
- `data/documents.json`: two ordinary fake documents and one tier-3 poisoned document.
- `data/customers.json`: fictional records only.
- `logs/`: JSONL audit logs are created here when a run is saved.

## What the guard checks

The demo gate checks the origin of the email recipient and whether the proposed message contains fake customer data. An email address found in a tier-3 document is blocked. Turning the guard off shows the simulated email action going through. This is a teaching prototype, not a complete security product: substring-based origin matching can miss paraphrases, and a live model may choose a different sequence of actions.

## First development milestone

Make the guided demo tell the story reliably. Then expand the attack and benign task scenarios, improve origin tracking, and measure attack success and safe task completion before polishing the UI.
