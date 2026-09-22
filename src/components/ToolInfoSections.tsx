const STEPS = [
  {
    title: "Paste Prompt or System Context",
    body: "Input user prompts, system instructions, MCP agent payloads, or choose from built-in attack samples to evaluate security posture.",
    accent: "from-cyan-400 to-sky-500",
  },
  {
    title: "Review Multi-Vector Findings",
    body: "Inspect real-time risk scores (0–100), severity breakdown (Critical, High, Medium, Low), and exact matched text snippets across threat categories.",
    accent: "from-amber-400 to-orange-500",
  },
  {
    title: "Copy Hardened Output Prompt",
    body: "Copy automated hardened prompts with redacted keys/PII and XML safety boundaries directly to clipboard or export JSON audit logs.",
    accent: "from-emerald-400 to-teal-500",
  },
] as const;

const FEATURES = [
  {
    title: "100% Client-Side Privacy",
    body: "Zero server network requests for scanning. Your AI prompts, enterprise system instructions, API keys, and sensitive LLM contexts are evaluated purely in local browser memory.",
    accent: "border-cyan-300/40 from-cyan-500/20",
  },
  {
    title: "Multi-Vector Threat Detection",
    body: "Identifies direct prompt injection, indirect injection, system prompt extraction, persona jailbreaks, DAN roleplay, and instruction overrides.",
    accent: "border-rose-300/40 from-rose-500/20",
  },
  {
    title: "PII & API Key Leakage Scanner",
    body: "Detects unmasked secrets including OpenAI/GitHub-style tokens, emails, credit cards, bearer tokens, and database connection strings.",
    accent: "border-amber-300/40 from-amber-500/20",
  },
  {
    title: "Data Exfiltration & Markdown Injection Defense",
    body: "Scans for malicious markdown image tags, hidden zero-width spaces, homoglyph character obfuscation, and URL exfiltration attempts — without making any network requests.",
    accent: "border-fuchsia-300/40 from-fuchsia-500/20",
  },
  {
    title: "Automated Prompt Sanitization & Hardening",
    body: "One-click automated prompt hardening that strips injection markers, redacts sensitive API keys and PII, and wraps untrusted input in protective XML safety boundaries.",
    accent: "border-emerald-300/40 from-emerald-500/20",
  },
  {
    title: "Real-Time Risk Scoring & Report Export",
    body: "Displays a clear 0–100 risk score with Critical, High, Medium, and Low severity badges, plus copyable sanitized prompts and downloadable JSON/Markdown audit reports.",
    accent: "border-sky-300/40 from-sky-500/20",
  },
] as const;

const FAQS = [
  {
    q: "What is a prompt injection attack in AI models and LLMs?",
    a: "Prompt injection occurs when malicious user input overrides an AI model's system instructions, tricking the LLM into ignoring developer constraints, revealing hidden system prompts, executing unauthorized commands, or exfiltrating data.",
  },
  {
    q: "Are my enterprise prompts, system instructions, or API keys uploaded to any server?",
    a: "No. This scanner operates 100% locally in your web browser. Neither your prompt text, system prompts, API keys, nor audit reports are uploaded for scanning.",
  },
  {
    q: "How does the automated prompt sanitization and hardening feature work?",
    a: "The local sanitization engine strips known attack markers, redacts detected API keys and PII with placeholders (for example [REDACTED_API_KEY]), and wraps untrusted user input inside defensive XML boundaries (<user_untrusted_input>…</user_untrusted_input>).",
  },
  {
    q: "Can this scanner audit MCP (Model Context Protocol) context payloads?",
    a: "Yes. You can paste MCP server tool definitions, JSON context payloads, or agent conversation logs to inspect them for injected instructions or unmasked credentials before passing them to an AI agent.",
  },
  {
    q: "Does this scanner provide perfect security guarantees?",
    a: "No. Pattern-based detection is deterministic and useful for catching common risks, but it can produce false positives or miss novel attacks. Treat results as a review aid, not a compliance certification.",
  },
] as const;

export function ToolInfoSections() {
  return (
    <div className="mt-16 space-y-16">
      <section aria-labelledby="how-heading">
        <h2
          id="how-heading"
          className="text-2xl font-semibold tracking-tight text-white"
        >
          How to Audit & Harden AI Prompts for Production Safety
        </h2>
        <ol className="mt-6 grid gap-4 md:grid-cols-3">
          {STEPS.map((step, index) => (
            <li
              key={step.title}
              className="rounded-2xl border border-white/15 bg-white/95 p-5 shadow-xl shadow-slate-950/20"
            >
              <span
                className={`inline-flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br text-sm font-bold text-white shadow-md ${step.accent}`}
              >
                {index + 1}
              </span>
              <h3 className="mt-3 text-base font-semibold text-slate-900">
                {step.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-600">
                {step.body}
              </p>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="features-heading">
        <h2 id="features-heading" className="sr-only">
          Scanner capabilities
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((feature) => (
            <article
              key={feature.title}
              className={`rounded-2xl border bg-gradient-to-br to-white/10 p-5 shadow-lg backdrop-blur-sm ${feature.accent}`}
            >
              <h3 className="text-base font-semibold text-white">
                {feature.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-300">
                {feature.body}
              </p>
            </article>
          ))}
        </div>
      </section>

      <section
        className="rounded-3xl border border-cyan-300/30 bg-gradient-to-br from-cyan-500/20 via-teal-500/10 to-emerald-500/20 p-6 shadow-2xl sm:p-8"
        aria-labelledby="privacy-heading"
      >
        <h2
          id="privacy-heading"
          className="text-xl font-semibold text-white"
        >
          Enterprise System Instructions, API Keys & Prompts Stay Strictly Local
        </h2>
        <p className="mt-3 max-w-3xl text-sm leading-relaxed text-cyan-50/90">
          Unlike third-party prompt testing APIs that log LLM inputs or store
          user queries on external cloud servers, this security scanner operates
          100% inside your local web browser memory. Neither your confidential
          system instructions, API tokens, database passwords, nor proprietary
          agent prompts are transmitted for scanning.
        </p>
      </section>

      <section aria-labelledby="faq-heading">
        <h2
          id="faq-heading"
          className="text-2xl font-semibold tracking-tight text-white"
        >
          Frequently Asked Questions
        </h2>
        <div className="mt-6 space-y-3">
          {FAQS.map((faq) => (
            <details
              key={faq.q}
              className="group rounded-2xl border border-white/15 bg-white/95 p-4 shadow-lg open:shadow-xl"
            >
              <summary className="cursor-pointer list-none text-sm font-semibold text-slate-900 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 [&::-webkit-details-marker]:hidden">
                <span className="flex items-start justify-between gap-3">
                  {faq.q}
                  <span
                    className="mt-0.5 inline-flex h-6 w-6 items-center justify-center rounded-full bg-gradient-to-br from-cyan-400 to-teal-500 text-white transition group-open:rotate-45"
                    aria-hidden="true"
                  >
                    +
                  </span>
                </span>
              </summary>
              <p className="mt-3 text-sm leading-relaxed text-slate-600">
                {faq.a}
              </p>
            </details>
          ))}
        </div>
      </section>
    </div>
  );
}
