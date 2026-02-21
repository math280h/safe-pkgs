---
hide:
  - title
  - toc
---

<div class="home-page">
<div class="hero-grid">
  <div class="hero-copy">
    <p class="hero-eyebrow">MCP Server + CLI</p>
    <h2>Stop risky packages before they reach your machine.</h2>
    <p class="hero-text">
      safe-pkgs runs package safety checks before install and returns a single decision your tools can enforce:
      <code>allow</code>, <code>risk</code>, <code>reasons</code>, and <code>metadata</code>.
    </p>
    <p class="hero-cta">
      <a class="md-button md-button--primary" href="getting-started/">Start in 60 Seconds</a>
      <a class="md-button" href="configuration-spec/">See config spec</a>
    </p>
  </div>
  <div class="hero-panel">
    <p class="panel-title">Typical Decision</p>
    <pre><code>{
  "allow": false,
  "risk": "high",
  "reasons": [
    "package is too new (published 2 days ago)",
    "postinstall script found"
  ],
  "metadata": {
    "latest": "1.2.4",
    "requested": "1.2.3"
  }
}</code></pre>
  </div>
  <div class="metrics">
    <article class="metric-item"><strong>7 checks</strong><span>aggregated into one risk score</span></article>
    <article class="metric-item"><strong>3 registries</strong><span>npm + crates.io + pypi</span></article>
    <article class="metric-item"><strong>Audit log</strong><span>append-only local trail</span></article>
  </div>
</div>

<section class="sp-section">
  <div class="section-head">
    <p class="hero-eyebrow">Why safe-pkgs</p>
    <h3>Fast installs are great. Blind installs are not.</h3>
  </div>
  <div class="card-grid three">
    <article class="sp-card">
      <h4>Catch common supply-chain risk</h4>
      <p>Typosquat checks, install-script detection, and advisory lookups reduce obvious package abuse before install.</p>
    </article>
    <article class="sp-card">
      <h4>Enforce policy, not vibes</h4>
      <p>Configure a max allowed risk. If checks fail or risk is too high, the decision is explicit and machine-enforceable.</p>
    </article>
    <article class="sp-card">
      <h4>Keep decisions auditable</h4>
      <p>Every decision can be logged with reasons and metadata so teams can review what was blocked and why.</p>
    </article>
  </div>
</section>

<section class="sp-section">
  <div class="section-head">
    <p class="hero-eyebrow">How it works + pipeline</p>
    <h3>One combined decision map.</h3>
  </div>
  <img class="arch-diagram" src="./assets/architecture-combined.svg" alt="Combined safe-pkgs architecture showing input surfaces, concurrent checks, risk aggregation, policy gate, and decision output." />
</section>

<section class="sp-section">
  <div class="section-head">
    <p class="hero-eyebrow">Provider matrix</p>
    <h3>Check support by registry</h3>
  </div>
  <p><a class="md-button" href="check-support-map/">Open check support map</a></p>
</section>

<section class="sp-section">
  <div class="section-head">
    <p class="hero-eyebrow">In-editor flow</p>
    <h3>What usage looks like</h3>
  </div>
  <div class="image-grid">
    <img src="./assets/vscode.png" alt="safe-pkgs VS Code example result" loading="lazy" />
    <img src="./assets/vscode2.png" alt="safe-pkgs VS Code example check flow" loading="lazy" />
  </div>
</section>

<section class="sp-section">
  <div class="section-head">
    <p class="hero-eyebrow">How to start</p>
    <h3>Copy, run, integrate.</h3>
  </div>
  <div class="code-grid">
    <article class="code-card">
      <h4>Build and run MCP server</h4>
      <pre><code>cargo build --release
./target/release/safe-pkgs serve --mcp</code></pre>
    </article>
    <article class="code-card">
      <h4>Optional: run one-off audit</h4>
      <pre><code>safe-pkgs audit /path/to/project-or-lockfile</code></pre>
    </article>
    <article class="code-card wide">
      <h4>MCP client config snippet</h4>
      <pre><code>{
  "servers": {
    "safe-pkgs": {
      "type": "stdio",
      "command": "/path/to/safe-pkgs",
      "args": ["serve", "--mcp"]
    }
  },
  "inputs": []
}</code></pre>
    </article>
  </div>
</section>

</div>
