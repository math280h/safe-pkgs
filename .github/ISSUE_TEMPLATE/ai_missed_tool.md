---
name: AI skipped safe-pkgs
about: Report a case where an AI agent installed packages without calling check_package or check_lockfile first
title: 'AI skipped safe-pkgs: <brief description>'
labels: ai-tool-selection
assignees: ''

---

**Which AI / client were you using?**
e.g. Claude (Sonnet 4.5), GPT-4o, Cursor, Continue, etc.

**What was the prompt or instruction you gave the AI?**

<!-- Paste the exact message or instruction that triggered the package install -->

```
<your prompt here>
```

**What did the AI do instead?**

<!-- Paste the relevant part of the AI's response or actions — e.g. it ran `npm install` directly without calling check_package -->

```
<AI response or tool calls here>
```

**What did you expect it to do?**

<!-- e.g. "Call check_package for each dependency before installing" -->

**MCP / tool configuration**

- How is safe-pkgs registered? (Claude Desktop config, Cursor settings, etc.)
- Paste your MCP server config if relevant:

```json

```

**Additional context**

<!-- Anything else that might help — system prompt, tool list shown to the model, etc. -->
