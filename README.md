# Agent Ready GEO: make your website agent-ready

[![Release](https://img.shields.io/github/v/release/ilang-ai/agent-ready-geo)](https://github.com/ilang-ai/agent-ready-geo/releases) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22864996.svg)](https://doi.org/10.5281/zenodo.22864996)

**Is your site agent-ready?** Agent Ready GEO is an agent skill for Claude Code, Codex and any client that supports Agent Skills. It takes a website to 100/100 on [isitagentready.com](https://isitagentready.com) (Level 5, Agent-Native) with the access you give it: llms.txt and llms-full.txt, Markdown for agents, Link headers, an API catalog and OpenAPI, a running MCP server with its server card, an Agent Skills index, WebMCP browser tools, ARD, OAuth discovery, auth.md and DNS-AID, all built on the stack you already have. Every capability it presents as available actually works; anything not built yet is published only as a labeled coming-soon declaration that you approve.

This project is not affiliated with Cloudflare or isitagentready.com.

GEO here means groundwork for generative engine optimization: machine-readable access for AI agents, AI search and answer engines. No AI citations, rankings or traffic are promised.

**Contents:** [Proof](#two-of-our-own-sites-score-100100) · [What it builds](#what-it-builds-llmstxt-markdown-for-agents-webmcp-mcp-and-more) · [Install](#install-as-a-claude-code-skill-codex-skill-or-agent-skill) · [Use](#how-to-use-it) · [FAQ](#faq) · [What you may be asked](#what-you-may-be-asked-to-do) · [What it will not do](#what-it-will-not-do) · [Privacy](#privacy) · [Scripts](#scripts) · [I-Lang](#written-in-i-lang)

## Two of our own sites score 100/100

| Site | Result page (opening it runs a fresh scan) |
|---|---|
| ilang.ai | https://isitagentready.com/ilang.ai |
| hotelcorporatecodes.com | https://isitagentready.com/hotelcorporatecodes.com |

Both showed 100, Level 5 Agent-Native, on 2026-09-19. Their OAuth checks pass with coming-soon declarations; neither site offers OAuth sign-in yet.

## What it builds: llms.txt, Markdown for agents, WebMCP, MCP and more

| Scanner check | What the skill builds and verifies |
|---|---|
| robots.txt, AI bot rules, Content Signals | AI crawler rules that match your policy, with named groups only where you want different rules per bot, each keeping the private-path rules that applied to it before; your own search, AI-input and AI-training choices as Content Signals |
| Sitemap | Real canonical URLs only, no fallback pages or private paths |
| Link headers | `api-catalog`, `service-desc`, `service-doc` relations on the scanned page, each pointing to a working resource |
| Markdown for agents | The same URL returns real Markdown for `Accept: text/markdown`, HTML by default, `q=0` respected, cache-safe |
| API catalog and OpenAPI | An RFC 9727 catalog and an OpenAPI document for a real, bounded, read-only lookup of your content |
| MCP server card | A running MCP server with real tools where your host can run one, and a card that matches it; where it cannot, the skill prepares the code and reports the check as blocked by the host |
| Agent Skills index | A task skill for your site with a digest computed from the bytes actually served |
| WebMCP | Browser tools registered through the native API, with normal pages unchanged for browsers without it |
| ARD | `/.well-known/ai-catalog.json` describing real resources |
| OAuth discovery, protected resource, auth.md | Your real authentication documented as it is; without an OAuth server, labeled coming-soon declarations if you approve them (see below) |
| DNS-AID | A service index plus the exact SVCB record and DNSSEC steps for your DNS |
| Web Bot Auth | Only when your site runs an outbound agent that signs requests, or when you ask for a key directory in advance, labeled as having no signing traffic yet; the check is informational otherwise |

It also writes `llms.txt` and `llms-full.txt` from your real pages, checks structured data, and walks the main visitor journey on desktop and phone so nothing a visitor used before breaks.

Instructions it writes for agents on your site (your site's own skill, the agent section of `auth.md`, the DNS-AID service index) use [I-Lang](https://ilang.ai/spec/), a plain-text instruction format, by default; ask for plain Markdown if you prefer. Those files carry your site's name, never ours.

It works on the hosting you have: a VPS, WordPress or another CMS, Cloudflare Workers or Pages, an application framework, or static hosting with the functions your host offers.

## Install as a Claude Code skill, Codex skill or Agent Skill

Claude Code:

```bash
git clone https://github.com/ilang-ai/agent-ready-geo ~/.claude/skills/agent-ready-geo
```

Codex:

```bash
git clone https://github.com/ilang-ai/agent-ready-geo ~/.codex/skills/agent-ready-geo
```

Other clients that load Agent Skills (a folder with a `SKILL.md`): copy the folder into the client's skills directory. The folder name must stay `agent-ready-geo`.

## How to use it

Ask your agent in plain words:

- "Check how agent-ready https://example.com is." Read-only: score, capability matrix, gaps.
- "Make https://example.com agent-ready and get it to 100." Builds, tests, deploys with the access you give it, rescans.
- "Recheck https://example.com." Confirms the current release still passes; repairs regressions.

## FAQ

### What is an agent-ready website?

A website that AI agents can discover, read and use without guessing: rules for AI crawlers, a readable Markdown version of each page, a list of its APIs, a working MCP server, a skill that explains its tasks, and discovery records that point to all of them. [isitagentready.com](https://isitagentready.com) scores these checks from 0 to 100 and in levels up to Level 5, Agent-Native.

### How do I get 100/100 on isitagentready.com?

Install this skill and ask your agent to make the site agent-ready. It reads your current result page, fixes each failing check on your real hosting, and rescans. Two steps usually need you: one DNS record for DNS-AID with DNSSEC, and a decision on OAuth if your site has no OAuth server (see below).

### Is this an llms.txt generator?

It writes `llms.txt` and `llms-full.txt` from your real pages, following the [llmstxt.org](https://llmstxt.org/) format, and then does much more: Markdown for agents, API catalog, MCP, Agent Skills, WebMCP and DNS-AID. Google Search does not need llms.txt to rank a page; agents and developer tools read it.

### Is it a GEO or AI SEO tool?

It does the technical groundwork for GEO (generative engine optimization), AEO (answer engine optimization) and AI SEO: machine-readable, verifiable access to your real content. It does not promise AI citations, rankings or traffic, and it adds no content written to game them.

### What is WebMCP, and does my site need it?

WebMCP lets a page register browser tools that an AI agent can call while the page is open. As of September 2026 it is a proposed web standard, with a Chrome origin trial starting in Chrome 149. The scanner checks it, so the skill registers real tools through the native API and leaves the page unchanged for browsers without it.

### Does it work with Claude, Codex and other agents?

Yes. It is a standard Agent Skill: a `SKILL.md` with reference files and two Python scripts. Claude Code and Codex load it from their skills folders; other clients that support the Agent Skills format can use the same folder.

### Will it change my DNS, login or firewall?

Only after you approve the listed change. It shows the exact DNS records and waits for approval even if it has DNS access, never overwrites real authentication, and never adds a site-wide firewall bypass.

## What you may be asked to do

- Approve DNS changes. DNS-AID needs one SVCB record, and the scanner needs DNSSEC on the zone. The agent shows the exact records and waits for your approval, even if it has DNS access; without access it hands you the records and how to check them.
- Decide on coming-soon OAuth. Two scored checks read OAuth discovery documents. If your site runs no OAuth authorization server (true for most sites, including many with a normal login), the skill shows you a plan: the files, their full content, the "Coming soon" wording and how to remove them. Planned endpoints answer `503`, nothing collects identity, public content stays public. It publishes them only after you accept; asking for 100 after seeing the plan counts as accepting it. If you decline, two or three scored checks stay failing and the result stays below 100, possibly below Level 5.
- State your content-use choices. If your search, AI-input and AI-training preferences are not written down, the agent asks instead of choosing.
- Decide on payments. If the scanner classifies your site as a shop, four commerce checks count (x402, MPP, UCP, ACP). The skill adds none of them without your decision; without them the score stays below 100.
- Open the result page. If your agent has no browser, it gives you the result page link and asks for the number it shows.

## What it will not do

- Present a capability as working when it does not. A JSON file named `mcp` is not an MCP server. The optional coming-soon OAuth documents use standard field names marked unavailable; clients that ignore the markers may read them as offered.
- Change only a `Content-Type` header and call it Markdown.
- Add a site-wide firewall or bot-management bypass keyed on User-Agent, Accept or a path.
- Add payment middleware, wallets or prices to raise the score.
- Harden or lock down your server along the way: root and password login, SSH keys, users and rescue access stay as they are.
- Put a watermark, credit line or link to this project in any file on your site.
- Touch DNS, authentication, firewall rules or accounts without your approval of the listed change.
- Promise AI citations, rankings or traffic. The score is a technical result for one URL at one time.

## Privacy

The scanner is a third-party service; scanning sends it your site URL. `scripts/probe_site.py` sends read-only GET requests to your site, identifying itself as `agent-ready-geo-probe/1.0`, plus a few requests with Python's default client to see whether your bot protection treats them differently, and DNS-over-HTTPS queries about your domain to Google and Cloudflare resolvers. It never posts, logs in or calls the scanner. Keep its evidence files out of public repositories.

## Scripts

```bash
python3 scripts/probe_site.py https://example.com/ --output /path/to/your-project/evidence/probe-v2.0-2026-09-19.json
python3 scripts/probe_site.py https://example.com/docs/ --app-base /docs/ --output /path/to/your-project/evidence/probe-docs-v2.0-2026-09-19.json
python3 scripts/verify_artifacts.py --site-root ./public --origin https://example.com
python3 -m unittest discover -s tests
```

Python 3.9 or newer, standard library only. Use `python` where that is your interpreter's name.

## Written in I-Lang

The skill's instructions are written in [I-Lang](https://ilang.ai/spec/), a structured language for instructing AI models, and pass the I-Lang grammar validator with no errors or warnings.

## Citation

[CITATION.cff](CITATION.cff); Zenodo archives each release. Concept DOI [10.5281/zenodo.22864996](https://doi.org/10.5281/zenodo.22864996) (all versions).

## License

MIT
