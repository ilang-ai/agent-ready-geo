::ILANG::v5.0
[TYPE:reference][PROJECT:agent_ready_geo][VERSION:1.0.0][DATE:2026-09-19][LANG:en]

::STATE{@SCOPE, value:WebMCP browser tools, browser-agent and visitor journeys, and what real consumers read}
::STATE{@SOURCES_CHECKED, value:web.dev and Chrome WebMCP pages on 2026-09-13; the WebMCP draft on 2026-09-19; refresh before relying on versions, trial dates or API names}

::MODULE{WEBMCP_C14}
  [MUST] Offer browser tools for the chosen real task and reuse the page's and the API's data, input meaning and permissions.
  [MUST] Check the real browser API first. The WebMCP Draft Community Group Report of the Web Machine Learning Community Group, dated 17 September 2026 when read on 2026-09-19, and Chrome's imperative API page updated 2026-09-11 use document.modelContext; the scanner's repair skill names navigator.modelContext. Feature-detect both. If both exist and are distinct objects, register the same tool definitions on each with one shared AbortController; if they are the same object, register once. Never create a fake modelContext object to look supported.
  [MUST] Each tool has a stable name, a clear description, a JSON input schema and an execute function that returns the real task result. Support cancellation, page unload and error feedback. One tool does one clear job; the name says whether it acts at once or starts a flow; the description says when to use it.
  [MUST] Accept the user's raw input as parameters, validate strictly, return errors that help the caller correct the call, and keep the page state in sync after execution.
  [MUST] Register tools only while the page state makes them usable and unregister them when it does not: an AbortSignal for imperative tools, removed attributes for declarative ones. Pass the signal from execute into long-running work.
  [MUST] Annotations match real side effects: readOnlyHint true for read-only tools, untrustedContentHint true when output contains user-generated or external data, consequentialHint true for bookings, transfers, deletions and other weighty actions. Annotations never replace authorization.
  [MUST] Declarative tools reuse existing real forms: the form carries toolname and tooldescription, and parameter descriptions come from toolparamdescription or an associated label. Never create a form with no business use for WebMCP.
  [MUST] Record whether declarative submission is manual or toolautosubmit. When a result must return to the model, the submit handler calls preventDefault and respondWith only for agentInvoked events and returns the real result or validation errors.
  [MUST] Keep the :tool-form-active and :tool-submit-active focus indicators visible, and handle toolactivated and toolcancel where they apply.
  [MUST] Documents that register tools stay origin-isolated: no Origin-Agent-Cluster ?0 and no document.domain. A cross-origin iframe needs allow="tools" from the embedder; record the actual Permissions-Policy value. Share across origins only through exposedTo lists of trusted secure origins, read with getTools fromOrigins; tools that read user data or act for the user are never exposed to untrusted origins.
  [RULE] Chrome's guidance suggested about 500 characters per tool description, 150 per parameter description, 30 per tool or parameter name and 1500 per tool output. These are changing recommendations; record the reason when exceeding them instead of failing.
  [FACT] On 2026-09-13 Chrome described WebMCP as a proposed web standard with an origin trial from Chrome 149 and a local testing flag. Visitors' browsers do not all support it; the flag is local development evidence only.
  [MUST] For visitor-facing use, record the origin trial or official support, the Chrome versions and the expiry or migration information.
  [MUST] WebMCP tools exist only while the page is open. Mentions in llms.txt, ARD, skills or OpenAPI are documentation, never evidence of WebMCP discovery or native execution. WebMCP does not declare server-side MCP resources.
  [MUST] Browsers without WebMCP keep the normal page flow; accessibility and ordinary features stay intact.
  [MUST] Native evidence records the browser version, how it was enabled, the getTools result with name, description, inputSchema, annotations and origin, the executeTool input and result, toolchange observations and page state. Pass inputs as objects. If a tool navigates and the contract returns null, verify the task on the page after navigation instead of calling null a failure.
  [MUST] The Model Context Tool Inspector extension can list and call tools manually; that counts as native_browser_executed, not external_agent_observed. Do not route non-public data through an extension that sends prompts to an outside model.
  [MUST] If the test environment cannot call the native API, finish independent verification and record native_unverified. A script's presence, a private registry or a scanner marker never replaces native execution.

::MODULE{BROWSER_AGENT_AND_VISITOR_JOURNEYS_C24}
  [MUST] For each real task define the start page, the required steps, the completion condition, error branches and the identity needed; run the main flow once on a desktop viewport and once on a phone viewport.
  [MUST] Prefer native button, a and input elements with accessible names, roles and states. A custom control needs equivalent keyboard and assistive-technology behavior, not only a role attribute.
  [MUST] Every input has a clear name through a label or an equivalent mechanism; validation errors, required fields, loading, expanded and disabled states are perceivable by users and agents.
  [MUST] Check keyboard order, visible focus and focus return after dialogs close. Modal dialogs manage focus; non-modal notices do not trap it.
  [MUST] Cookie choices keep the real accept, reject and manage options; closing a banner is not accepting all, and no extra consent is given on the user's behalf. Age checks and login keep their lawful steps.
  [MUST] Pages show clear loading, completion and failure feedback. No transparent overlays over controls, no layout shifts or collapsed menus that make a task unreachable. Measure stability on the real layout; do not promise zero shift.
  [MUST] Every action a task needs has a visible entry point. An action reachable only on hover or through a hidden element fails unless the same action has another visible entry.
  [MUST] The same main action sits in the same place on pages of the same type; sample two pages of a type, save screenshots and the main action's getBoundingClientRect, and record the business reason for any difference.
  [MUST] Operable elements on the task path compute cursor: pointer; read getComputedStyle, do not infer from the tag.
  [MUST] Each element needed to continue the journey has a visible area larger than 8 square pixels after scrolling into view, measured on the unclipped, unobscured rectangle. When a visually hidden native input is clicked through its label, record the label's area and the for or wrapping relationship.
  [MUST] Save accessibility-tree snapshots of the start page and key steps across two loads; the needed controls keep their roles, names and hierarchy, and the key nodes stay stable across reloads and same-type pages.
  [MUST] Real purchases and sensitive submissions stay a separate, visible step. WebMCP adaptation never hides where confirmation happens or completes a user's decision invisibly.
  [MUST] Screenshots, DOM and accessibility tree can be combined as evidence; do not assume all agents use one way of perceiving the page, and never pass an interaction on a screenshot alone.
  [MUST] Playwright or a similar tool proves a specific browser flow. A changed User-Agent string does not prove Google-Agent succeeded. Keep native WebMCP, simulated browsers and real external agents as separate evidence.
  [RULE] Google's guidance for browser agents often says should, consider, recommend or can. This skill adopts those points as project acceptance criteria; reports keep the original strength and never present the project's choice as a Google requirement.

::MODULE{CONSUMERS_C02_C06_C20}
  [FACT] Google's guidance for AI Overviews and AI Mode does not require llms.txt to rank in Search. This skill still builds llms.txt for documentation reading, agent access and future compatibility.
  [FACT] Google's ADK codelab reads adk.dev's llms.txt through an MCP documentation server, a concrete developer workflow; it does not mean every Google product reads every site's llms.txt.
  [FACT] Google-Agent is a user-triggered fetcher that navigates and acts for a user request, and Google documents how to verify its requests. Whether a specific browser task succeeds has to be tested.
  [MUST] Describe Google-Extended by its current official training and grounding purpose and Google-CloudVertexBot by the Vertex use a site owner requests. Never treat either as Google-Agent or Googlebot.
  [MUST] Record the other consumers the site actually serves, such as MCP-capable developer tools, retrieval clients and browser agents. Write only proven compatibility and adoption, never that all AI will use the site.
  [MUST] An AI chat answer about the site is an independent observation with its question, time, sources and answer; one appearance or absence neither guarantees nor disproves the work. A generated report's timestamp is not HTTP evidence.
  [MUST] Outside answers can correct this skill's judgment. Adopt valid evidence and keep the verification standard for the specific implementation.

::MODULE{SOURCES}
  google_ai_search_guide:https://developers.google.com/search/docs/fundamentals/ai-optimization-guide
  google_adk_codelab:https://codelabs.developers.google.com/sdd-adk-antigravity
  google_user_triggered_fetchers:https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers
  google_crawling_changelog:https://developers.google.com/crawling/docs/changelog
  google_web_bot_auth:https://developers.google.com/crawling/docs/crawlers-fetchers/web-bot-auth
  google_common_crawlers:https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
  web_dev_agent_site_ux:https://web.dev/articles/ai-agent-site-ux
  web_dev_ai_agents:https://web.dev/articles/ai-agents
  web_dev_accessibility_tree:https://web.dev/articles/the-accessibility-tree
  webmcp_draft:https://webmachinelearning.github.io/webmcp/
  chrome_webmcp:https://developer.chrome.com/docs/ai/webmcp
  chrome_webmcp_imperative:https://developer.chrome.com/docs/ai/webmcp/imperative-api
  chrome_webmcp_declarative:https://developer.chrome.com/docs/ai/webmcp/declarative-api
  chrome_webmcp_security:https://developer.chrome.com/docs/ai/webmcp/secure-tools
  chrome_webmcp_best_practices:https://developer.chrome.com/docs/ai/webmcp/best-practices
  chrome_webmcp_vs_mcp:https://developer.chrome.com/docs/ai/webmcp/compare-mcp
  [MUST] These pages change. Record the date and revision read, and refresh versions, trial status and API names before implementation.
::ILANG::COMPLETE::
