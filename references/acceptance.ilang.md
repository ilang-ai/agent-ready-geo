::ILANG::v5.0
[TYPE:acceptance_reference][PROJECT:agent_ready_geo][VERSION:1.0.0][DATE:2026-09-19][LANG:en]

::STATE{@SCOPE, value:Coverage policy, capability matrix, evidence levels, acceptance tests and completion rules}
::STATE{@PASS_RULE, value:A capability passes when the public URL returns the right content and type and the advertised behavior works; a created file is not a pass}

::MODULE{MODE_COMPLETION}
  inspect_site:ends when the capability matrix and the score evidence are delivered; nothing on the site changed.
  implement_site:ends when RUBRIC WEBSITE_IMPLEMENTATION_ACCEPTANCE passes, or with an explicit partial result naming each remaining check, the reason and the ready-to-apply steps.
  recheck_site:ends when the release and the current score are recorded, or regressions are repaired and re-verified, or the exact remaining regression is reported.

::MODULE{COVERAGE_POLICY}
  [MUST] Every capability C01 to C24 gets a conclusion: reuse and verify, add and verify, keep as disclosed planned material, platform-limited, not applicable to this business, or needs repair. Nothing is silently skipped.
  [MUST] Not applicable needs a concrete business fact. Difficulty, a missing test tool or not being scored is never a reason.
  [MUST] Existing valid configuration stays. Having no ranking benefit or no score is not a reason to delete it; removal needs the owner's decision.
  [MUST] Planned material means real documents, design and entry points with an honest status. Unimplemented transactions, identities, writes or tools are never announced as running.
  [MUST] When a scanner requirement conflicts with the platform or the business, keep both sides' evidence, finish the independent work and list the exact capability still missing. Never narrow the check set or report an incomplete result as 100.
  [MUST] When drafts change, keep old entry points that still have consumers and generate the compatible form from the same data.
  [RULE] C01 to C24 are this skill's coverage numbers. They do not claim the scanner has 24 scored checks; add new check families from the live index and keep existing records.

::SCHEMA{CAPABILITY_RECORD}
  [FIELD] capability_id: C01 to C24.
  [FIELD] scanner_check_ids: the scanner's actual IDs for this capability, possibly empty; never guessed from names.
  [FIELD] purpose_and_consumers: the real task served, target clients and adoption evidence.
  [FIELD] existing_artifacts: URLs, routes, files, release and source, or none.
  [FIELD] applicability: applicable, not_applicable or unknown, with the reason.
  [FIELD] implementation_state: operational, planned, absent, broken, platform_blocked or retired.
  [FIELD] verification_state: verified, partial or unverified, recorded separately from implementation_state.
  [FIELD] score_state: pass, fail, neutral, unableToCheck or not_selected, with the raw value kept.
  [FIELD] action: reuse, add, repair, preserve_planned or document_limit, with affected files and the verification method.
  [FIELD] authority_and_contract: control needed, protocol or draft or scanner version, source link and summary.
  [FIELD] evidence_and_rollback: evidence IDs, observation time, result, recovery method and remaining conditions.
  [RULE] Planned never maps to pass by itself; unverified never maps to broken by itself; neutral comes only from the scanner's explicit rule.

::MODULE{CAPABILITY_MATRIX}
  [ITEM] C01 robots.txt: /robots.txt answers 200 as text/plain, parses into groups, keeps every earlier private-path Disallow for every bot, and lists the sitemap.
  [ITEM] C02 AI crawler rules: the rules that apply to the AI user agents the scanner names and to the clients the site serves match the owner's policy, with search, user-triggered fetching and training decided separately; named groups exist only where the policy differs; for each named bot, the group it now obeys is no wider than the group that applied to it before, and carries the Content-Signal line meant for it.
  [ITEM] C03 Content Signals: valid Content-Signal lines whose search, ai-input and ai-train values match the owner's written policy; reported as a declaration, not enforcement.
  [ITEM] C04 sitemap: parses; a sample of at least ten URLs each answers 200 without a soft 404; the main pages, taken from the owner's analytics when available or else from navigation and internal links, and deep content pages are listed; large sites use a sitemap index; robots.txt points to it.
  [ITEM] C05 HTML semantics and structured data: every JSON-LD block parses; types fit the page; FAQ answers are visible on the page; no invented dates, authors, prices, ratings or identities.
  [ITEM] C06 llms.txt: answers 200 as plain text, starts with an H1, every listed URL answers, the main pages are listed, and no marketing claims, missing pages, local paths or secrets appear.
  [ITEM] C07 llms-full.txt: answers 200; a layered alternative really retrieves; content that is not public cannot be reached through it.
  [ITEM] C08 Markdown negotiation: the same URL with Accept text/markdown returns that page's real content as text/markdown; the default stays HTML; q=0 never gets Markdown; alternating requests never cross representations.
  [ITEM] C09 HTTP Link: the scanned canonical page's response carries Link with the applicable relations and every target answers with the declared type.
  [ITEM] C10 data API: known input returns parseable data with stable IDs and source URLs; unknown ID returns a clear not-found; missing parameter returns a validation error; limits hold.
  [ITEM] C11 OpenAPI and API catalog: /.well-known/api-catalog answers as application/linkset+json; every anchor, service-desc and service-doc resolves with a matching media type; the documented operations match the real service.
  [ITEM] C12 MCP and server card: initialize, the initialized notification and tools/list work with the right version and session; at least one tools/call returns real results; the card matches the server.
  [ITEM] C13 agent skills: the index follows the current schema; each artifact's sha256 over the served, content-decoded bytes equals its digest; following the skill completes a task.
  [ITEM] C14 WebMCP: native registration and one call in a supporting browser with version and enablement recorded; unsupported browsers keep the normal flow; no fake modelContext.
  [ITEM] C15 ARD: /.well-known/ai-catalog.json answers with the current shape and exactly one of url or data per entry; an optional /.well-known/ard.json is generated from the same list and validated separately.
  [ITEM] C16 DNS-AID: the authoritative SVCB or HTTPS record exists; host, port and ALPN match the service; the index it names answers and links to real resources.
  [ITEM] C17 DNSSEC: parent DS and authoritative DNSKEY and RRSIG form a chain; at least one validating public resolver returns AD; the scanner's resolver agrees or the cache state is recorded with TTL.
  [ITEM] C18 OAuth or OIDC discovery: the document answers with issuer equal to the canonical origin or the real issuer; operational metadata lists only supported features; a planned declaration carries the construction markers and its endpoints answer 503, or 404 on hosts that cannot send 503, never a 200 fallback.
  [ITEM] C19 protected resource metadata: resource equals the described resource exactly and authorization_servers names the issuer; planned future paths sit in a separate field.
  [ITEM] C20 auth.md: answers with an H1 containing auth.md, states the real current state and points to the public read-only service; existing real authentication documents are untouched.
  [ITEM] C21 Web Bot Auth: key directory, outbound signed requests and inbound verification are evidenced separately; a directory alone proves only the first; private keys appear nowhere public.
  [ITEM] C22 A2A: a real agent endpoint handles the task and message lifecycle and its card matches it; a renamed MCP URL fails; without an A2A business the state and plan are recorded.
  [ITEM] C23 commerce family: UCP, ACP, AP2, x402 and MPP each have applicability, state, basis and verification; each binds to a real catalog, prices and checkout or is recorded as not applicable with the business fact.
  [ITEM] C24 browser agent and visitor journey: the main task completes on desktop and phone with visible entries, stable layout, pointer cursors, visible areas over 8 square pixels and a stable accessibility tree; nothing a visitor used before is broken.

::MODULE{EVIDENCE}
  [LEVEL] declared: a file or page claims a capability; nothing was executed.
  [LEVEL] http_observed: a real HTTP or DNS result, limited to that request and environment.
  [LEVEL] protocol_validated: a fixed-version schema or client validated the structure and interaction.
  [LEVEL] task_completed: a real task was completed by following the public instructions, with a checkable result.
  [LEVEL] native_browser_executed: the native interface ran in an explicitly supported browser.
  [LEVEL] external_agent_observed: a verifiable record of a real outside agent, not a simulated User-Agent or a projection.
  [MUST] One capability can have several levels; lower evidence never upgrades itself into a higher conclusion.
  [MUST] Each evidence record has evidence_id, target_url, release_revision, observed_at, client_and_version, method_or_action, request_parameters, expected, actual, raw_artifact and limitations.
  [MUST] External specification citations keep source_url, version or revision, observation date and the fields used; older conclusions keep their time range after the source changes.
  [MUST] Empty evidence is recorded as missing. Failures are attributed to site defect, client limit, authorization limit, network or CDN, scanner limit or not yet located, never lumped together as a site error.
  [MUST] An AI citation or a search display is an independent observation with question, time, source and answer; a single appearance or absence neither guarantees nor disproves the work.
  [MUST] Evidence folders stay private and outside the public webroot.

::MODULE{TESTS}
  [RULE] Run each test for its capability. Business non-applicability is recorded with its reason in the matrix; tool or environment limits are never disguised as non-applicability.
  [CASE] T01 mode boundary: an inspect or recheck request; expect no unauthorized deployment and no demand to reach 100 before finishing. Evidence: the execution record.
  [CASE] T02 routing identity: one root site, one subdirectory application and one article URL; expect ORIGIN, APP_BASE, PUBLISH_ROOT and root control resolved independently and no unauthorized root resource claimed.
  [CASE] T03 fallback detection: a missing JSON path that returns 200 HTML; expect the body and type mismatch identified and not counted as discovery.
  [CASE] T04 non-ASCII URLs: Chinese path and query, spaces, IDN host, existing percent-encoding, a redirect to a Chinese path and an explicit app base; expect correct requests or an exact local input report, no double encoding and no request-line encoding failure.
  [CASE] T05 default representation: homepage and a deep page without Accept; expect normal HTML with the original navigation and content.
  [CASE] T06 negotiation: text/markdown, quality-value precedence, wildcards and q=0; expect the representation the contract allows, no Markdown for q=0, and a recorded rule for the no-acceptable-type case.
  [CASE] T07 cache alternation: at least two HTML and two Markdown requests interleaved; expect no crossed representation, with cache status, Vary or real cache-key evidence.
  [CASE] T08 content consistency: core facts, qualifiers, dates, stable IDs and sources sampled; expect no contradiction across HTML, Markdown, API and structured data.
  [CASE] T09 llms entry: from llms.txt reach the full or layered material and the task entry; expect reachable public links, no secrets and a completed query.
  [CASE] T10 robots and sitemap: the served combined content and the index, and the effective group of each named bot; expect no accidental private exposure, no named group that drops a star-group Disallow, no managed-rule conflict and no fake valid URLs.
  [CASE] T11 structured data: syntax and facts per page type; expect true fields that match visible content, with rich-result eligibility reported separately.
  [CASE] T12 API known input: a real record or entry; expect consistent result, source and input meaning.
  [CASE] T13 API unknown and missing input: unknown ID and missing parameter; expect a clear not-found or validation error, never a fabricated match or an indistinguishable success placeholder.
  [CASE] T14 API bounds: length, pagination, count and applicable rate limits; expect bounded behavior and understandable errors, with no unauthorized load testing.
  [CASE] T15 OpenAPI and catalog: get the service description from the discovery entry and call one operation; expect method, parameters, authentication and response consistent with the real service.
  [CASE] T16 MCP lifecycle: initialize, the initialized notification and tools/list; expect correct protocol version, session and capabilities.
  [CASE] T17 MCP real calls: known, unknown and qualified queries; expect real results, sources and error meaning, with other card capabilities checked separately.
  [CASE] T18 skill and digest: download the artifact from the index, check the digest and run one task by its text; expect complete supporting files, correct links and a matching digest.
  [CASE] T19 WebMCP native: register, call and clean up in a supporting browser; expect real API execution with browser version and evidence saved; a mock is never upgraded to native.
  [CASE] T20 unsupported browser: visit without native WebMCP; expect navigation, search and reading unchanged.
  [CASE] T21 ARD and card compatibility: validate the scanner entry and any supported upstream entry separately; expect the same identity and endpoint facts, no broken old links and no mixed versions.
  [CASE] T22 DNS discovery: resolve the service index from the real SVCB or HTTPS record and fetch the resource; expect host, port, ALPN and content to match.
  [CASE] T23 DNSSEC: compare parent and authoritative chain, public resolvers and the scanner; expect sufficient evidence or an exact cache or authority limitation.
  [CASE] T24 real authentication: only for running, authorized test flows; expect consistent issuer, resource identity, scopes and client behavior, and the existing login still working.
  [CASE] T25 planned authentication: read the planned documents and public services; expect the unavailable state explicit, no implied token success, no new login gate on public content and no identity collection.
  [CASE] T26 Web Bot Auth: check keys, outbound signing and inbound verification per real business; expect correct identity and signatures, and missing kinds labeled exactly.
  [CASE] T27 A2A and commerce: verify each applicable protocol separately; real writes or payments only in an authorized sandbox; a declaration never replaces a task result.
  [CASE] T28 desktop and mobile main task: start from the homepage or a valid deep link; expect menu, reading, search, copy or download actually completed.
  [CASE] T29 interaction accessibility: keyboard, names, roles, states, error messages, async loading and overlays; expect users and agents to find the next step and finish.
  [CASE] T30 required dialogs: operate the consent, reject, manage, close, login or age paths that exist; expect real choices kept, sensible focus and no forced accept-all.
  [CASE] T31 client differences: a normal browser, an ordinary HTTP client and the agent clients the site serves; expect differences explained or listed as unresolved.
  [CASE] T32 release regression: on the same production release, the key existing features and the new capabilities; expect login, navigation, forms, downloads and payments unharmed where they apply.
  [CASE] T33 full score: the current default profile on the same production URL and release; expect 100 with no unresolved scored failure and no changed check set.
  [CASE] T34 recovery: backups readable, the release locatable and rollback verified in a suitable environment; expect resumption from the stage record without relying on lost chat context.
  [CASE] T35 visible actions and layout: every needed action of the main task and the main action on two pages of one type; expect visible entries, no hover-only actions and recorded reasons for position differences. Evidence: screenshots and element rectangles.
  [CASE] T36 pointer and visible area: all operable elements on the task path; expect computed cursor pointer, visible area over 8 square pixels and recorded label relationships for hidden native inputs.
  [CASE] T37 accessibility tree: start page and key step pages, at least two loads each; expect correct roles and names for the task controls and stable key nodes.
  [CASE] T38 WebMCP preconditions: response headers, Permissions-Policy, iframe allow, browser version and origin trial, official support or local flag; expect origin isolation, cross-origin registration only with explicit permission, and visitor evidence kept apart from local development evidence.
  [CASE] T39 WebMCP declarations: read back all tools' annotations, declarative attributes, parameter description sources and lengths; expect annotations that match side effects and recorded submission modes and confirmation places.
  [CASE] T40 critical-step confirmation: go up to the step before a real purchase or sensitive submission within scope; expect the agent to stop and ask unless that exact action is authorized, never cross it in a read-only audit, and use the sandbox rules of T27 for tests.
  [MUST] Unit tests cover known URL defects, body classification, truncation and digests; end-to-end tests cover real user tasks. Do not write tests that only restate the implementation.

::RUBRIC{WEBSITE_IMPLEMENTATION_ACCEPTANCE}
  [PASS] The current default profile shows 100 on the result page for the production URL and release, with a reviewable check set and no unresolved applicable scored failure.
  [PASS] C01 to C24 and any new live check families have state, applicability, action and evidence; valid existing configuration was kept; planned and not-applicable items have concrete reasons.
  [PASS] Every capability announced as operational passed its protocol or task test; native browser conclusions have native evidence.
  [PASS] Visitors' desktop and mobile journeys, existing identities and business flows did not regress, and all representations agree.
  [PASS] A usable release and rollback exist; platform, client, planned and unverified items are stated plainly.
  [RULE] When key conditions are missing, deliver an explicit partial result with the remaining items after finishing the independent work. Never lower the target, fabricate a score or wait indefinitely on an unchanged state.

::MODULE{DELIVERY_PACKAGE}
  [ARTIFACT] Report in the user's language: target URL, mode, result, scanner profile and time, result page URL, tasks that now work and material limits.
  [ARTIFACT] capability-matrix: CAPABILITY_RECORD rows for C01 to C24; missing values never filled in as success.
  [ARTIFACT] evidence: raw scans and the related HTTP, DNS, MCP and browser evidence bound to one release, kept private.
  [ARTIFACT] rollback and checkpoint: backup location, recovery steps, current stage, background process state and next step.
  [MUST] Keep the human summary short and the detail traceable. File names carry version and date. Handoffs to other agents are I-Lang and state the real authorization scope.
::ILANG::COMPLETE::
