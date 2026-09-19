::ILANG::v5.0
[TYPE:architecture_reference][PROJECT:agent_ready_geo][VERSION:1.0.0][DATE:2026-09-19][LANG:en]

::STATE{@SCOPE, value:Where each capability lives on common hosting types, and failure patterns already seen on production sites}

::MODULE{HOSTING_BRANCHES}
  static_site_on_a_VPS:Serve the documents and discovery files through the current web server and publish directory. Real read-only API and MCP operations come from the existing application or a small local service. A static file cannot pretend to be a POST endpoint.
  WordPress_or_CMS:Prefer the platform's public content API and plugin extension points. Protect permalinks, the admin, theme updates, login, forms and the shop. Do not replace core routing with a copied web-server stanza.
  Workers_or_edge_functions:Reuse the existing project, routes, bindings and build. Confirm streaming, request methods, limits, caching and SDK runtime support before adopting an MCP library. Handle HEAD wherever GET is handled.
  application_framework:Add routes and middleware inside the existing project. Protect server rendering, static assets, content negotiation, sessions and authentication boundaries. Do not create a second application because an example used one.
  static_only_host:Publish the documents and discovery files; check what response headers and function extensions exist. Without POST handling, prepare the smallest extension the host supports and never claim MCP is running.
  provider_subdomain:Check whether the user controls DNS for that exact host. Control of the root domain does not include a provider-owned subdomain. Without that control, record the DNS-AID limit; never migrate domains on your own.
  subdirectory_application:Map ORIGIN, APP_BASE and PUBLISH_ROOT separately. Ordinary documents can live under APP_BASE; robots.txt and protocol root paths depend on ORIGIN authority; OAuth locations derive from the real issuer and resource rules. Never place a misleading .well-known copy under the mount.
  [MUST] A content site can offer real article search and reading; a tool site can expose its tools; a SaaS reuses its public and signed-in features; a shop keeps its catalog and checkout. Never turn every site into the same product.
  [MUST] WebMCP does not require a separate MCP microservice. Split services only when the architecture and the task need it.
  [MUST] These are routing choices, not ready configurations. Read the actual deployment and the provider's current documentation before editing.

::MODULE{A_USEFUL_MINIMAL_CHAIN}
  task:Search the site's public articles or catalog, then fetch one record by stable identifier.
  shared_data:One source of truth feeds pages, Markdown, the API, MCP tools and the AI entry documents, with qualifiers, provenance and dates kept.
  ai_entry:Site purpose, available facts, source URLs, how to retrieve more and the limits. Answers cite the relevant page; nothing can compel other agents to recommend the site.
  operations:Bounded queries with known and unknown inputs and a meaningful not-found result, the real MCP lifecycle, and native browser tools where supported. No arbitrary-URL fetch, admin actions or invented endpoints.
  deployment:Keep release and rollback state apart from public assets and use the site's normal release method. Measure memory and latency under the real task instead of promising capacity.

::MODULE{PROVEN_FAILURE_PATTERNS}
  html_fallback_for_missing_files:A single-page-app host, a CMS or a static platform without a 404 page answers 200 with the homepage HTML for any missing path, including /.well-known/*.json. The scanner and clients then read HTML where JSON is expected. On Cloudflare Pages, adding a top-level 404.html switches unknown paths to real 404 responses; after any restructuring, check that it still exists.
  header_rules_on_error_pages:Path-based header rules, such as a Content-Type rule for /.well-known/*.json or /*.md, also apply to the 404 page served at those paths. A 404 status with a JSON content type is acceptable; a 200 status with an HTML body is not.
  middleware_asset_fallback:Edge middleware that fetches a Markdown twin through the static asset binding can receive the homepage with 200 when the twin is missing. Judge by the body, not the status.
  head_returns_404:A worker that only handles GET answered HEAD with 404 while GET returned 200. Handle HEAD on every page route, then purge the edge cache for the affected URLs, because the 404 may be cached.
  managed_robots_prepend:A CDN option that manages robots.txt prepended its own block that disallowed several AI crawlers, contradicting the site's own Allow groups. Some parsers read only the first matching group. Move any needed lines, such as Content-Signal, into the site's own robots.txt; turn the managed block off only with the owner's decision, then purge robots.txt.
  default_client_blocked:Requests from Python's default urllib client got HTTP 403 with error code 1010 while browsers, curl and other libraries got 200. Cloudflare's browser integrity check rejects that client signature. Record both clients; the owner may scope an exception to the agent-facing paths. Never add a site-wide skip keyed on User-Agent.
  dns_aid_dashboard_fields:A DNS dashboard with separate SVCB fields for priority, target and value stored the whole record typed into the target field as an escaped string. Enter priority 1, target DOMAIN. and value alpn="h2" port="443" key65409="/ai/index.ilang" in their own fields, then read the record back through DNS over HTTPS.
  negative_dnssec_cache:After DNSSEC was enabled and the parent DS appeared, Google Public DNS validated at once while Cloudflare's resolver, the scanner's default, kept serving the older insecure answer until its cache expired. The scanner moved from 93 to 100 without further DNS changes. Compare DS, RRSIG and AD evidence with TTL before touching a correct zone; a public resolver's cache purge page can shorten the wait.
  prm_resource_mismatch:Setting the protected resource to the planned operation path instead of ORIGIN produced a resource-mismatch failure and a score of 93. Keep resource equal to the identifier being described and put future paths in a separate field.
  vary_ignored_by_cdn:A CDN ignored Vary: Accept for cached HTML, so a Markdown response could be served to browsers. Use a supported variant cache key or no-store on negotiated URLs and test alternating requests.
  edge_injected_script:An analytics beacon injected by the CDN made the HTML hashes of two identical pages differ. Keep the raw bodies and hashes; normalize only that confirmed injection when comparing authored content.
  stale_skill_digest:A skill artifact edited after its index was generated left a mismatching digest. Compute the digest from the final served bytes and regenerate compressed copies in the same release.
  markdown_file_is_not_negotiation:An explicit .md URL worked while the HTML URL ignored Accept. Test negotiation on the HTML URL itself, including q=0 and alternating order.
  accept_substring_match:Middleware that tested whether the Accept header contained text/markdown served Markdown to text/markdown;q=0, an explicit refusal, while the scanner still passed. Parse media ranges and quality values instead of matching a substring.
  protocol_mock:MCP JSON files, placeholder callbacks and a fabricated browser global can pass shallow checks while serving no task. Run a real client call and keep native browser execution apart from a test harness.
  scanner_profile_confusion:The scan API reported a failing check that the default browser profile does not include, while the result page showed 100. Report the profile's result as the score and the extra checks separately.

::MODULE{SCANNER_RESULT_AND_PRODUCT_EVIDENCE}
  [MUST] An overall 100 is a scanner result for one URL, profile and time. Keep it apart from functional test evidence and from construction-only declarations.
  [MUST] Disclosed planned-auth metadata can pass discovery while accounts and token exchange stay unavailable. Say so in every report; never present the score as working login.
  [MUST] DNSSEC signing, key rollover and registrar DS changes affect availability. Show the exact records and checks and wait for the user's explicit approval of that list; holding DNS or registrar credentials is not approval.
  [MUST] Keep visitor-facing pages useful. Implementation details, local paths, schedules, account identities and score checklists belong in private evidence, never on the site.
  [MUST] Stop when the requested readiness and the real behavior are verified. Separate content or search work may continue under its own request, without ranking claims.
::ILANG::COMPLETE::
