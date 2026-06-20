# dependencies-report

A small Go web app that talks to a SonarQube server, discovers all of your
portfolios, applications and projects, and lets you pick any subset of them
to drive three reports:

- **Risk report** — dependency vulnerabilities, prohibited licenses and
  malware findings from SonarQube SCA.
- **Dependency report** — the full list of packages used across the
  selection, with ecosystem and license, derived from the SonarQube SPDX
  SBOMs.
- **Downloads** — the raw SPDX 3.0 SBOMs (single file or a streamed zip)
  and a CSV export of the risk report.

The whole thing is a single browser page with in-page tabs — no extra
browser windows are opened.

## What it does

1. Renders a single-page UI that shows your SonarQube URL (taken from the
   `SQS_URL` environment variable).
2. On **Discover components** it walks your SonarQube instance and builds
   the full hierarchy — portfolios (`VW`/`SVW`, shown as **Portfolio**),
   applications (`APP`, shown as **App**) and projects (`TRK`, shown as
   **Project**) — and displays it as a collapsible tree with per-node
   checkboxes, a search box, and a "select all" toggle. Selecting a parent
   automatically selects all of its descendants.
3. Once components are selected you can:
   - **Create risk report** — fetches SCA risks per component and switches
     to the in-page **Risk report** tab.
   - **Create dependency report** — fetches the SBOM per component and
     switches to the **Dependency report** tab.
   - **Download SBOM** — streams the raw SPDX 3.0 JSON of every selected
     component to your browser (a single file when one is selected, a zip
     when there are several).
4. In the Risk report tab there's also a **Download CSV** button that
   exports the rows currently visible (i.e. the filters and search are
   honoured).

All SonarQube authentication uses the `SQS_TOKEN` environment variable as a
bearer token. The token never leaves the Go process — the browser only
talks to the local server.

## SonarQube API calls

All calls are issued by the Go backend with
`Authorization: Bearer $SQS_TOKEN` against `$SQS_URL`. There are four
upstream endpoints; two for discovery, two for reporting.

### 1. `GET /api/components/search`

Lists every component of a given qualifier (`VW`, `SVW`, `APP`, `TRK`).
Called once per qualifier during discovery.

| Query parameter | Value |
| --- | --- |
| `qualifiers` | one of `VW`, `SVW`, `APP`, `TRK` |
| `ps` | `500` (page size) |
| `p` | `1`, `2`, … (page index) |

Headers: `Accept: application/json`, `Authorization: Bearer …`.

The response is a paged envelope:

```json
{ "paging": { "pageIndex": 1, "pageSize": 500, "total": 1234 },
  "components": [ { "key": "…", "name": "…", "qualifier": "TRK" }, … ] }
```

The server walks the `paging.pageIndex / pageSize / total` triple, keeps
incrementing `p` until everything has been fetched, and stops at 10 000
results (SonarQube's hard deep-paging limit). The qualifier returned by
this endpoint is the authoritative source of truth for each component.

### 2. `GET /api/components/tree`

Returns the *resolved* immediate children of a container component
(portfolio, sub-portfolio or application). Called once per discovered
container.

| Query parameter | Value |
| --- | --- |
| `component` | the container's key |
| `strategy` | `children` (immediate children only) |
| `ps` | `500` |
| `p` | `1`, `2`, … |

Headers: `Accept: application/json`, `Authorization: Bearer …`.

For portfolios this includes any projects/applications matched by the
portfolio's selection rules (regex, tags, manual selection, …) — not just
the raw definition. Children of a portfolio that are references to
elsewhere appear as **wrappers**: the wrapper has its own qualifier
(usually `SVW`) and a `refKey` field pointing at the real component. The
backend follows `refKey` so the parent edge is recorded against the real
`APP` / `TRK`, and the wrapper's qualifier is ignored in favour of the
authoritative one learned in step 1.

> **Why not `api/views/show` or `api/applications/show`?**
> `views/show` returns the *definition* of a portfolio (selection mode and
> nested sub-portfolios), not the resolved list of projects that currently
> belong to it. For portfolios that pick projects by regex or tags the
> project list comes back empty. `components/tree?strategy=children`
> returns the resolved membership uniformly for portfolios, sub-portfolios
> and applications, so one endpoint covers every container type.

### 3. `GET /api/v2/sca/risk-reports`

Returns the SCA dependency-risk findings for one component. Called once
per selected component when the Risk report runs.

| Query parameter | Value |
| --- | --- |
| `component` | the component's key |

Headers: `Accept: application/json`, `Authorization: Bearer …`.

The response is a **bare JSON array** (one risk record per element) — no
paging envelope. The backend tries the array form first and falls back to
a `{risks:[…]} / {items:[…]}` envelope shape if that ever changes. The
result is wrapped into `{component, risks: […]}` for the browser.

Risk record shape (the fields the UI consumes):

```json
{
  "projectKey": "sca_project3",
  "branchKey":  "main",
  "riskType":      "VULNERABILITY | PROHIBITED_LICENSE | MALWARE",
  "riskSeverity":  "INFO | LOW | MEDIUM | HIGH | BLOCKER",
  "riskStatus":    "OPEN | CONFIRM | ACCEPT | SAFE | FIXED",
  "riskTitle":       "CVE-2022-23491 - Insufficient Verification of Data Authenticity",
  "vulnerabilityId": "CVE-2022-23491",
  "cvssScore": 7.5,
  "cweIds":    ["CWE-345"],
  "packageUrl": "pkg:pypi/certifi@2022.6.15",
  "publishedOn": "2022-12-07",
  "createdAt":   "2026-04-15T20:58:40.179Z",
  "riskUrl": "https://…/dependency-risks/…"
}
```

Other versions of SonarQube may use slightly different field names. The
report tab is tolerant of common variants
(`riskType`/`type`, `packageName`/`package`,
`vulnerabilityId`/`cveId`/`title`, …) — see the `FIELDS` map inside the
`<script>` block of `static/index.html` to add more aliases.

### 4. `GET /api/v2/sca/sbom-reports`

Returns the Software Bill of Materials for one component in SPDX 3.0
JSON-LD form. Called once per selected component when the Dependency
report runs, and again (this time streamed straight through) for SBOM
downloads.

| Query parameter | Value |
| --- | --- |
| `component` | the component's key |
| `type` | `spdx_30` |

Headers: **`Accept: application/spdx+json`** (without this the server
returns HTTP 406), `Authorization: Bearer …`.

The response is a single JSON-LD document. The interesting bits are in
`@graph`:

| Node `type` | What it carries |
| --- | --- |
| `software_Package` | `name`, `software_packageVersion`, optional `externalRef[].locator[]` (a PURL like `pkg:npm/foo@1.2.3`). |
| `simplelicensing_LicenseExpression` | `simplelicensing_licenseExpression` (e.g. `MIT`, `Apache-2.0`, `NOASSERTION`). |
| `Relationship` with `relationshipType` `hasDeclaredLicense` / `hasConcludedLicense` | Edge from a `software_Package` (`from`) to a license expression (`to[0]`). |
| `LifecycleScopedRelationship` with `relationshipType=dependsOn` | Dependency edges between packages — we don't render the dep graph today, but the data is there. |

For the Dependency report the backend extracts only what's needed:

```json
{ "name": "certifi",
  "version": "2022.6.15",
  "purl":    "pkg:pypi/certifi@2022.6.15",
  "ecosystem":        "pypi",
  "declaredLicense":  "MPL-2.0",
  "concludedLicense": "MPL-2.0" }
```

The synthetic root package that represents the project itself (it has no
PURL) is skipped. For one of the projects on the test instance the raw
SBOM is ~32 MB and contains ~15 000 packages, so concurrency for the SBOM
fetch is intentionally low (2 at a time on the browser side).

For SBOM downloads the backend doesn't parse anything — it streams the
raw SPDX JSON straight through and, for multi-component selections, writes
each file directly into a `zip.Writer` so we never hold more than one
SBOM in memory at a time.

## Server endpoints (browser ↔ Go)

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Serves the single-page UI (`static/index.html`) with the Discover, Risk report and Dependency report tabs. |
| `GET /api/config` | Returns `{sqsURL, hasToken}` for the header. |
| `GET /api/discover` | Triggers the discovery walk (endpoints 1 and 2 above) and returns the flat component list. |
| `GET /api/risk-report?component={key}` | Calls endpoint 3 and returns `{component, risks:[…]}`. |
| `GET /api/sbom-report?component={key}` | Calls endpoint 4, parses the SPDX graph, and returns a lean `{component, packages:[…]}`. |
| `GET /api/sbom-download?component={k1}&component={k2}…` | Streams the raw SPDX JSON (single component) or a `sboms.zip` (multiple). |

## Requirements

- Go 1.22 or newer
- Network access from the machine running the server to your SonarQube
  instance
- A SonarQube user token with permission to read components, portfolios,
  applications, the SCA risk-reports API and the SCA SBOM API

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `SQS_URL` | yes | Base URL of your SonarQube instance, e.g. `https://sonarqube.example.com`. Trailing slash is fine. |
| `SQS_TOKEN` | yes | Bearer token used for every SonarQube API call. |
| `LISTEN_ADDR` | no | Address the HTTP server binds to. Defaults to `:8080`. |

## Run

```sh
export SQS_URL=https://sonarqube.example.com
export SQS_TOKEN=squ_xxxxxxxxxxxxxxxxxxxxxxxx
go run .
```

Then open <http://localhost:8080> in a browser.

To build a standalone binary:

```sh
go build -o dependencies-report .
./dependencies-report
```

## Using it

1. Open the app. The header shows the SonarQube URL it's pointing at, and
   warns if `SQS_TOKEN` is missing. Three tabs are visible just below the
   header: **Discover** (active), **Risk report** and **Dependency
   report** (both disabled until you trigger them).
2. Click **Discover components**. After a few seconds the tree appears,
   sorted as portfolios → applications → projects. Each node shows a
   coloured badge — **Portfolio**, **App**, or **Project** — together
   with its display name and its SonarQube key.
3. Narrow scope:
   - Type into the search box to filter the tree by name or key. Ancestors
     of matches stay visible so you keep context.
   - Tick checkboxes to select components. Selecting a parent selects
     every descendant; the same project under multiple portfolios stays
     in sync.
   - Use **Select all** to tick every component.
4. With at least one component selected, choose any of:
   - **Create risk report (N)** — fetches risks for every selected
     component, switches to the Risk report tab and shows progress while
     loading.
   - **Create dependency report (N)** — fetches SBOMs and switches to
     the Dependency report tab.
   - **Download SBOM (N)** — saves the raw SPDX JSON for every
     selected component (single file or zip).
5. In the **Risk report** tab:
   - Three dropdowns let you filter by **Type**, **Severity**, and
     **Status** (multi-select; all values checked by default).
   - The search box matches vulnerability IDs / titles and packages; a
     hit reveals every component affected by that risk.
   - The cards above the table show counts by type, severity, status,
     plus the top five portfolios, applications, and projects by issue
     count.
   - The results table is grouped per unique `(vulnerability, package)`
     so each row lists every component the issue applies to. The
     "Affected components" cell collapses to the first three with a
     "(+N more)" toggle that expands the full list.
   - **Download CSV** exports the rows currently visible (i.e. honouring
     the filters and search). The file is UTF-8 with BOM and CRLF line
     endings, ready for Excel.
6. In the **Dependency report** tab:
   - Multi-select filters for **Ecosystem** and **License** are built
     dynamically from the loaded data and sorted by frequency.
   - Search matches package name, PURL or license expression.
   - Stat cards show top ecosystems, top licenses, totals (occurrences,
     unique versions, unique names) and top components by package count.
   - The table groups by unique `(name@version)` with the same
     expandable affected-components cell as the risk table. It caps at
     2 000 rows on screen — narrow further with filters or search if you
     need to drill in.
7. Switch back to the **Discover** tab at any time to refine the
   selection and re-run anything.

## File layout

```
main.go             — HTTP server, discovery walk, risk + SBOM proxies,
                       SBOM zip-streaming downloader
static/index.html   — single-page UI (Discover + both report tabs)
```

## Notes and limitations

- Discovery is sequential per qualifier and per container. On very large
  instances with thousands of components it can take a few seconds;
  results are not cached between page loads — click **Discover
  components** again to refresh.
- The browser fetches risks with concurrency 6 and SBOMs with
  concurrency 2 (SBOM responses are tens of MB each).
- Risk field names vary slightly between SonarQube versions; see the
  `FIELDS` map in `static/index.html` to extend the alias list.
- SBOM downloads stream both from SonarQube to the Go process and from
  the Go process to the browser, so the only memory pressure is the
  current single-SBOM buffer used by the zip writer.
- All views live in one HTML document, so opening any report does not
  open a browser tab or window — it just switches the in-page tab.
