# dependencies-report

A small Go web app that talks to a SonarQube server, discovers all of your
portfolios, applications and projects, lets you pick any subset of them, and
then renders an interactive dependency-risk report sourced from SonarQube's
SCA risk-reports API. The whole thing lives in a single browser page with two
in-page tabs — no extra windows are opened.

## What it does

1. Renders a single-page UI that shows your SonarQube URL (taken from the
   `SQS_URL` environment variable).
2. On **Discover components** it walks your SonarQube instance and builds the
   full hierarchy of components — portfolios (`VW`/`SVW`, shown as
   **Portfolio**), applications (`APP`, shown as **App**) and projects
   (`TRK`, shown as **Project**) — then displays it as a collapsible tree
   with per-node checkboxes, a search box, and a "select all" toggle.
   Selecting a parent automatically selects all of its descendants.
3. On **Create report** the page switches to the in-page **Report** tab,
   fetches the SCA risk report for every selected component, and renders:
   - filter dropdowns for **risk type**, **severity** and **status** (each a
     multi-select),
   - a free-text search over vulnerabilities and packages,
   - summary stats (counts and bar charts per type / severity / status),
   - top-5 lists of portfolios, applications and projects by issue count,
   - a results table grouped by `(vulnerability, package)` so that one search
     hit shows every component the issue affects.

All SonarQube authentication uses the `SQS_TOKEN` environment variable as a
bearer token. The token never leaves the Go process — the browser only talks
to the local server.

## SonarQube API calls

All calls are issued by the Go backend with `Authorization: Bearer $SQS_TOKEN`
against `$SQS_URL`. Only two upstream endpoints are used.

| Endpoint | When | How it's used |
| --- | --- | --- |
| `GET /api/components/search?qualifiers={Q}&p={page}&ps=500` | Discovery — once per qualifier (`VW`, `SVW`, `APP`, `TRK`) | Lists every component of each kind. The server walks the `paging.pageIndex / pageSize / total` envelope and keeps incrementing `p` until all pages are fetched (capped at 10 000 results, which is SonarQube's deep-paging limit). |
| `GET /api/components/tree?component={key}&strategy=children&p={page}&ps=500` | Discovery — once per portfolio, sub-portfolio, and application discovered above | Returns the *resolved* immediate children of a container component. For portfolios this includes any projects/applications matched by the portfolio's selection rules (regex, tags, manual selection, …), not just the raw definition. Paged the same way as `components/search`. Each child is added as a component and a `parent → child` edge is recorded. |
| `GET /api/v2/sca/risk-reports?component={key}&pageIndex={p}&pageSize=500` | Report tab — once per selected component | Fetches the SCA dependency-risk records for that component. The server pages through `page.total` (falling back to `paging.total`) until everything is retrieved. The response is flattened to `{component, risks: [...]}`. |

The discovery walk produces a deduplicated list of components, each with
`parents` and `children` keys; the browser uses that to render the tree and
to cascade selection.

> **Why `api/components/tree` and not `api/views/show` or `api/applications/show`?**
> `views/show` returns the *definition* of a portfolio (selection mode and any
> nested sub-portfolios), not the resolved list of projects that currently
> belong to it. For portfolios that pick projects by regex or tags this means
> the project list comes back empty. `api/components/tree?strategy=children`
> returns the resolved membership uniformly for portfolios, sub-portfolios
> and applications, so a single endpoint covers every container type.

## Server endpoints (browser ↔ Go)

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Serves the single-page UI (`static/index.html`) with both the Discover and Report tabs. |
| `GET /api/config` | Returns `{sqsURL, hasToken}` for the header. |
| `GET /api/discover` | Triggers the discovery walk and returns the flat component list. |
| `GET /api/risk-report?component={key}` | Fetches and paginates risks for one component. |

## Requirements

- Go 1.22 or newer
- Network access from the machine running the server to your SonarQube
  instance
- A SonarQube user token with permission to read components, portfolios,
  applications and the SCA risk-reports API

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
   warns if `SQS_TOKEN` is missing. Two tabs are visible just below the
   header: **Discover** (active) and **Report** (disabled until you make a
   selection).
2. Click **Discover components**. After a few seconds the tree appears,
   sorted as portfolios → applications → projects. Each node shows a coloured
   badge — **Portfolio**, **App**, or **Project** — together with its display
   name and its SonarQube key.
3. Narrow scope:
   - Type into the search box to filter the tree by name or key. Ancestors of
     matches stay visible so you keep context.
   - Tick checkboxes to select components. Selecting a parent selects every
     descendant; the same project under multiple portfolios stays in sync.
   - Use **Select all** to tick every component.
4. Click **Create report (N)**. The page switches to the **Report** tab and
   begins fetching. Progress is shown at the top of the tab.
5. In the Report tab:
   - The three dropdowns let you filter by **Type**, **Severity**, and
     **Status**. All values are checked by default.
   - The search box matches vulnerability IDs / titles and package names; a
     hit reveals every component affected by that risk.
   - The cards above the table show counts by type, severity, status, plus
     the top five portfolios, applications, and projects by issue count.
   - The results table is grouped per unique `(vulnerability, package)` so
     each row lists every component the issue applies to.
6. Switch back to the **Discover** tab at any time to refine the selection
   and re-run the report.

## File layout

```
main.go             — HTTP server, discovery walk, risk-report proxy
static/index.html   — single-page UI (Discover + Report tabs in one document)
```

## Notes and limitations

- Discovery is sequential per qualifier and per container. On very large
  instances with thousands of components it can take a few seconds; results
  are not cached between page loads — click **Discover components** again to
  refresh.
- The browser fetches risks with concurrency 6 to avoid hammering SonarQube.
- Risk field names vary slightly between SonarQube versions. The report tab
  is tolerant of common variants (`riskType`/`type`, `packageName`/`package`,
  `vulnerabilityId`/`cveId`/`title`, etc.) — see the `FIELDS` map inside the
  `<script>` block of `static/index.html` to add more aliases.
- Both views live in one HTML document, so opening **Create report** does not
  open a browser tab or window — it just switches the in-page tab.
