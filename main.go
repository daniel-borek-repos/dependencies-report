// DISCLAIMER: This software is provided for illustrational purposes only.
// It comes with no warranty and no support. Use at your own risk.

package main

import (
	"archive/zip"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var staticFS embed.FS

var (
	sqsURL   = strings.TrimRight(os.Getenv("SQS_URL"), "/")
	sqsToken = os.Getenv("SQS_TOKEN")
	httpC    = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
)

type Component struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Qualifier string   `json:"qualifier"`
	Parents   []string `json:"parents,omitempty"`
	Children  []string `json:"children,omitempty"`
}

// rawComponent is what SonarQube returns inside paging envelopes. We pick out
// refKey / refQualifier because portfolio children are wrappers that point at
// the real component via refKey — the wrapper's own qualifier is meaningless
// for our purposes (it'll be SVW for applications and projects inside a
// portfolio, hiding the real qualifier).
type rawComponent struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Qualifier    string `json:"qualifier"`
	RefKey       string `json:"refKey,omitempty"`
	RefQualifier string `json:"refQualifier,omitempty"`
}

type pagingEnvelope struct {
	Paging struct {
		PageIndex int `json:"pageIndex"`
		PageSize  int `json:"pageSize"`
		Total     int `json:"total"`
	} `json:"paging"`
	Components []rawComponent `json:"components"`
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/discover", handleDiscover)
	http.HandleFunc("/api/risk-report", handleRiskReport)
	http.HandleFunc("/api/sbom-report", handleSBOMReport)
	http.HandleFunc("/api/sbom-download", handleSBOMDownload)

	log.Printf("Listening on %s, SonarQube: %s", addr, redactedURL())
	if sqsURL == "" {
		log.Printf("WARNING: SQS_URL is not set")
	}
	if sqsToken == "" {
		log.Printf("WARNING: SQS_TOKEN is not set")
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}

func redactedURL() string {
	if sqsURL == "" {
		return "(unset)"
	}
	return sqsURL
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"sqsURL":      sqsURL,
		"hasToken":    sqsToken != "",
	})
}

// handleDiscover walks all components and their relationships.
func handleDiscover(w http.ResponseWriter, r *http.Request) {
	if sqsURL == "" || sqsToken == "" {
		http.Error(w, "SQS_URL or SQS_TOKEN not set", http.StatusServiceUnavailable)
		return
	}

	all := map[string]*Component{}
	parents := map[string]map[string]struct{}{}
	addParent := func(child, parent string) {
		if child == parent {
			return
		}
		s, ok := parents[child]
		if !ok {
			s = map[string]struct{}{}
			parents[child] = s
		}
		s[parent] = struct{}{}
	}
	// upsert sets a component, preferring qualifier from a trusted source.
	// trustQualifier=true overwrites the stored qualifier (use this for results
	// coming from components/search by qualifier, where the qualifier is
	// authoritative). For wrappers returned by components/tree the qualifier
	// is unreliable, so we only fill it in if we don't already know it.
	upsert := func(key, name, qualifier string, trustQualifier bool) {
		c, ok := all[key]
		if !ok {
			c = &Component{Key: key}
			all[key] = c
		}
		if name != "" {
			c.Name = name
		}
		if qualifier != "" && (trustQualifier || c.Qualifier == "") {
			c.Qualifier = qualifier
		}
	}

	// 1) Discover all components by each qualifier. The qualifier from this
	//    call is authoritative.
	for _, q := range []string{"VW", "SVW", "APP", "TRK"} {
		cs, err := fetchComponentsByQualifier(q)
		if err != nil {
			http.Error(w, fmt.Sprintf("components/search %s: %v", q, err), http.StatusBadGateway)
			return
		}
		for _, c := range cs {
			upsert(c.Key, c.Name, q, true)
		}
	}

	// 2) For each container, list its immediate children. Children returned
	//    by components/tree may be wrappers (e.g. an APP inside a portfolio is
	//    returned with qualifier=SVW and a refKey pointing at the real APP).
	//    Collapse via refKey/refQualifier so the parent edge points at the
	//    real component, not the wrapper.
	containerKeys := []string{}
	for k, c := range all {
		if c.Qualifier == "VW" || c.Qualifier == "SVW" || c.Qualifier == "APP" {
			containerKeys = append(containerKeys, k)
		}
	}
	for _, parentKey := range containerKeys {
		children, err := fetchChildren(parentKey)
		if err != nil {
			log.Printf("components/tree %s: %v", parentKey, err)
			continue
		}
		for _, ch := range children {
			realKey := ch.Key
			realQualifier := ch.Qualifier
			if ch.RefKey != "" {
				realKey = ch.RefKey
				if ch.RefQualifier != "" {
					realQualifier = ch.RefQualifier
				} else {
					// Wrapper's own qualifier (e.g. SVW) is meaningless; if we
					// already know the referenced component, keep its qualifier.
					realQualifier = ""
				}
			}
			upsert(realKey, ch.Name, realQualifier, false)
			addParent(realKey, parentKey)
		}
	}

	// 3) Build Parents/Children fields.
	childrenMap := map[string][]string{}
	for child, ps := range parents {
		for p := range ps {
			childrenMap[p] = append(childrenMap[p], child)
		}
	}
	out := make([]*Component, 0, len(all))
	for k, c := range all {
		if ps, ok := parents[k]; ok {
			for p := range ps {
				c.Parents = append(c.Parents, p)
			}
		}
		c.Children = childrenMap[k]
		out = append(out, c)
	}

	writeJSON(w, out)
}

func fetchComponentsByQualifier(qualifier string) ([]rawComponent, error) {
	const pageSize = 500
	var out []rawComponent
	page := 1
	for {
		q := url.Values{}
		q.Set("qualifiers", qualifier)
		q.Set("ps", strconv.Itoa(pageSize))
		q.Set("p", strconv.Itoa(page))
		var env pagingEnvelope
		if err := getJSON("/api/components/search?"+q.Encode(), &env); err != nil {
			return nil, err
		}
		out = append(out, env.Components...)
		fetched := page * env.Paging.PageSize
		if env.Paging.Total == 0 || fetched >= env.Paging.Total || len(env.Components) == 0 {
			break
		}
		// SonarQube limits ?p deep paging at 10_000 results; guard against runaway.
		if fetched >= 10000 {
			break
		}
		page++
	}
	return out, nil
}

// fetchChildren returns the immediate children of a portfolio, sub-portfolio,
// or application using api/components/tree with strategy=children. Pages are
// followed until exhausted.
func fetchChildren(parentKey string) ([]rawComponent, error) {
	const pageSize = 500
	var out []rawComponent
	page := 1
	for {
		q := url.Values{}
		q.Set("component", parentKey)
		q.Set("strategy", "children")
		q.Set("ps", strconv.Itoa(pageSize))
		q.Set("p", strconv.Itoa(page))
		var env pagingEnvelope
		if err := getJSON("/api/components/tree?"+q.Encode(), &env); err != nil {
			return nil, err
		}
		out = append(out, env.Components...)
		fetched := page * env.Paging.PageSize
		if env.Paging.Total == 0 || fetched >= env.Paging.Total || len(env.Components) == 0 {
			break
		}
		if fetched >= 10000 {
			break
		}
		page++
	}
	return out, nil
}

// handleRiskReport proxies /api/v2/sca/risk-reports and paginates if needed.
// On upstream error, the response body includes the SonarQube status + body
// so the user can diagnose without digging into server logs.
func handleRiskReport(w http.ResponseWriter, r *http.Request) {
	if sqsURL == "" || sqsToken == "" {
		http.Error(w, "SQS_URL or SQS_TOKEN not set", http.StatusServiceUnavailable)
		return
	}
	comp := r.URL.Query().Get("component")
	if comp == "" {
		http.Error(w, "missing component", http.StatusBadRequest)
		return
	}

	risks, debug, err := fetchAllRisks(comp)
	if err != nil {
		// Bubble upstream details up to the browser so the user can see what
		// went wrong (status, URL, body).
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "component=%s\n%s\nlast URL: %s\n", comp, err.Error(), debug)
		return
	}
	writeJSON(w, map[string]any{
		"component": comp,
		"risks":     risks,
	})
}

// fetchAllRisks calls the v2 risk-reports endpoint for one component.
// SonarQube returns a bare JSON array of risk objects (one entry per finding).
// We also tolerate the {risks:[...]} / {items:[...]} envelopes some versions
// of the API may return.
func fetchAllRisks(component string) ([]map[string]any, string, error) {
	q := url.Values{}
	q.Set("component", component)
	path := "/api/v2/sca/risk-reports?" + q.Encode()
	lastURL := sqsURL + path

	body, err := getRaw(path)
	if err != nil {
		return nil, lastURL, err
	}

	// Bare array — the common case.
	var arr []map[string]any
	if jerr := json.Unmarshal(body, &arr); jerr == nil {
		return arr, lastURL, nil
	}

	// Envelope fallback.
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, lastURL, fmt.Errorf("decode risk-reports: %w (body: %s)", err, truncate(string(body), 500))
	}
	return extractRisks(parsed), lastURL, nil
}

// ---------------------------------------------------------------------------
// SBOM report (SPDX 3.0 JSON-LD)
// ---------------------------------------------------------------------------

type SBOMPackage struct {
	Name             string `json:"name"`
	Version          string `json:"version,omitempty"`
	Purl             string `json:"purl,omitempty"`
	Ecosystem        string `json:"ecosystem,omitempty"`
	DeclaredLicense  string `json:"declaredLicense,omitempty"`
	ConcludedLicense string `json:"concludedLicense,omitempty"`
}

// Subset of an SPDX 3.0 node — we only care about a handful of types.
type spdxNode struct {
	SpdxID       string `json:"spdxId"`
	BlankID      string `json:"@id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Version      string `json:"software_packageVersion"`
	LicenseExpr  string `json:"simplelicensing_licenseExpression"`
	RelType      string `json:"relationshipType"`
	From         string `json:"from"`
	To           []string `json:"to"`
	ExternalRef  []struct {
		Locator []string `json:"locator"`
	} `json:"externalRef"`
}

func (n *spdxNode) id() string {
	if n.SpdxID != "" {
		return n.SpdxID
	}
	return n.BlankID
}

func handleSBOMReport(w http.ResponseWriter, r *http.Request) {
	if sqsURL == "" || sqsToken == "" {
		http.Error(w, "SQS_URL or SQS_TOKEN not set", http.StatusServiceUnavailable)
		return
	}
	comp := r.URL.Query().Get("component")
	if comp == "" {
		http.Error(w, "missing component", http.StatusBadRequest)
		return
	}

	pkgs, lastURL, err := fetchSBOMPackages(comp)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "component=%s\n%s\nlast URL: %s\n", comp, err.Error(), lastURL)
		return
	}
	writeJSON(w, map[string]any{
		"component": comp,
		"packages":  pkgs,
	})
}

func fetchSBOMPackages(component string) ([]SBOMPackage, string, error) {
	q := url.Values{}
	q.Set("component", component)
	q.Set("type", "spdx_30")
	path := "/api/v2/sca/sbom-reports?" + q.Encode()
	lastURL := sqsURL + path

	body, err := getRawAccept(path, "application/spdx+json")
	if err != nil {
		return nil, lastURL, err
	}

	var doc struct {
		Graph []spdxNode `json:"@graph"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, lastURL, fmt.Errorf("decode sbom: %w (body: %s)", err, truncate(string(body), 500))
	}

	// Index nodes by id so we can resolve relationship targets without a second pass.
	byID := make(map[string]*spdxNode, len(doc.Graph))
	for i := range doc.Graph {
		n := &doc.Graph[i]
		if id := n.id(); id != "" {
			byID[id] = n
		}
	}

	// Map package id -> license expression for each license role.
	declared := map[string]string{}
	concluded := map[string]string{}
	resolveLicense := func(n *spdxNode) string {
		if len(n.To) == 0 {
			return ""
		}
		lic := byID[n.To[0]]
		if lic == nil {
			return ""
		}
		if expr := lic.LicenseExpr; expr != "" && expr != "NOASSERTION" {
			return expr
		}
		return ""
	}
	for i := range doc.Graph {
		n := &doc.Graph[i]
		if n.Type != "Relationship" {
			continue
		}
		switch n.RelType {
		case "hasDeclaredLicense":
			if expr := resolveLicense(n); expr != "" {
				declared[n.From] = expr
			}
		case "hasConcludedLicense":
			if expr := resolveLicense(n); expr != "" {
				concluded[n.From] = expr
			}
		}
	}

	// Collect packages. Skip the synthetic "manifests" root — it represents
	// the project itself and has no PURL.
	pkgs := make([]SBOMPackage, 0, len(doc.Graph)/2)
	for i := range doc.Graph {
		n := &doc.Graph[i]
		if n.Type != "software_Package" {
			continue
		}
		purl := ""
		if len(n.ExternalRef) > 0 && len(n.ExternalRef[0].Locator) > 0 {
			purl = n.ExternalRef[0].Locator[0]
		}
		if purl == "" {
			continue
		}
		id := n.id()
		pkgs = append(pkgs, SBOMPackage{
			Name:             n.Name,
			Version:          n.Version,
			Purl:             purl,
			Ecosystem:        ecosystemFromPurl(purl),
			DeclaredLicense:  declared[id],
			ConcludedLicense: concluded[id],
		})
	}
	return pkgs, lastURL, nil
}

// handleSBOMDownload streams raw SBOM bytes from SonarQube straight to the
// browser. For a single component it pipes the SPDX JSON through; for many,
// it builds a zip on the fly so we never hold multiple SBOMs in memory.
func handleSBOMDownload(w http.ResponseWriter, r *http.Request) {
	if sqsURL == "" || sqsToken == "" {
		http.Error(w, "SQS_URL or SQS_TOKEN not set", http.StatusServiceUnavailable)
		return
	}
	components := r.URL.Query()["component"]
	if len(components) == 0 {
		http.Error(w, "missing component", http.StatusBadRequest)
		return
	}

	if len(components) == 1 {
		comp := components[0]
		w.Header().Set("Content-Type", "application/spdx+json")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename=%q`, safeFilename(comp)+".spdx.json"))
		if err := streamSBOM(w, comp); err != nil {
			// Headers may already be on the wire; log and move on.
			log.Printf("sbom-download %s: %v", comp, err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="sboms.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()

	for _, comp := range components {
		entry, err := zw.Create(safeFilename(comp) + ".spdx.json")
		if err != nil {
			log.Printf("zip create %s: %v", comp, err)
			continue
		}
		if err := streamSBOM(entry, comp); err != nil {
			log.Printf("sbom-download %s: %v", comp, err)
			// Attach a sibling file with the error so the user sees what failed.
			if errEntry, e2 := zw.Create(safeFilename(comp) + ".error.txt"); e2 == nil {
				fmt.Fprintf(errEntry, "Failed to fetch SBOM for %s:\n%v\n", comp, err)
			}
		}
	}
}

// streamSBOM streams the SPDX JSON for one component into the given writer.
// Used both for the single-component path (writes directly to the HTTP
// response) and the multi-component path (writes into a zip entry).
func streamSBOM(dst io.Writer, component string) error {
	q := url.Values{}
	q.Set("component", component)
	q.Set("type", "spdx_30")
	req, err := http.NewRequest("GET", sqsURL+"/api/v2/sca/sbom-reports?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+sqsToken)
	req.Header.Set("Accept", "application/spdx+json")
	resp, err := httpC.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.New(strconv.Itoa(resp.StatusCode) + ": " + string(body))
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

// safeFilename keeps a component key usable as a filename across OSes.
func safeFilename(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			return '_'
		}
		if r < 32 {
			return '_'
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		s = "component"
	}
	return s
}

func ecosystemFromPurl(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[4:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return ""
}

func extractRisks(parsed map[string]any) []map[string]any {
	for _, key := range []string{"risks", "riskReports", "items", "data"} {
		if v, ok := parsed[key]; ok {
			if arr, ok := v.([]any); ok {
				out := make([]map[string]any, 0, len(arr))
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						out = append(out, m)
					}
				}
				return out
			}
		}
	}
	return nil
}

func getJSON(path string, dest any) error {
	body, err := getRaw(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dest)
}

func getRaw(path string) ([]byte, error) {
	return getRawAccept(path, "application/json")
}

func getRawAccept(path, accept string) ([]byte, error) {
	req, err := http.NewRequest("GET", sqsURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sqsToken)
	req.Header.Set("Accept", accept)

	resp, err := httpC.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New(strconv.Itoa(resp.StatusCode) + ": " + truncate(string(body), 500))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("encode: %v", err)
	}
}

// concurrent batch helper kept around for symmetry; not currently used because
// the frontend issues one request per component (one in-flight per browser tab).
var _ = sync.WaitGroup{}
