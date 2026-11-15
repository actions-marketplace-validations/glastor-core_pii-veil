// Package piiveil provides an ultrafast reversible PII & secret anonymization SDK,
// SSE streaming restorer, net/http DLP middleware, and a persistent JSON-RPC 2.0
// STDIO bridge to the Rust `veil mcp` binary.
package piiveil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// RedactionMode defines how sensitive spans are replaced.
type RedactionMode string

const (
	ModePlaceholder RedactionMode = "placeholder"
	ModeSynthetic   RedactionMode = "synthetic"
	ModeMask        RedactionMode = "mask"
)

// VaultEntry stores a single reversible mapping.
type VaultEntry struct {
	Replacement string `json:"replacement"`
	Original    string `json:"original"`
	Kind        string `json:"kind"`
}

// Vault tracks bidirectional original <-> replacement mappings.
type Vault struct {
	mu          sync.RWMutex
	origToEntry map[string]VaultEntry
	repToOrig   map[string]string
	counters    map[string]int
}

// NewVault creates an empty reversible Vault.
func NewVault() *Vault {
	return &Vault{
		origToEntry: make(map[string]VaultEntry),
		repToOrig:   make(map[string]string),
		counters:    make(map[string]int),
	}
}

// GetOrInsert returns an existing replacement for original or creates one via gen(index).
func (v *Vault) GetOrInsert(kind, original string, gen func(idx int) string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	if entry, ok := v.origToEntry[original]; ok {
		return entry.Replacement
	}
	v.counters[kind]++
	idx := v.counters[kind]
	rep := gen(idx)

	v.origToEntry[original] = VaultEntry{
		Replacement: rep,
		Original:    original,
		Kind:        kind,
	}
	v.repToOrig[rep] = original
	return rep
}

// Restore replaces all placeholders/tokens in sanitizedText back to their original PII values.
func (v *Vault) Restore(sanitizedText string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.repToOrig) == 0 || sanitizedText == "" {
		return sanitizedText
	}

	pairs := make([]string, 0, len(v.repToOrig)*2)
	// Sort keys by length descending so longer tokens match first
	keys := make([]string, 0, len(v.repToOrig))
	for k := range v.repToOrig {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	for _, k := range keys {
		pairs = append(pairs, k, v.repToOrig[k])
	}
	return strings.NewReplacer(pairs...).Replace(sanitizedText)
}

// Len returns the number of unique entities stored in the Vault.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.origToEntry)
}

// StreamingRestorer restores placeholders across chunked LLM SSE streams
// even when a token is split across two network chunks (e.g. "[EMA" + "IL_1]").
type StreamingRestorer struct {
	vault       *Vault
	pending     string
	maxTokenLen int
}

// NewStreamingRestorer creates a chunked SSE stream restorer backed by v.
func (v *Vault) NewStreamingRestorer() *StreamingRestorer {
	maxLen := 32
	v.mu.RLock()
	for rep := range v.repToOrig {
		if len(rep)+4 > maxLen {
			maxLen = len(rep) + 4
		}
	}
	v.mu.RUnlock()
	return &StreamingRestorer{
		vault:       v,
		maxTokenLen: maxLen,
	}
}

// PushChunk processes a streaming text chunk and returns the safe restored prefix.
func (sr *StreamingRestorer) PushChunk(chunk string) string {
	if chunk == "" {
		return ""
	}
	sr.pending += chunk

	lastOpen := strings.LastIndexByte(sr.pending, '[')
	if lastOpen != -1 {
		tail := sr.pending[lastOpen:]
		if !strings.ContainsRune(tail, ']') && len(tail) <= sr.maxTokenLen {
			safePrefix := sr.pending[:lastOpen]
			sr.pending = tail
			if safePrefix == "" {
				return ""
			}
			return sr.vault.Restore(safePrefix)
		}
	}

	out := sr.vault.Restore(sr.pending)
	sr.pending = ""
	return out
}

// Finish flushes any remaining buffered bytes at the end of an SSE stream.
func (sr *StreamingRestorer) Finish() string {
	if sr.pending == "" {
		return ""
	}
	out := sr.vault.Restore(sr.pending)
	sr.pending = ""
	return out
}

type detectorRule struct {
	kind     string
	priority int
	re       *regexp.Regexp
	validate func(string) bool
}

var defaultRules = []detectorRule{
	{
		kind:     "CONNECTION_URI",
		priority: 99,
		re:       regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^\s:@"'<>]+:[^\s@"'<>]+@[^\s"'<>]+`),
	},
	{
		kind:     "OPENAI_KEY",
		priority: 95,
		re:       regexp.MustCompile(`\bsk-(?:proj-|None-|svcacct-)?[A-Za-z0-9_-]{20,}\b`),
	},
	{
		kind:     "AWS_KEY",
		priority: 90,
		re:       regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		kind:     "EMAIL",
		priority: 85,
		re:       regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
	},
	{
		kind:     "CREDIT_CARD",
		priority: 80,
		re:       regexp.MustCompile(`\b(?:\d[ \-]*?){13,19}\b`),
		validate: IsValidLuhn,
	},
	{
		kind:     "IPV4",
		priority: 70,
		re:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	},
}

// IsValidLuhn verifies a credit card candidate using the ISO/IEC 7812 Luhn checksum.
func IsValidLuhn(candidate string) bool {
	digits := make([]int, 0, 19)
	for _, r := range candidate {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		} else if r != ' ' && r != '-' {
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	allSame := true
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	sum := 0
	for idx := 0; idx < len(digits); idx++ {
		d := digits[len(digits)-1-idx]
		if idx%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// Engine performs PII detection and replacement in Go.
type Engine struct {
	mode RedactionMode
}

// NewEngine creates a new PII anonymization Engine.
func NewEngine(mode RedactionMode) *Engine {
	if mode == "" {
		mode = ModePlaceholder
	}
	return &Engine{mode: mode}
}

type spanMatch struct {
	kind     string
	priority int
	start    int
	end      int
	orig     string
}

// RedactWithVault anonymizes text and stores original <-> replacement pairs in vault.
func (e *Engine) RedactWithVault(text string, vault *Vault) (string, int) {
	var raw []spanMatch
	for _, rule := range defaultRules {
		locs := rule.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			candidate := strings.TrimRight(text[loc[0]:loc[1]], " .-")
			endPos := loc[0] + len(candidate)
			if rule.validate != nil && !rule.validate(candidate) {
				continue
			}
			raw = append(raw, spanMatch{
				kind:     rule.kind,
				priority: rule.priority,
				start:    loc[0],
				end:      endPos,
				orig:     candidate,
			})
		}
	}
	if len(raw) == 0 {
		return text, 0
	}

	sort.Slice(raw, func(i, j int) bool {
		if raw[i].start != raw[j].start {
			return raw[i].start < raw[j].start
		}
		lenI := raw[i].end - raw[i].start
		lenJ := raw[j].end - raw[j].start
		if lenI != lenJ {
			return lenI > lenJ
		}
		return raw[i].priority > raw[j].priority
	})

	var accepted []spanMatch
	for _, cand := range raw {
		if len(accepted) > 0 {
			last := &accepted[len(accepted)-1]
			if cand.start < last.end {
				if cand.priority > last.priority && (cand.end-cand.start) >= (last.end-last.start) {
					*last = cand
				}
				continue
			}
		}
		accepted = append(accepted, cand)
	}

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, s := range accepted {
		if s.start > cursor {
			b.WriteString(text[cursor:s.start])
		}
		kindCopy := s.kind
		origCopy := s.orig
		rep := vault.GetOrInsert(kindCopy, origCopy, func(idx int) string {
			if e.mode == ModeMask {
				if kindCopy == "EMAIL" {
					if at := strings.IndexByte(origCopy, '@'); at > 0 {
						return origCopy[:1] + "***" + origCopy[at:]
					}
				}
				return "***REDACTED***"
			}
			return fmt.Sprintf("[%s_%d]", kindCopy, idx)
		})
		b.WriteString(rep)
		cursor = s.end
	}
	if cursor < len(text) {
		b.WriteString(text[cursor:])
	}
	return b.String(), len(accepted)
}

// Redact anonymizes text and returns the sanitized string, a fresh Vault, and the span count.
func (e *Engine) Redact(text string) (string, *Vault, int) {
	v := NewVault()
	out, count := e.RedactWithVault(text, v)
	return out, v, count
}

// NewDlpMiddleware wraps an http.Handler so incoming request bodies have PII redacted
// before reaching next, and downstream response bodies have placeholders restored automatically.
func NewDlpMiddleware(engine *Engine, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vault := NewVault()
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err == nil && len(bodyBytes) > 0 {
				redactedReq, _ := engine.RedactWithVault(string(bodyBytes), vault)
				r.Body = io.NopCloser(strings.NewReader(redactedReq))
				r.ContentLength = int64(len(redactedReq))
			}
		}

		rec := &responseBufferWriter{
			header: make(http.Header),
			status: http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		for k, vals := range rec.header {
			if strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		restoredResp := vault.Restore(rec.body.String())
		w.WriteHeader(rec.status)
		_, _ = w.Write([]byte(restoredResp))
	})
}

type responseBufferWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *responseBufferWriter) Header() http.Header { return w.header }
func (w *responseBufferWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}
func (w *responseBufferWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

// McpBridge connects to the Rust `veil mcp` server over persistent STDIO pipes.
type McpBridge struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	nextID int
}

// NewMcpBridge launches `veil mcp` and initializes the JSON-RPC 2.0 session.
func NewMcpBridge(veilBinaryPath string) (*McpBridge, error) {
	cmd := exec.Command(veilBinaryPath, "mcp")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	b := &McpBridge{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdoutPipe),
		nextID: 1,
	}
	if _, err := b.callRPC("initialize", map[string]any{}); err != nil {
		_ = b.Close()
		return nil, err
	}
	return b, nil
}

func (b *McpBridge) callRPC(method string, params any) (json.RawMessage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.nextID
	b.nextID++
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := b.stdin.Write(append(raw, '\n')); err != nil {
		return nil, err
	}

	line, err := b.stdout.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("mcp error: %s", resp.Error.Message)
	}
	return resp.Result, nil
}

// Redact delegates redaction to the Rust `veil mcp` process (with all 18 detectors).
func (b *McpBridge) Redact(text string) (string, error) {
	res, err := b.callRPC("tools/call", map[string]any{
		"name": "veil_redact",
		"arguments": map[string]any{
			"text": text,
		},
	})
	if err != nil {
		return "", err
	}
	var toolOut struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &toolOut); err != nil || len(toolOut.Content) == 0 {
		return "", fmt.Errorf("invalid tool output")
	}
	var payload struct {
		RedactedText string `json:"redacted_text"`
	}
	if err := json.Unmarshal([]byte(toolOut.Content[0].Text), &payload); err != nil {
		return "", err
	}
	return payload.RedactedText, nil
}

// Restore delegates restoration to the Rust `veil mcp` session vault.
func (b *McpBridge) Restore(sanitizedText string) (string, error) {
	res, err := b.callRPC("tools/call", map[string]any{
		"name": "veil_restore",
		"arguments": map[string]any{
			"text": sanitizedText,
		},
	})
	if err != nil {
		return "", err
	}
	var toolOut struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &toolOut); err != nil || len(toolOut.Content) == 0 {
		return "", fmt.Errorf("invalid tool output")
	}
	return toolOut.Content[0].Text, nil
}

// Close terminates the underlying `veil mcp` process.
func (b *McpBridge) Close() error {
	_ = b.stdin.Close()
	if b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	return b.cmd.Wait()
}
