package piiveil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngineRedactRestoreAndStreaming(t *testing.T) {
	engine := NewEngine(ModePlaceholder)
	prompt := "Cobrar a maria@startup.io con tarjeta 4532-0151-1283-0366 en postgres://admin:Secret99@db.internal:5432/prod"

	redacted, vault, count := engine.Redact(prompt)
	if count != 3 {
		t.Fatalf("expected 3 redacted spans, got %d (%s)", count, redacted)
	}
	if strings.Contains(redacted, "maria@startup.io") || strings.Contains(redacted, "4532-0151-1283-0366") {
		t.Fatalf("PII leaked in redacted output: %s", redacted)
	}

	// Simulate SSE stream where tokens are split across chunks
	restorer := vault.NewStreamingRestorer()
	chunks := []string{
		"Recibo enviado a [EMA",
		"IL_1] para tarjeta [CRED",
		"IT_CARD_1] en [CONNECTION_URI_1].",
	}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(restorer.PushChunk(c))
	}
	out.WriteString(restorer.Finish())

	expected := "Recibo enviado a maria@startup.io para tarjeta 4532-0151-1283-0366 en postgres://admin:Secret99@db.internal:5432/prod."
	if out.String() != expected {
		t.Fatalf("mismatch:\ngot:  %s\nwant: %s", out.String(), expected)
	}
}

func TestHttpDlpMiddleware(t *testing.T) {
	engine := NewEngine(ModePlaceholder)

	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		// Downstream handler should NEVER see raw PII
		if strings.Contains(s, "juan@fintech.cl") {
			t.Errorf("downstream handler saw unredacted email: %s", s)
		}
		_, _ = w.Write([]byte("Processed request for " + s))
	})

	handler := NewDlpMiddleware(engine, downstream)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat", strings.NewReader("Usuario juan@fintech.cl"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	resp := rec.Body.String()
	if resp != "Processed request for Usuario juan@fintech.cl" {
		t.Fatalf("expected restored response, got: %s", resp)
	}
}

func TestRustMcpBridgeIntegration(t *testing.T) {
	veilBin := filepath.Join("..", "..", "target", "debug", "veil.exe")
	if _, err := os.Stat(veilBin); err != nil {
		t.Skip("veil debug binary not found, skipping MCP bridge test")
	}

	bridge, err := NewMcpBridge(veilBin)
	if err != nil {
		t.Fatalf("failed to start MCP bridge: %v", err)
	}
	defer bridge.Close()

	redacted, err := bridge.Redact("Cliente ana@fintech.ar (CUIT 20-12345678-6)")
	if err != nil {
		t.Fatalf("MCP Redact failed: %v", err)
	}
	if !strings.Contains(redacted, "[EMAIL_1]") || !strings.Contains(redacted, "[NATIONAL_ID_1]") {
		t.Fatalf("unexpected MCP redaction: %s", redacted)
	}

	restored, err := bridge.Restore("Factura emitida a [EMAIL_1] con CUIT [NATIONAL_ID_1].")
	if err != nil {
		t.Fatalf("MCP Restore failed: %v", err)
	}
	if restored != "Factura emitida a ana@fintech.ar con CUIT 20-12345678-6." {
		t.Fatalf("unexpected MCP restore: %s", restored)
	}
}
