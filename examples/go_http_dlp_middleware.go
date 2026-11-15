// Production Reference Example: Go net/http DLP Middleware & SSE Streaming Restorer
//
// Run from `sdks/go`:
//   go run ../../examples/go_http_dlp_middleware.go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	piiveil "github.com/glastor-core/pii-veil/sdks/go"
)

func main() {
	fmt.Println("🛡️  pii-veil Go SDK — HTTP DLP Middleware & SSE Restorer Demo")
	fmt.Println("----------------------------------------------------------------")

	engine := piiveil.NewEngine(piiveil.ModePlaceholder)

	// 1. Downstream handler representing an internal AI microservice or OpenAI forwarder.
	// It never sees the real email, credit card, or Postgres password!
	llmService := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sanitizedPrompt, _ := io.ReadAll(r.Body)
		fmt.Printf("🔒 [Downstream AI Handler] Received Sanitized Prompt:\n   %s\n\n", string(sanitizedPrompt))

		// Simulate LLM replying with placeholder tokens
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"reply": "Se procesó el pago de [EMAIL_1] con la tarjeta [CREDIT_CARD_1] en el cluster [CONNECTION_URI_1]."}`)
	})

	// 2. Wrap with pii-veil DLP Middleware
	protectedHandler := piiveil.NewDlpMiddleware(engine, llmService)

	// 3. Send a request containing live PII & credentials
	rawBody := `{"prompt": "Cobrar a lucia@fintech.mx en la Visa 4532-0151-1283-0366 usando postgres://admin:SuperSecret99@db.internal:5432/prod"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(rawBody))
	rec := httptest.NewRecorder()

	protectedHandler.ServeHTTP(rec, req)

	fmt.Printf("🔓 [Client Response] Automatically Restored by Middleware:\n   %s\n", rec.Body.String())
}
