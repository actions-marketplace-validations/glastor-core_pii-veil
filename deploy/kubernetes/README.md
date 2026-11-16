# ☸️ GLASTOR® `pii-veil` — Kubernetes Sidecar Pattern

Deploy `pii-veil` as an ultra-lightweight (< 15 MB), zero-attack-surface sidecar proxy container inside your Kubernetes pods to transparently redact outgoing prompts and restore streaming SSE responses.

---

## 🏗️ Architecture

```text
+-------------------------------------------------------------------------------+
| Kubernetes Pod                                                                |
|                                                                               |
|  +-----------------------------+               +----------------------------+ |
|  |     Your AI Application     |               |    pii-veil DLP Sidecar    | |
|  | (FastAPI, Next.js, Express) |               |  (Distroless Static < 15MB)| |
|  +-----------------------------+               +----------------------------+ |
|                 |                                             |               |
|                 | 1. POST /v1/chat/completions                |               |
|                 |    (raw prompt with PII)                    |               |
|                 +-------------------------------------------->|               |
|                                                               |               |
|                                                               | 2. Redact PII |
|                                                               |    (Aho-Corasick)
|                                                               |    [EMAIL_1], etc.
|                                                               |               |
|                                                               | 3. Forward    |
|                                                               +-------+       |
|                                                                       |       |
|                                                                       v       |
+-----------------------------------------------------------------------+-------+
                                                                        |
                                              4. Request with ONLY      |
                                                 safe placeholders      |
                                                                        v
                                                          +-------------------+
                                                          |  External LLM API |
                                                          |  (OpenAI, Claude) |
                                                          +-------------------+
                                                                        |
                                              5. Streamed SSE response  |
                                                 with placeholders      |
                                                                        v
+-----------------------------------------------------------------------+-------+
|                                                                       |       |
|                                                               | 6. Intercept  |
|                                                               |    SSE stream |
|                                                               |               |
|                                                               | 7. Real-time  |
|                 8. Restored tokens in real-time               |    restore    |
|                 <---------------------------------------------+    tokens     |
|                 |                                                             |
+-------------------------------------------------------------------------------+
```

---

## 🚀 Quick Deployment

### 1. Apply Declarative Policy ConfigMap
```bash
kubectl apply -f deploy/kubernetes/configmap.yaml
```

### 2. Deploy AI Service with pii-veil Sidecar
```bash
kubectl apply -f deploy/kubernetes/sidecar-deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

### 3. Verify Health & Logs
```bash
kubectl get pods -l app=ai-service
kubectl logs -l app=ai-service -c pii-veil-sidecar
```

---

## 🔒 Security Hardening

The sidecar container runs under a strict enterprise security context:
- **Rootless**: Runs as non-root user `UID 65532` (`nonroot`).
- **Read-only Filesystem**: `readOnlyRootFilesystem: true`.
- **Privilege Escalation**: `allowPrivilegeEscalation: false`.
- **Capabilities**: All Linux capabilities dropped (`drop: ["ALL"]`).
- **Footprint**: Image size `< 15 MB` with zero shell, zero package manager, and zero CVEs.
