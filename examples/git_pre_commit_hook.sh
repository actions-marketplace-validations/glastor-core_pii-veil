#!/usr/bin/env sh
# Git Pre-Commit DLP Hook powered by `veil scan`
# Copy to `.git/hooks/pre-commit` and run `chmod +x .git/hooks/pre-commit`

set -e

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

echo "🛡️  [pii-veil] Scanning staged files for leaked PII & secrets..."

for FILE in $STAGED_FILES; do
  if [ -f "$FILE" ]; then
    veil scan --file "$FILE" --fail-on-detect || {
      echo "❌ Commit blocked: Sensitive PII or secret detected in '$FILE'."
      echo "   Use 'veil redact --file $FILE' or add safe test domains to 'veil.json'."
      exit 1
    }
  fi
done

echo "✅ [pii-veil] All staged files are clean."
