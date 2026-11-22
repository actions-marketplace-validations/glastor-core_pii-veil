from fastapi import FastAPI
from pydantic import BaseModel
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = FastAPI()

# Pre-load spaCy & Presidio engines once at startup (strict production mode)
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


class RedactRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/redact")
def redact(payload: RedactRequest):
    results = analyzer.analyze(text=payload.text, language="en")
    anonymized = anonymizer.anonymize(text=payload.text, analyzer_results=results)
    return {
        "text": anonymized.text,
        "spans_found": len(results),
    }
