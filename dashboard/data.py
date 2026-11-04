"""Validated, localhost-only dashboard data access. No Streamlit or persistence."""

from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# Reuse response contracts only; analysis always goes through HTTP.
from backend.main import AnalyzeURLResponse
from backend.decision_policy import URLDecision
from backend.text_investigator import AnalyzeTextResponse, OLLAMA_MODEL

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_PATH = ROOT / "benchmarks/results/url_evaluation.json"
API = "http://127.0.0.1:8000"
OLLAMA = "http://127.0.0.1:11434"


class DataError(Exception):
    """Safe user-facing error; never contains upstream bodies or submitted data."""


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")


class Health(Contract):
    status: Literal["ok"]
    service: Literal["SUS.NOT"]


class HistoryStatus(Contract):
    enabled: bool


class ModelInfo(Contract):
    name: str


class ModelList(Contract):
    models: list[ModelInfo]


class Record(Contract):
    investigation_id: UUID
    timestamp_utc: datetime
    investigation_type: Literal["URL", "text"]
    sus_score: int | None = Field(ge=0, le=100)
    risk_level: Literal["low", "review", "high", "critical"] | None
    indicators: list[str]
    recommended_action: Literal["continue_with_caution", "review_before_proceeding", "show_warning", "strong_warning"] | None
    policy_version: str | None
    analysis_status: Literal["completed", "failed"]

    @model_validator(mode="after")
    def utc_required(self):
        if self.timestamp_utc.utcoffset() != timedelta(0):
            raise ValueError("UTC timestamp required")
        return self


class Page(Contract):
    items: list[Record]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)

    @model_validator(mode="after")
    def valid_page(self):
        if len(self.items) > self.limit or len(self.items) > max(0, self.total - self.offset):
            raise ValueError("Inconsistent page")
        return self


class Metrics(Contract):
    true_positives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1_score: float = Field(ge=0, le=1)
    accuracy: float = Field(ge=0, le=1)


class Benchmark(Contract):
    evaluation_version: str
    dataset_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dataset_size: int = Field(ge=0)
    warning_threshold: int = Field(ge=0, le=100)
    metrics: Metrics

    @model_validator(mode="after")
    def counts_match(self):
        m = self.metrics
        if sum((m.true_positives, m.true_negatives, m.false_positives, m.false_negatives)) != self.dataset_size:
            raise ValueError("Counts do not match dataset size")
        return self


def load_benchmark(path: Path = BENCHMARK_PATH) -> Benchmark:
    try:
        return Benchmark.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise DataError("Saved benchmark is missing or invalid. Re-run the offline evaluation.") from None



BENCHMARK_VERSIONS = {
    "V1": ("url_cases_v1.json", "url_evaluation_v1.json"),
    "V2": ("url_cases_v2.json", "url_evaluation_v2.json"),
    "V3": ("url_cases_v3.json", "url_evaluation_v3.json"),
}

def load_benchmark_version(version: str) -> tuple[Benchmark, list[dict]]:
    """Load saved offline evidence, verifying dataset identity and case counts."""
    if version not in BENCHMARK_VERSIONS:
        raise DataError("Unknown benchmark version.")
    dataset_name, result_name = BENCHMARK_VERSIONS[version]
    base = ROOT / "benchmarks"
    try:
        dataset = json.loads((base / dataset_name).read_text(encoding="utf-8"))
        raw = json.loads((base / "results" / result_name).read_text(encoding="utf-8"))
        benchmark = Benchmark.model_validate(raw)
        canonical = json.dumps(dataset, sort_keys=True, ensure_ascii=True)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        rows = raw["cases"]
        if (not isinstance(dataset, list) or not isinstance(rows, list)
                or len(dataset) != benchmark.dataset_size or len(rows) != len(dataset)
                or digest != benchmark.dataset_sha256
                or benchmark.evaluation_version != version[1:]):
            raise ValueError("Inconsistent saved benchmark")
        if len({case["id"] for case in dataset}) != len(dataset):
            raise ValueError("Duplicate case IDs")
        expected = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        for case, row in zip(dataset, rows):
            if any(row.get(key) != case[key] for key in ("id", "url", "expected_label", "rationale")):
                raise ValueError("Dataset and result rows disagree")
            predicted = "suspicious" if row["sus_score"] >= benchmark.warning_threshold else "benign"
            outcome = ("tp" if case["expected_label"] == "suspicious" else "fp") if predicted == "suspicious" else ("fn" if case["expected_label"] == "suspicious" else "tn")
            if row.get("predicted_label") != predicted or row.get("outcome") != outcome:
                raise ValueError("Invalid case outcome")
            expected[outcome] += 1
        m = benchmark.metrics
        if (expected["tp"], expected["tn"], expected["fp"], expected["fn"]) != (m.true_positives, m.true_negatives, m.false_positives, m.false_negatives):
            raise ValueError("Invalid confusion matrix")
        return benchmark, rows
    except (OSError, ValueError, KeyError, TypeError):
        raise DataError(f"{version} saved evidence is missing or inconsistent. Re-run its offline evaluation.") from None

def threshold_sweep(rows: list[dict], thresholds=(15, 25, 30, 40, 45, 55, 60, 70)) -> list[dict]:
    """Exploratory reclassification of stored scores; no new inference."""
    result = []
    for threshold in thresholds:
        tp = tn = fp = fn = 0
        for row in rows:
            predicted = row["sus_score"] >= threshold
            positive = row["expected_label"] == "suspicious"
            if predicted and positive: tp += 1
            elif predicted: fp += 1
            elif positive: fn += 1
            else: tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        result.append({"Threshold": threshold, "Accuracy": (tp + tn) / len(rows) if rows else 0.0,
                       "Precision": precision, "Recall": recall,
                       "F1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
                       "FP": fp, "FN": fn})
    return result

def confusion_matrix(benchmark: Benchmark) -> list[dict]:
    m = benchmark.metrics
    return [
        {"Actual": "Suspicious", "Predicted suspicious": m.true_positives, "Predicted benign": m.false_negatives},
        {"Actual": "Benign", "Predicted suspicious": m.false_positives, "Predicted benign": m.true_negatives},
    ]


class DashboardClient:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            trust_env=False, follow_redirects=False, transport=transport,
            timeout=httpx.Timeout(100, connect=3),
        )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._client.close()

    def _request(self, method, base, path, schema, *, payload=None, params=None, record=False):
        try:
            response = self._client.request(
                method, base + path, json=payload, params=params,
                headers={"X-SUSNOT-Record-History": "true"} if record else {},
                timeout=100 if path == "/analyze-text" else 5,
            )
        except httpx.TimeoutException:
            raise DataError("Local service timed out. Please retry.") from None
        except httpx.RequestError:
            raise DataError("Local service unavailable. Check that it is running.") from None
        if response.status_code == 422:
            raise DataError("Input or request parameters were rejected. Check your submission.")
        if response.status_code == 404:
            raise DataError("Requested local resource was not found.")
        if not response.is_success:
            raise DataError("Local service could not complete the request. Check FastAPI and Ollama.")
        try:
            # JSON validation accepts serialized UUIDs/timestamps while staying strict.
            return schema.model_validate_json(response.content, strict=True)
        except (ValidationError, ValueError):
            raise DataError("Local service returned an invalid response.") from None

    def health(self):
        return self._request("GET", API, "/health", Health)

    def history_status(self):
        return self._request("GET", API, "/history-status", HistoryStatus)

    def models(self):
        return self._request("GET", OLLAMA, "/api/tags", ModelList)

    def analyze_url(self, url: str):
        # URL analysis is not recorded; the decision request is the single record.
        return self._request("POST", API, "/analyze-url", AnalyzeURLResponse, payload={"url": url})

    def evaluate_url(self, url: str, *, record: bool = False):
        return self._request("POST", API, "/evaluate-url", URLDecision, payload={"url": url}, record=record)

    def analyze_text(self, text: str, *, record: bool = False):
        return self._request("POST", API, "/analyze-text", AnalyzeTextResponse, payload={"text": text}, record=record)

    def history(self, *, limit=20, offset=0):
        if type(limit) is not int or type(offset) is not int or not 1 <= limit <= 100 or offset < 0:
            raise DataError("Invalid pagination parameters.")
        page = self._request("GET", API, "/investigations", Page, params={"limit": limit, "offset": offset})
        if page.limit != limit or page.offset != offset:
            raise DataError("Local service returned inconsistent pagination.")
        return page

    def investigation(self, investigation_id: str):
        try:
            identifier = str(UUID(investigation_id))
        except (ValueError, TypeError, AttributeError):
            raise DataError("Invalid investigation ID.") from None
        record = self._request("GET", API, f"/investigations/{identifier}", Record)
        if str(record.investigation_id) != identifier:
            raise DataError("Local service returned a mismatched investigation.")
        return record


def qwen_available(models: ModelList) -> bool:
    return any(model.name == OLLAMA_MODEL for model in models.models)


def history_rows(page: Page) -> list[dict]:
    # Explicit allowlist: no raw URL/text or unknown fields from stored records.
    return [record.model_dump(mode="json") for record in page.items]
