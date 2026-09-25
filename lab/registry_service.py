"""KAVACHAM LAB — dataset + model registries (Sections BD/BE).

Every row describes a real artifact on disk. Nothing is invented: row
counts, columns, label distributions, duplicate/missing-value tallies
are computed by streaming the actual CSVs; model metrics come only from
the real metrics.json; unknown fields stay NULL and render as "—".
"""

import csv
import json
import os
from collections import Counter
from datetime import datetime, timezone

from lab import db

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_FILES = (
    "dataset.csv",
    "dataset_balanced.csv",
    "dataset_kavacham_v2.csv",
    "KAVACHAM_HARD_TEST.csv",
)

MODEL_FILES = (
    ("models/kavacham_v1.pkl", "kavacham_v1", "classifier"),
    ("models/kavacham_v2.pkl", "kavacham_v2", "classifier"),
    ("models/vectorizer_v1.pkl", "vectorizer_v1", "vectorizer"),
    ("models/vectorizer_v2.pkl", "vectorizer_v2", "vectorizer"),
    ("model.pkl", "model", "classifier"),
    ("vectorizer.pkl", "vectorizer", "vectorizer"),
)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _profile_csv(path):
    """Stream a CSV into BD registry facts. Raises on unreadable files."""
    row_count = 0
    columns = []
    label_counter = Counter()
    seen_hashes = set()
    duplicates = 0
    missing = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        columns = list(reader.fieldnames or [])
        has_label = "label" in columns
        for row in reader:
            row_count += 1
            values = [row.get(c) or "" for c in columns]
            if any(v == "" for v in values):
                missing += sum(1 for v in values if v == "")
            digest = hash(tuple(values))
            if digest in seen_hashes:
                duplicates += 1
            else:
                seen_hashes.add(digest)
            if has_label:
                label_counter[(row.get("label") or "").strip() or
                              "(missing)"] += 1
    return {
        "row_count": row_count,
        "columns": columns,
        "labels": sorted(label_counter)[:50],
        "class_distribution": dict(label_counter.most_common(50)),
        "duplicates": duplicates,
        "missing_values": missing,
    }


def scan_datasets():
    """Profile every known dataset file present on disk."""
    out = []
    for filename in DATASET_FILES:
        path = os.path.join(REPO_ROOT, filename)
        if not os.path.isfile(path):
            continue
        try:
            profile = _profile_csv(path)
        except Exception:
            continue
        stem = os.path.splitext(filename)[0]
        out.append({
            "dataset_id": stem,
            "name": stem.replace("_", " "),
            "source": "repository root (%s)" % filename,
            "license": None,
            "version": None,
            "download_date": None,
            "row_count": profile["row_count"],
            "columns": profile["columns"],
            "labels": profile["labels"],
            "class_distribution": profile["class_distribution"],
            "duplicates": profile["duplicates"],
            "missing_values": profile["missing_values"],
            "training_usage": None,
            "model_usage": None,
        })
    return out


def _read_metrics():
    path = os.path.join(REPO_ROOT, "metrics.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def scan_models():
    """Describe every model artifact present on disk + real metrics."""
    metrics = _read_metrics()
    version = str(metrics.get("model_version") or "")
    out = []
    for rel, model_id, kind in MODEL_FILES:
        path = os.path.join(REPO_ROOT, rel)
        if not os.path.isfile(path):
            continue
        row = {
            "model_id": model_id,
            "name": model_id.replace("_", " "),
            "path": rel.replace("\\", "/"),
            "kind": kind,
            "dataset_id": None,
            "dataset_version": None,
            "training_date": None,
            "features": None,
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "roc_auc": None,
            "false_positive_rate": None,
            "false_negative_rate": None,
            "confusion_matrix": None,
        }
        # metrics.json documents exactly one model version — attach its
        # numbers only to the matching artifact, never to the others.
        if version and version == model_id and kind == "classifier":
            row["training_date"] = metrics.get("trained_at")
            row["features"] = metrics.get("feature_extraction")
            for key in ("accuracy", "precision", "recall"):
                try:
                    row[key] = float(metrics[key]) \
                        if metrics.get(key) is not None else None
                except (TypeError, ValueError):
                    row[key] = None
            try:
                row["f1"] = float(metrics["f1_score"]) \
                    if metrics.get("f1_score") is not None else None
            except (TypeError, ValueError):
                row["f1"] = None
            try:
                row["false_positive_rate"] = float(
                    metrics["false_positive_rate"]) \
                    if metrics.get("false_positive_rate") is not None \
                    else None
            except (TypeError, ValueError):
                row["false_positive_rate"] = None
        out.append(row)
    return out


def seed_registries():
    """Insert registry rows for on-disk artifacts (idempotent)."""
    now = _now()
    with db.transaction() as conn:
        for ds in scan_datasets():
            conn.execute(
                "INSERT OR IGNORE INTO dataset_registry(dataset_id, name, "
                "source, license, version, download_date, row_count, "
                "columns_json, labels_json, class_distribution_json, "
                "duplicates, missing_values, training_usage, model_usage, "
                "registered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ds["dataset_id"], ds["name"], ds["source"], ds["license"],
                 ds["version"], ds["download_date"], ds["row_count"],
                 json.dumps(ds["columns"]), json.dumps(ds["labels"]),
                 json.dumps(ds["class_distribution"]), ds["duplicates"],
                 ds["missing_values"], ds["training_usage"],
                 ds["model_usage"], now))
        for m in scan_models():
            conn.execute(
                "INSERT OR IGNORE INTO model_registry(model_id, name, path, "
                "kind, dataset_id, dataset_version, training_date, "
                "features, accuracy, precision, recall, f1, roc_auc, "
                "false_positive_rate, false_negative_rate, "
                "confusion_matrix_json, registered_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (m["model_id"], m["name"], m["path"], m["kind"],
                 m["dataset_id"], m["dataset_version"], m["training_date"],
                 m["features"], m["accuracy"], m["precision"], m["recall"],
                 m["f1"], m["roc_auc"], m["false_positive_rate"],
                 m["false_negative_rate"],
                 json.dumps(m["confusion_matrix"])
                 if m["confusion_matrix"] is not None else None, now))


def list_datasets():
    """Registry rows with JSON columns decoded."""
    out = []
    for r in db.query("SELECT * FROM dataset_registry ORDER BY dataset_id"):
        d = dict(r)
        for key, default in (("columns_json", []), ("labels_json", []),
                             ("class_distribution_json", {})):
            try:
                d[key[:-5]] = json.loads(d.pop(key) or
                                         json.dumps(default))
            except Exception:
                d[key[:-5]] = default
        out.append(d)
    return out


def list_models():
    """Registry rows with JSON columns decoded."""
    out = []
    for r in db.query("SELECT * FROM model_registry ORDER BY model_id"):
        d = dict(r)
        try:
            d["confusion_matrix"] = json.loads(
                d.pop("confusion_matrix_json") or "null")
        except Exception:
            d["confusion_matrix"] = None
        out.append(d)
    return out
