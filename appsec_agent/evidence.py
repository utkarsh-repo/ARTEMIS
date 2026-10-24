from __future__ import annotations
import base64, hashlib, json, os, pathlib, re, stat, time, uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)\b(token|password|secret|session|api[_-]?key)\b([\"']?\s*[:=]\s*[\"']?)[^\"'\s,;]{4,}")
]
SENSITIVE_HEADERS = {"authorization","cookie","set-cookie","x-api-key","proxy-authorization"}
SENSITIVE_FIELD_RE = re.compile(r"(?i)(?:^|[_-])(password|passwd|secret|token|access[_-]?key|api[_-]?key|client[_-]?secret|authorization|cookie|session(?:id)?|refresh[_-]?token)(?:$|[_-])")
SENSITIVE_QUERY_NAMES = {"token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "key", "secret", "password", "passwd", "session", "sessionid", "authorization", "cookie"}


def redact_url(value):
    """Redact credential-like query parameters while preserving safe URL context."""
    try:
        parts = urlsplit(str(value))
        query = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            sensitive = key.lower().replace("-", "_") in SENSITIVE_QUERY_NAMES or bool(SENSITIVE_FIELD_RE.search(key))
            query.append((key, "[REDACTED]" if sensitive else val))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except (ValueError, TypeError):
        return redact_text(value)


def redact_payload(value, key=""):
    """Recursively redact common secret-bearing structured fields."""
    if key and (key.lower() in SENSITIVE_QUERY_NAMES or bool(SENSITIVE_FIELD_RE.search(key))):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_payload(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_body(raw):
    """Return a redacted evidence representation without retaining raw secret values."""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary bodies may contain arbitrary data; do not persist them as raw base64.
        return b"[BINARY BODY OMITTED]", True
    try:
        parsed = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        safe = redact_text(decoded)
        return safe.encode("utf-8"), safe != decoded
    safe_obj = redact_payload(parsed)
    safe = json.dumps(safe_obj, ensure_ascii=False, separators=(",", ":"))
    return safe.encode("utf-8"), safe != decoded


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def redact_text(value):
    s = str(value)
    # JSON bodies need key-aware redaction because regex-only handling can miss
    # underscore-separated names such as access_token or nested secret fields.
    if s.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(s)
            safe = redact_payload(parsed)
            return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    for i, pat in enumerate(SECRET_VALUE_PATTERNS):
        if i == 0: s = pat.sub("Bearer [REDACTED]", s)
        elif i == 1: s = pat.sub("[REDACTED_JWT]", s)
        else: s = pat.sub(r"\1\2[REDACTED]", s)
    return s

def redact_headers(headers):
    def sensitive(name):
        low=name.lower()
        return low in SENSITIVE_HEADERS or any(marker in low for marker in ("authorization","cookie","token","secret","api-key","apikey","password"))
    return {k: ("[REDACTED]" if sensitive(k) else redact_text(v)[:500]) for k, v in headers.items()}

def safe_observation(obs, max_chars=3000):
    """Produce model-safe data. Raw headers/body are deliberately removed."""
    out = {}
    for k, v in obs.items():
        if k.startswith("_") or k in ("raw_headers","raw_body","request_headers","cookies"):
            continue
        if k == "body_excerpt":
            out[k] = redact_text(str(v)[:max_chars])
        elif k == "headers":
            out[k] = redact_headers(v if isinstance(v, dict) else {})
        elif k == "url":
            out[k] = redact_url(v)
        else:
            out[k] = v
    return out

class EvidenceStore:
    def __init__(self, run_dir):
        self.run_dir = pathlib.Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try: os.chmod(self.run_dir, 0o700)
        except OSError: pass
        self.seq = 0
        self._finding_keys = set()
        self._finding_count = 0
        findings_path = self.run_dir / "findings.jsonl"
        if findings_path.exists():
            for line in findings_path.read_text(encoding="utf-8").splitlines():
                try:
                    item=json.loads(line)
                    self._finding_keys.add(item.get("dedupe_key"))
                    self._finding_count += 1
                except Exception:
                    pass
    def append(self, filename, record):
        # Evidence filenames are fixed basenames. Reject traversal and symlinks so a
        # crafted run directory cannot redirect evidence writes outside the run.
        if not isinstance(filename, str) or pathlib.Path(filename).name != filename or filename in {".", ".."}:
            raise ValueError("Evidence filename must be a simple basename")
        path = self.run_dir / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Evidence destination must be a regular file")
            with os.fdopen(fd, "ab") as stream:
                fd = -1
                stream.write((json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
    def capture(self, request_record, status, response_headers, response_body, elapsed_ms, reason):
        self.seq += 1
        evidence_id = f"ev-{self.seq:05d}-{sha256(response_body)[:10]}"
        safe_body, body_redacted = redact_body(response_body)
        safe_request = redact_payload(request_record)
        if isinstance(safe_request, dict) and "url" in safe_request:
            safe_request["url"] = redact_url(safe_request["url"])
        if isinstance(safe_request, dict) and "body" in safe_request and isinstance(safe_request["body"], str):
            safe_request["body"] = redact_text(safe_request["body"])
        record = {
            "evidence_id": evidence_id, "timestamp": time.time(), "reason": redact_text(reason)[:200],
            "request": safe_request,
            "response": {"status": status, "headers": redact_headers(response_headers),
                         "body_base64": base64.b64encode(safe_body).decode(),
                         "body_sha256": sha256(response_body),
                         "stored_body_sha256": sha256(safe_body),
                         "bytes_captured": len(response_body), "bytes_stored": len(safe_body),
                         "body_redacted": body_redacted, "elapsed_ms": elapsed_ms}
        }
        self.append("evidence.jsonl", record)
        return evidence_id
    def finding(self, finding):
        import hashlib
        canonical = json.dumps({"check":finding.get("check"),"title":finding.get("title"),
                                "url":finding.get("url"),"details":finding.get("details",{})},
                               sort_keys=True,default=str)
        key=hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        if key in self._finding_keys:
            self.event({"type":"finding_deduplicated","dedupe_key":key,"title":finding.get("title")})
            return None
        self._finding_keys.add(key)
        self._finding_count += 1
        finding["finding_id"] = f"fn-{self._finding_count:05d}"
        finding["dedupe_key"] = key
        self.append("findings.jsonl", finding)
        return finding["finding_id"]
    def event(self, event):
        self.append("events.jsonl", event)
