#!/usr/bin/env python3
"""
AI pull-request reviewer for GitHub Actions.

Works with any OpenAI-compatible chat-completions endpoint
(OpenAI, Azure OpenAI, Groq, Together, OpenRouter, Mistral, DeepSeek,
vLLM, LM Studio, Ollama, llama.cpp server, etc.).

Only uses the Python standard library so no `pip install` step is needed.

Environment variables
---------------------
Required:
  AI_API_KEY            Bearer token for the provider
  AI_BASE_URL           Base URL, e.g. https://api.openai.com/v1
  AI_MODEL              Model name, e.g. gpt-4o-mini
  GITHUB_TOKEN          Provided automatically by Actions
  GITHUB_REPOSITORY     owner/repo (automatic)
  PR_NUMBER             Pull request number
  PR_HEAD_SHA           Head commit SHA (reviews must be tied to a commit)

Optional:
  AI_MAX_DIFF_CHARS     Cap on diff size sent to the model (default 120000)
  AI_TEMPERATURE        Sampling temperature (default 0.2)
  AI_MAX_TOKENS         Max completion tokens (default 8000; reasoning models
                        spend these on thinking first, so go higher if truncated)
  AI_TIMEOUT            Socket read timeout in seconds (default 600). With streaming
                        on, this is per-chunk, not total, so it rarely needs raising.
  AI_BACKEND            "api" (default) posts the diff to /chat/completions directly.
                        "opencode" runs `opencode run` headlessly inside the repo
                        checkout with a read-only agent, so the model can read the
                        code around the diff. Requires opencode on PATH and a full
                        checkout (fetch-depth: 0). Ponytail loads as the native
                        OpenCode plugin instead of an inlined ruleset.
  AI_AGENT_TIMEOUT      Seconds allowed for the whole opencode run (default 1500).
  AI_JSON_MODE          "true" (default) sends response_format=json_object. Set
                        "false" for reasoning models that stop dead under JSON
                        mode (Poolside Laguna does); the script auto-detects and
                        retries without it, but opting out saves a wasted pass.
  AI_STREAM             "true" (default) streams the response, which keeps the
                        connection alive while a reasoning model thinks and avoids
                        gateway idle timeouts. Set "false" for providers that
                        don't support SSE.
  AI_EXTRA_BODY         JSON object merged into the chat-completions request body
                        for provider-specific options. Examples:
                          Poolside / vLLM, turn off thinking:
                            {"chat_template_kwargs": {"enable_thinking": false}}
                          OpenRouter, cap reasoning effort:
                            {"reasoning": {"effort": "low"}}
                          Ollama:  {"think": false}
  AI_EXCLUDE_PATTERNS   Comma-separated fnmatch globs to skip, e.g.
                        "*.lock,package-lock.json,dist/*,*.min.js"
  AI_EXTRA_INSTRUCTIONS Free text appended to the system prompt
                        (e.g. team conventions to enforce)
  AI_PONYTAIL           "off" (default), "on" = correctness review + Ponytail
                        over-engineering pass, "only" = Ponytail pass alone.
                        Loads the ruleset from github.com/DietrichGebert/ponytail
  AI_PONYTAIL_REF       Git ref of the Ponytail repo to load (default: pinned tag)
"""

from __future__ import annotations

import fnmatch
import http.client as httpclient
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

REVIEW_MARKER = "<!-- ai-pr-review -->"

DEFAULT_EXCLUDES = [
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.pdf",
    "*.snap",
]

# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #

CORRECTNESS_PROMPT = """You are a senior software engineer performing a code review on a GitHub pull request.

Your job is to find real problems, not to nitpick style. Prioritize, in order:
1. Bugs, logic errors, off-by-one errors, unhandled edge cases
2. Security issues (injection, auth/authz gaps, secrets, unsafe deserialization, SSRF, etc.)
3. Data loss or corruption risks, race conditions, resource leaks
4. Performance problems that matter (N+1 queries, unbounded loops, blocking I/O in hot paths)
5. Maintainability concerns that will realistically cause pain later
6. Missing or inadequate tests for risky changes
"""

COMMON_RULES = """
Rules:
- Only comment on lines that appear in the diff. Use the exact file path and NEW-file line number shown.
- Be specific and actionable. Say what is wrong and how to fix it. Include a short code suggestion when it helps.
- Do not praise, do not restate what the code does, do not comment on formatting a linter would catch.
- If the change looks good, say so briefly and return an empty comments list.
- Keep the summary under 200 words.
"""

OUTPUT_SCHEMA = """
You MUST respond with a single JSON object and nothing else, in this exact shape:
{
  "summary": "Markdown summary of the review. High-level assessment plus any cross-cutting concerns.",
  "verdict": "APPROVE" | "COMMENT" | "REQUEST_CHANGES",
  "comments": [
    {"path": "src/example.py", "line": 42, "severity": "high" | "medium" | "low", "body": "Markdown comment text"}
  ]
}
"""

# Ponytail (https://github.com/DietrichGebert/ponytail, MIT) is a ruleset, not a
# model. We pull its core rules + the `ponytail-review` skill and inject them
# into the system prompt. Pinned to a tag so upstream edits can't silently
# change review behaviour; override with AI_PONYTAIL_REF.
PONYTAIL_REPO = "DietrichGebert/ponytail"
PONYTAIL_DEFAULT_REF = "v4.9.0"
PONYTAIL_FILES = ["AGENTS.md", "skills/ponytail-review/SKILL.md"]

PONYTAIL_SCHEMA_ADDENDUM = """
Ponytail additions to the JSON shape:
- Over-engineering findings go in "comments" too, but with an extra "tag" field:
    {"path": "src/x.py", "line": 12, "tag": "delete" | "stdlib" | "native" | "yagni" | "shrink",
     "severity": "low", "body": "<what to cut>. <what replaces it>."}
  Keep the body to one line, in the ponytail-review style. No "consider", no hedging.
- Add a top-level integer "ponytail_net_lines": the total lines that could be removed (negative number, e.g. -37).
  Use 0 if the diff is lean already.
"""

PONYTAIL_HYBRID_NOTE = """
You are running TWO review passes on the same diff and must report both:
(a) the correctness/security review described above, and
(b) the Ponytail over-engineering review described below.
Correctness findings use "severity" and no "tag". Ponytail findings use "tag".
Never flag validation at trust boundaries, security checks, error handling that prevents
data loss, accessibility, or a single smoke test as bloat. If a line has both a bug and
bloat, report the bug; the rewrite will remove the bloat anyway.
"""

PONYTAIL_ONLY_NOTE = """
You are performing ONLY the Ponytail over-engineering review described below. Correctness,
security, and performance are explicitly out of scope; do not comment on them. Every
comment must carry a "tag". Your verdict is "COMMENT" unless the diff is lean, in which
case it is "APPROVE" with summary "Lean already. Ship."
"""


def fetch_ponytail(ref: str) -> str:
    """Download the Ponytail ruleset and review skill (raw, MIT-licensed)."""
    parts = []
    for path in PONYTAIL_FILES:
        url = f"https://raw.githubusercontent.com/{PONYTAIL_REPO}/{ref}/{path}"
        status, text = http("GET", url, {"User-Agent": "ai-pr-review"}, retries=2, timeout=30)
        if status != 200:
            raise RuntimeError(f"Could not fetch {url} ({status})")
        # Strip YAML front-matter from the skill file; the model doesn't need it.
        text = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.S)
        parts.append(f"### {path}\n\n{text.strip()}")
    return "\n\n".join(parts)


def build_system_prompt(ponytail_mode: str, ponytail_ref: str, extra: str, inline_ruleset: bool = True) -> str:
    """ponytail_mode: 'off' (default), 'on' (hybrid), or 'only'.
    inline_ruleset=False when a harness plugin already injects Ponytail every turn."""
    if ponytail_mode == "off":
        prompt = CORRECTNESS_PROMPT + COMMON_RULES + OUTPUT_SCHEMA
    else:
        if not inline_ruleset:
            ruleset = (
                "The Ponytail plugin is active in this session and its ruleset is injected on every turn. "
                "Apply the `ponytail-review` skill format for over-engineering findings."
            )
        else:
            try:
                ruleset = fetch_ponytail(ponytail_ref)
            except Exception as e:
                log(f"::warning::Ponytail requested but could not be loaded ({e}); falling back to standard review")
                ponytail_mode = "off"
                ruleset = ""
        if ponytail_mode == "only":
            prompt = (
                "You are a senior software engineer reviewing a GitHub pull request.\n"
                + PONYTAIL_ONLY_NOTE
                + COMMON_RULES
                + "\n## Ponytail ruleset\n\n" + ruleset + "\n"
                + OUTPUT_SCHEMA + PONYTAIL_SCHEMA_ADDENDUM
            )
        elif ponytail_mode == "on":
            prompt = (
                CORRECTNESS_PROMPT
                + PONYTAIL_HYBRID_NOTE
                + COMMON_RULES
                + "\n## Ponytail ruleset\n\n" + ruleset + "\n"
                + OUTPUT_SCHEMA + PONYTAIL_SCHEMA_ADDENDUM
            )
        else:
            prompt = CORRECTNESS_PROMPT + COMMON_RULES + OUTPUT_SCHEMA
    if extra:
        prompt += "\n\nAdditional project-specific instructions:\n" + extra
    return prompt


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, "")
    if value.strip() == "":
        if required:
            print(f"::error::Missing required environment variable {name}", file=sys.stderr)
            sys.exit(1)
        return default or ""
    return value


def log(msg: str) -> None:
    print(msg, flush=True)


def http(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict | None = None,
    retries: int = 3,
    timeout: int = 180,
) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            # Don't retry client errors other than rate limits
            if e.code < 500 and e.code != 429:
                return e.code, text
            last_err = e
            log(f"HTTP {e.code} from {url} (attempt {attempt + 1}/{retries}): {text[:300]}")
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            log(f"Network error calling {url} (attempt {attempt + 1}/{retries}): {e}")
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Request to {url} failed after {retries} attempts: {last_err}")


# --------------------------------------------------------------------------- #
# GitHub
# --------------------------------------------------------------------------- #

class GitHub:
    def __init__(self, token: str, repo: str):
        self.repo = repo
        self.base = f"https://api.github.com/repos/{repo}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-pr-review",
        }

    def get_pr(self, number: int) -> dict:
        status, text = http("GET", f"{self.base}/pulls/{number}", self.headers)
        if status != 200:
            raise RuntimeError(f"Failed to fetch PR: {status} {text[:300]}")
        return json.loads(text)

    def get_diff(self, number: int) -> str:
        headers = dict(self.headers, Accept="application/vnd.github.v3.diff")
        status, text = http("GET", f"{self.base}/pulls/{number}", headers)
        if status != 200:
            raise RuntimeError(f"Failed to fetch diff: {status} {text[:300]}")
        return text

    def create_review(self, number: int, commit_id: str, body: str, comments: list[dict]) -> bool:
        payload = {"commit_id": commit_id, "body": body, "event": "COMMENT", "comments": comments}
        status, text = http("POST", f"{self.base}/pulls/{number}/reviews", self.headers, payload)
        if status in (200, 201):
            return True
        log(f"::warning::Review creation failed ({status}): {text[:500]}")
        return False

    def create_issue_comment(self, number: int, body: str) -> None:
        status, text = http("POST", f"{self.base}/issues/{number}/comments", self.headers, {"body": body})
        if status not in (200, 201):
            raise RuntimeError(f"Failed to post comment: {status} {text[:300]}")


# --------------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------------- #

@dataclass
class FileDiff:
    path: str
    text: str
    commentable_lines: set[int] = field(default_factory=set)  # NEW-file line numbers (RIGHT side)


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(diff: str) -> list[FileDiff]:
    """Split a unified diff into per-file chunks and record which new-file
    line numbers are valid targets for inline review comments."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line = 0
    in_hunk = False

    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            if current:
                files.append(current)
            # "diff --git a/path b/path" -> take the b/ path
            m = re.match(r'^diff --git a/(.+?) b/(.+)$', raw)
            path = m.group(2) if m else raw.split(" b/")[-1]
            current = FileDiff(path=path, text=raw + "\n")
            in_hunk = False
            continue

        if current is None:
            continue

        current.text += raw + "\n"

        hm = HUNK_RE.match(raw)
        if hm:
            new_line = int(hm.group(1))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if raw.startswith("+"):
            current.commentable_lines.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            pass  # old-file line only; not a RIGHT-side target
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:  # context line
            current.commentable_lines.add(new_line)
            new_line += 1

    if current:
        files.append(current)
    return files


def excluded(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(os.path.basename(path), p) for p in patterns)


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

class ProviderError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:800]}")
        self.status, self.body = status, body


@dataclass
class ModelReply:
    content: str = ""
    reasoning: str = ""
    finish_reason: str | None = None
    usage: dict = field(default_factory=dict)


RETRYABLE = (
    urllib.error.URLError,
    TimeoutError,
    ConnectionError,          # includes ConnectionResetError, RemoteDisconnected
    httpclient.HTTPException,  # IncompleteRead, BadStatusLine, ...
)


def _post_chat(url: str, headers: dict, payload: dict, timeout: int) -> ModelReply:
    """One POST. Streams if the server streams; otherwise parses a normal JSON body.
    Raises ProviderError on 4xx/5xx and RETRYABLE on transport failures."""
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise ProviderError(e.code, e.read().decode(errors="replace")) from None

    with resp:
        if "text/event-stream" not in (resp.headers.get("Content-Type") or ""):
            return _parse_nonstream(json.loads(resp.read().decode()))

        reply = ModelReply()
        last_log = time.monotonic()
        phase = ""
        for raw in resp:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                ev = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(ev.get("usage"), dict):
                reply.usage = ev["usage"]
            for ch in ev.get("choices") or []:
                d = ch.get("delta") or {}
                c = d.get("content")
                if isinstance(c, list):
                    c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
                r = d.get("reasoning_content") or d.get("reasoning")
                if r:
                    reply.reasoning += r
                    if phase != "thinking":
                        phase = "thinking"
                        log("Model is thinking...")
                if c:
                    reply.content += c
                    if phase != "answering":
                        phase = "answering"
                        log(f"Model is answering (after {len(reply.reasoning)} chars of reasoning)")
                if ch.get("finish_reason"):
                    reply.finish_reason = ch["finish_reason"]
            now = time.monotonic()
            if now - last_log > 30:
                log(f"  ...{len(reply.reasoning)} reasoning chars, {len(reply.content)} content chars so far")
                last_log = now
        return reply


def _parse_nonstream(data: dict) -> ModelReply:
    try:
        choice = data["choices"][0]
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Unexpected response shape: {json.dumps(data)[:800]}") from e
    msg = choice.get("message") or {}
    content = msg.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    if not content and isinstance(choice.get("text"), str):  # legacy completions shape
        content = choice["text"]
    return ModelReply(
        content=content or "",
        reasoning=msg.get("reasoning_content") or msg.get("reasoning") or "",
        finish_reason=choice.get("finish_reason"),
        usage=data.get("usage") or {},
    )


def call_model(
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    temperature: float,
    max_tokens: int,
    timeout: int = 600,
    extra_body: dict | None = None,
    stream: bool = True,
    json_mode: bool = True,
) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream, application/json",
        "User-Agent": "ai-pr-review",
    }
    payload: dict = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if stream:
        # Streaming keeps the connection alive while a reasoning model thinks, so
        # gateway idle timeouts don't kill long requests.
        payload["stream"] = True
        payload["stream_options"] = {"include_usage": True}
    if extra_body:
        payload.update(extra_body)  # provider-specific knobs, e.g. chat_template_kwargs

    def request(payload: dict) -> ModelReply:
        transport_failures = 0
        for _ in range(8):  # bounded: a few param adaptations + 2 transport retries
            try:
                return _post_chat(url, headers, payload, timeout)
            except ProviderError as e:
                err = e.body.lower()
                if e.status == 400 and "response_format" in err and "response_format" in payload:
                    log("Provider rejected response_format; retrying without JSON mode")
                    payload.pop("response_format")
                elif e.status == 400 and "stream_options" in err and "stream_options" in payload:
                    log("Provider rejected stream_options; retrying without it")
                    payload.pop("stream_options")
                elif e.status == 400 and "stream" in err and payload.get("stream"):
                    log("Provider rejected streaming; retrying non-streaming")
                    payload.pop("stream", None)
                    payload.pop("stream_options", None)
                elif e.status == 400 and "max_completion_tokens" in err and "max_tokens" in payload:
                    log("Provider wants max_completion_tokens; retrying")
                    payload["max_completion_tokens"] = payload.pop("max_tokens")
                elif e.status == 400 and "temperature" in err and "temperature" in payload:
                    log("Provider rejected temperature; retrying without it")
                    payload.pop("temperature")
                elif e.status in (429, 500, 502, 503, 504) and transport_failures < 2:
                    transport_failures += 1
                    log(f"HTTP {e.status} from provider (retry {transport_failures}/2): {e.body[:200]}")
                    time.sleep(5 * transport_failures)
                else:
                    raise RuntimeError(f"Model request failed ({e.status}): {e.body[:800]}") from None
            except RETRYABLE as e:
                transport_failures += 1
                if transport_failures > 2:
                    raise RuntimeError(f"Model request failed after retries: {e!r}") from None
                log(f"Transport error (retry {transport_failures}/2): {e!r}")
                time.sleep(5 * transport_failures)
        raise RuntimeError("Model request failed: too many parameter adaptations")

    def report(reply: ModelReply) -> None:
        if reply.usage:
            log(f"Usage: {json.dumps(reply.usage)}")
        log(f"finish_reason={reply.finish_reason!r}, content={len(reply.content)} chars, reasoning={len(reply.reasoning)} chars")
        if reply.finish_reason == "length":
            log(
                "::warning::Response was cut off at max_tokens. Reasoning models spend tokens "
                "thinking before answering; raise AI_MAX_TOKENS or lower AI_MAX_DIFF_CHARS."
            )

    reply = request(payload)
    report(reply)

    # Reasoning models on some stacks stop dead when JSON mode is on: they think,
    # then emit nothing. Retry once without response_format if that's what we see.
    if not reply.content.strip() and reply.reasoning.strip() and "response_format" in payload \
            and reply.finish_reason != "length":
        log("::warning::Model reasoned but produced no content with JSON mode on; retrying without response_format")
        payload.pop("response_format")
        reply = request(payload)
        report(reply)

    content = reply.content
    if not content.strip() and reply.reasoning.strip():
        # Last resort: some models put the final JSON inside the reasoning channel
        try:
            extract_json(reply.reasoning)
            log("::warning::content was empty but reasoning contains a review object; using it")
            content = reply.reasoning
        except json.JSONDecodeError:
            raise RuntimeError(
                f"Model reasoned ({len(reply.reasoning)} chars) but returned no answer "
                f"(finish_reason={reply.finish_reason!r}). Start of reasoning:\n{reply.reasoning[:600]}"
            ) from None
    if not content.strip():
        raise RuntimeError(
            f"Model returned no content (finish_reason={reply.finish_reason!r}). "
            + ("It hit the token limit; raise AI_MAX_TOKENS. " if reply.finish_reason == "length" else "")
        )
    return content



# --------------------------------------------------------------------------- #
# OpenCode backend
# --------------------------------------------------------------------------- #

# Read-only tool policy for the review agent. OpenCode evaluates rules by pattern
# with last-match-wins, so the "*" deny goes first and allowances follow.
READ_ONLY_BASH = {
    "*": "deny",
    "git diff*": "allow",
    "git log*": "allow",
    "git show*": "allow",
    "git status*": "allow",
    "git blame*": "allow",
    "git ls-files*": "allow",
    "grep *": "allow",
    "rg *": "allow",
    "cat *": "allow",
    "head *": "allow",
    "tail *": "allow",
    "ls*": "allow",
    "find *": "allow",
    "find * -delete*": "deny",
    "find * -exec*": "deny",
    "wc *": "allow",
    "tree*": "allow",
    "pwd*": "allow",
}


def write_opencode_config(
    cfg_dir: str,
    model: str,
    base_url: str,
    system_prompt: str,
    temperature: float,
    max_tokens: int,
    ponytail: bool,
    extra_body: dict | None,
) -> str:
    """Write an isolated opencode.json + system prompt and return the config path.
    The API key is referenced via {env:AI_API_KEY}, never written to disk."""
    os.makedirs(cfg_dir, exist_ok=True)
    prompt_path = os.path.join(cfg_dir, "system.md")
    with open(prompt_path, "w") as f:
        f.write(system_prompt)

    model_entry: dict = {
        "name": model,
        "limit": {"context": 200000, "output": max_tokens},
    }
    if extra_body:
        # Provider-specific request options (support varies by provider SDK)
        model_entry["options"] = extra_body

    config: dict = {
        "$schema": "https://opencode.ai/config.json",
        "model": f"review/{model}",
        "share": "disabled",
        "autoupdate": False,
        "provider": {
            "review": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "PR review endpoint",
                "options": {"baseURL": base_url, "apiKey": "{env:AI_API_KEY}"},
                "models": {model: model_entry},
            }
        },
        # Global floor: nothing may write, fetch, or leave the checkout.
        "permission": {
            "edit": "deny",
            "bash": READ_ONLY_BASH,
            "webfetch": "deny",
            "websearch": "deny",
            "external_directory": "deny",
            "doom_loop": "deny",
            "read": {"*": "allow", "*.env": "deny", "*.env.*": "deny", "*.pem": "deny", "*.key": "deny"},
        },
        "agent": {
            "reviewer": {
                "description": "Read-only pull request reviewer",
                "mode": "primary",
                "prompt": "{file:" + prompt_path + "}",
                "temperature": temperature,
                "permission": {"edit": "deny", "bash": READ_ONLY_BASH, "webfetch": "deny", "websearch": "deny"},
            }
        },
    }
    if ponytail:
        config["plugin"] = ["@dietrichgebert/ponytail"]

    cfg_path = os.path.join(cfg_dir, "opencode.json")
    with open(cfg_path, "w") as f:
        json.dump(config, f, indent=2)
    return cfg_path


def call_opencode(
    repo_dir: str,
    cfg_path: str,
    model: str,
    task: str,
    timeout: int,
) -> str:
    """Run `opencode run` headlessly in the checkout and return its stdout."""
    import shutil
    import subprocess

    exe = shutil.which("opencode")
    if not exe:
        raise RuntimeError("opencode is not on PATH; install it in a prior workflow step")

    # Minimal environment: the agent must not see GITHUB_TOKEN or other CI secrets.
    env = {
        k: v for k, v in os.environ.items()
        if k in ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "AI_API_KEY", "TMPDIR")
        or k.startswith("XDG_")
    }
    env.update({
        "OPENCODE_CONFIG": cfg_path,
        "OPENCODE_DISABLE_AUTOUPDATE": "1",
        "CI": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
    })

    cmd = [exe, "run", "--agent", "reviewer", "--model", f"review/{model}", task]
    log(f"Running: opencode run --agent reviewer --model review/{model} <task>")
    try:
        proc = subprocess.run(
            cmd, cwd=repo_dir, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"opencode timed out after {timeout}s") from e

    if proc.stderr.strip():
        tail = proc.stderr.strip().splitlines()[-30:]
        log("opencode stderr (tail):\n  " + "\n  ".join(tail))
    if proc.returncode != 0:
        raise RuntimeError(
            f"opencode exited {proc.returncode}. stdout tail:\n{proc.stdout[-1500:]}"
        )
    if not proc.stdout.strip():
        raise RuntimeError("opencode produced no output")
    return proc.stdout


def extract_json(text: str) -> dict:
    """Tolerate code fences, leading/trailing prose, <think> blocks, and an
    unterminated reasoning block. Scans for the first balanced {...} that parses."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"<think>.*\Z", "", text, flags=re.S).strip()  # unterminated
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    # Walk candidate start braces; find a balanced object that parses
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text, m.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("summary" in obj or "comments" in obj):
            return obj
    raise json.JSONDecodeError("no review object found", text, 0)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}
PONYTAIL_TAGS = {"delete", "stdlib", "native", "yagni", "shrink"}
VERDICT_ICON = {"APPROVE": "✅", "COMMENT": "💬", "REQUEST_CHANGES": "🛑"}


def main() -> int:
    api_key = env("AI_API_KEY", required=True)
    base_url = env("AI_BASE_URL", required=True)
    model = env("AI_MODEL", required=True)
    gh_token = env("GITHUB_TOKEN", required=True)
    repo = env("GITHUB_REPOSITORY", required=True)
    pr_number = int(env("PR_NUMBER", required=True))
    head_sha = env("PR_HEAD_SHA", required=True)

    max_chars = int(env("AI_MAX_DIFF_CHARS", "120000"))
    temperature = float(env("AI_TEMPERATURE", "0.2"))
    max_tokens = int(env("AI_MAX_TOKENS", "8000"))
    timeout = int(env("AI_TIMEOUT", "600"))
    stream = env("AI_STREAM", "true").strip().lower() not in ("false", "0", "no", "off")
    json_mode = env("AI_JSON_MODE", "true").strip().lower() not in ("false", "0", "no", "off")
    backend = env("AI_BACKEND", "api").strip().lower()
    if backend not in ("api", "opencode"):
        log(f"::warning::Unknown AI_BACKEND {backend!r}; using 'api'")
        backend = "api"
    repo_dir = env("GITHUB_WORKSPACE", os.getcwd())
    agent_timeout = int(env("AI_AGENT_TIMEOUT", "1500"))
    extra_body: dict = {}
    if env("AI_EXTRA_BODY"):
        try:
            extra_body = json.loads(env("AI_EXTRA_BODY"))
            if not isinstance(extra_body, dict):
                raise ValueError("must be a JSON object")
        except (json.JSONDecodeError, ValueError) as e:
            log(f"::warning::AI_EXTRA_BODY is not a JSON object ({e}); ignoring")
            extra_body = {}
    extra_instructions = env("AI_EXTRA_INSTRUCTIONS")
    ponytail_mode = env("AI_PONYTAIL", "off").strip().lower()
    if ponytail_mode in ("true", "1", "yes", "hybrid"):
        ponytail_mode = "on"
    if ponytail_mode not in ("off", "on", "only"):
        log(f"::warning::Unknown AI_PONYTAIL value {ponytail_mode!r}; using 'off'")
        ponytail_mode = "off"
    ponytail_ref = env("AI_PONYTAIL_REF", PONYTAIL_DEFAULT_REF)
    excludes = DEFAULT_EXCLUDES + [
        p.strip() for p in env("AI_EXCLUDE_PATTERNS").split(",") if p.strip()
    ]

    gh = GitHub(gh_token, repo)

    log(f"Fetching PR #{pr_number} from {repo}")
    pr = gh.get_pr(pr_number)
    diff = gh.get_diff(pr_number)
    files = parse_diff(diff)

    kept, skipped_excluded, skipped_size = [], [], []
    budget = max_chars
    for f in files:
        if excluded(f.path, excludes):
            skipped_excluded.append(f.path)
            continue
        if len(f.text) > budget:
            skipped_size.append(f.path)
            continue
        kept.append(f)
        budget -= len(f.text)

    if not kept:
        log("No reviewable files after filtering; nothing to do.")
        return 0

    log(f"Reviewing {len(kept)} file(s); excluded {len(skipped_excluded)}, over budget {len(skipped_size)}")

    if ponytail_mode != "off":
        log(f"Ponytail mode: {ponytail_mode}" + (f" (ref {ponytail_ref})" if backend == "api" else " (OpenCode plugin)"))

    pr_header = (
        f"Repository: {repo}\n"
        f"PR #{pr_number}: {pr.get('title', '')}\n"
        f"Author: {pr.get('user', {}).get('login', '')}\n"
        f"Base: {pr.get('base', {}).get('ref', '')}  Head: {pr.get('head', {}).get('ref', '')} ({head_sha[:7]})\n\n"
        f"PR description:\n{(pr.get('body') or '(none)').strip()}\n\n"
    )

    if backend == "opencode":
        base_ref = pr.get("base", {}).get("ref", "main")
        system = build_system_prompt(ponytail_mode, ponytail_ref, extra_instructions, inline_ruleset=False)
        system += (
            "\n\nYou are running inside a checkout of the PR head commit with read-only tools. "
            "Use them: get the diff with `git diff origin/" + base_ref + "...HEAD`, then read the "
            "surrounding code, callers, and existing helpers before judging a change. "
            "Do not attempt to edit files, run tests, install anything, or access the network. "
            "Your final message must be ONLY the JSON object described above, nothing before or after it."
        )
        task = (
            pr_header
            + f"Changed files ({len(kept)}): " + ", ".join(f.path for f in kept) + "\n\n"
            + f"Review this pull request. Start with `git diff origin/{base_ref}...HEAD`."
        )
        cfg_dir = os.path.join(env("RUNNER_TEMP", "/tmp"), "ai-review-opencode")
        cfg_path = write_opencode_config(
            cfg_dir, model, base_url, system, temperature, max_tokens,
            ponytail=(ponytail_mode != "off"), extra_body=extra_body or None,
        )
        log(f"Calling {model} via OpenCode at {base_url}")
        raw = call_opencode(repo_dir, cfg_path, model, task, agent_timeout)
    else:
        system = build_system_prompt(ponytail_mode, ponytail_ref, extra_instructions)
        user_prompt = pr_header + f"Unified diff ({len(kept)} files):\n\n" + "".join(f.text for f in kept)
        log(f"Calling {model} at {base_url}")
        raw = call_model(
            base_url, api_key, model, system, user_prompt, temperature, max_tokens,
            timeout=timeout, extra_body=extra_body, stream=stream, json_mode=json_mode,
        )

    try:
        result = extract_json(raw)
    except json.JSONDecodeError:
        log("::warning::Model did not return valid JSON. First 1500 chars of output:")
        log(raw[:1500])
        result = {
            "summary": (
                "_The model returned output that could not be parsed as a review. "
                "Check the workflow log for the raw response. If the model is a reasoning "
                "model, try raising `AI_MAX_TOKENS` or disabling thinking via `AI_EXTRA_BODY`._\n\n"
                "<details><summary>Raw output (truncated)</summary>\n\n```\n"
                + raw[:3000].replace("```", "` ` `")
                + "\n```\n</details>"
            ),
            "verdict": "COMMENT",
            "comments": [],
        }

    summary = str(result.get("summary", "")).strip() or "_No summary provided._"
    verdict = str(result.get("verdict", "COMMENT")).upper()
    if verdict not in VERDICT_ICON:
        verdict = "COMMENT"

    # Validate inline comments against actual diff positions
    line_index = {f.path: f.commentable_lines for f in kept}
    inline: list[dict] = []
    orphaned: list[str] = []
    ponytail_count = 0
    for c in result.get("comments", []) or []:
        path = str(c.get("path", "")).lstrip("./")
        body = str(c.get("body", "")).strip()
        tag = str(c.get("tag", "") or "").lower().strip(": ")
        if tag in PONYTAIL_TAGS:
            ponytail_count += 1
            rendered = f"✂️ **{tag}:** {body}"
        else:
            sev = str(c.get("severity", "medium")).lower()
            rendered = f"{SEVERITY_ICON.get(sev, '🟠')} {body}"
        try:
            line = int(c.get("line"))
        except (TypeError, ValueError):
            line = -1
        if not body:
            continue
        if path in line_index and line in line_index[path]:
            inline.append({"path": path, "line": line, "side": "RIGHT", "body": rendered})
        else:
            orphaned.append(f"- `{path}`" + (f" (line {line})" if line > 0 else "") + f": {rendered}")

    try:
        net_lines = int(result.get("ponytail_net_lines", 0) or 0)
    except (TypeError, ValueError):
        net_lines = 0

    # Build the review body
    parts = [
        REVIEW_MARKER,
        f"## {VERDICT_ICON[verdict]} AI Review — {verdict.replace('_', ' ').title()}",
        "",
        summary,
    ]
    if orphaned:
        parts += ["", "### Additional notes", *orphaned]
    if ponytail_mode != "off":
        if ponytail_count == 0 and net_lines == 0:
            parts += ["", "**Ponytail:** Lean already. Ship."]
        else:
            parts += ["", f"**Ponytail:** {ponytail_count} thing(s) to cut · `net: {net_lines:+d} lines possible`"]
    notes = []
    if skipped_excluded:
        notes.append(f"{len(skipped_excluded)} file(s) skipped by exclude patterns")
    if skipped_size:
        notes.append(f"{len(skipped_size)} file(s) skipped for size: " + ", ".join(f"`{p}`" for p in skipped_size))
    if notes:
        parts += ["", "<sub>" + " · ".join(notes) + "</sub>"]
    footer = f"Model: `{model}` · Commit: `{head_sha[:7]}`"
    if ponytail_mode != "off":
        footer += f" · Ponytail `{ponytail_ref}` ({ponytail_mode})"
    parts += ["", f"<sub>{footer}</sub>"]
    body = "\n".join(parts)

    # Post: try full review with inline comments, then without, then as a plain comment
    if gh.create_review(pr_number, head_sha, body, inline):
        log(f"Posted review with {len(inline)} inline comment(s)")
        return 0
    if inline:
        log("Retrying review without inline comments")
        fallback_body = body + "\n\n### Inline comments (could not be attached)\n" + "\n".join(
            f"- `{c['path']}:{c['line']}` — {c['body']}" for c in inline
        )
        if gh.create_review(pr_number, head_sha, fallback_body, []):
            return 0
    gh.create_issue_comment(pr_number, body)
    log("Posted review as an issue comment")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # surface as an annotation in the Actions UI
        print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
