#!/usr/bin/env python3
"""Bounded local Presidio analyzer worker for the #113 evaluation adapter.

Evaluation-only, synthetic-only, NON-ENFORCING. This process exists to answer exactly one request
line on stdin with exactly one reply line on stdout, inside a disposable local environment that has
already passed #46's origin/license/advisory screen. It is not a production gateway, not a gateway
to any network service, and not an authority: it has no policy, no mapping, no transform and no
ability to grant a release. Everything it reports is detector evidence.

**Configuration is not code.** Every choice that changes what the analyzer can see - the NLP engine,
the enabled recognizers, the language, the country/entity set, the score threshold, context handling,
duplicate suppression, allow lists and the decision-process seam - is read from the pinned manifest
passed as the single argument. Editing the manifest is a reviewable change; editing this file is not
how a trial is reconfigured.

Three things are disabled by construction and by containment:

* no NER. The engine is Presidio's own `NoOpNlpEngine`, so no language model is loaded, no weights
  are downloaded, and person/location recognition is limited to what the selected pattern
  recognizers do on their own. The missing capability is reported, never hidden.
* no remote recognizer. No recognizer in the pinned set performs a network call, and the analyzer is
  additionally run with the network unshared by the caller.
* no automatic runtime download. `tldextract` is reconfigured from its default global instance to an
  explicit offline instance using only its bundled public-suffix snapshot, because Presidio's
  `EmailRecognizer` calls `tldextract.extract` while validating a result and the default instance
  fetches the suffix list on first use. This is recorded in the manifest.

Error handling: this worker never prints a traceback, a path, a value or an exception message to
stdout. Failures are a fixed `status` value, and the adapter turns the process exit into a fixed
code. Diagnostics go to stderr, which the adapter counts and discards.

  usage: presidio_worker.py <manifest.json>
"""

import json
import os
import sys

PROTOCOL = "hylja.presidio.worker"
PROTOCOL_VERSION = 1
MAX_INPUT_UNITS = 1 << 20
# A child-side bound on this worker's OWN post-processing, not on what the parent retains. The parent
# cannot provide it: `WORKER_OUTPUT_LIMIT` fires only after the child has already written past the cap,
# and the startup deadline is the only thing bounding what the child does before its first stdout byte -
# which is exactly where the result array is filled and the whole reply is serialised. A stub-engine
# probe measured a 1 MiB adversarial input producing 400 000 findings at 83 MiB child RSS with a ~10 MB
# reply, so an uncapped loop here is a real reachable order of magnitude, not a theoretical one.
#
# Past this many findings the worker refuses with a NAMED status rather than truncating: `FAILURE`
# becomes the adapter's `WORKER_REPORTED_FAILURE` with zero candidates. An earlier revision truncated
# and answered with an unnamed `PARTIAL`, so a reader could not tell "the worker stopped working" from
# "the worker found nothing" - that is the error this bound must not repeat. The adapter's own
# `REPLY_RESULT_LIMIT` (256) is the tighter, earlier bound and names the normal overflow path.
MAX_REPORTED_RESULTS = 4096
# Recognizer id / pattern name grammar the adapter accepts. Anything else is refused there, so a
# value could never ride in on producer metadata.
TOKEN = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


REQUEST = None
MANIFEST = None


def filtering_block():
    # Never raises. Every refusal path calls this, including refusals caused by an unreadable or
    # non-object manifest, so it reads defensively and reports a fixed, conservative context.
    manifest = MANIFEST if isinstance(MANIFEST, dict) else {}
    settings = manifest.get("configuration")
    settings = settings if isinstance(settings, dict) else {}
    filtering = settings.get("filtering")
    filtering = filtering if isinstance(filtering, dict) else {}
    return {
        "scoreThreshold": filtering.get("requestScoreThreshold"),
        "deduplicate": bool(filtering.get("deduplicate", True)),
        "allowListCount": 0,
        "allowListMatch": "NONE",
        "context": filtering.get("context", "UNAVAILABLE_NO_NLP"),
        "decisionProcess": "REQUESTED" if filtering.get("decisionProcess") else "NOT_REQUESTED",
    }


def installed_version():
    """The installed analyzer version, or the fixed token `unknown`.

    Unreadable distribution metadata is a real possibility (a stripped environment, a renamed
    distribution), and it must not become an uncaught exception with no frame at all. `unknown` then
    fails the adapter's pinned-equality check as `PRODUCER_VERSION_MISMATCH`, which is the correct and
    named outcome: Hylja must not credit a runtime whose version it cannot establish.
    """
    try:
        from importlib import metadata

        resolved = metadata.version("presidio-analyzer")
    except Exception:  # noqa: BLE001 - an unestablished version is reported, never guessed
        return "unknown"
    return resolved.replace(".", "_") if isinstance(resolved, str) and resolved else "unknown"


def runtime_block(version=None, ner_available=False):
    manifest = MANIFEST if isinstance(MANIFEST, dict) else {}
    settings = manifest.get("configuration")
    language = settings.get("language") if isinstance(settings, dict) else "en"
    if not isinstance(language, str) or not language:
        language = "en"
    return {"version": version if version is not None else installed_version(),
            "language": language, "nerAvailable": bool(ner_available)}


def die(status, results=None, unsupported=None):
    """Answer a complete protocol frame and stop. No detail leaves this process.

    Every failure path emits the whole shape - binding echoed, filtering and runtime present - so the
    adapter can name it (`WORKER_REPORTED_FAILURE`, `PRODUCER_VERSION_MISMATCH`, ...) instead of
    refusing the frame as malformed. A frame the adapter rejects for a *binding* reason is still
    fail-closed: it yields no candidate.
    """
    request = REQUEST or {}
    reply = {
        "version": PROTOCOL_VERSION,
        "protocol": PROTOCOL,
        "requestId": request.get("requestId", ""),
        "inputRef": request.get("inputRef", ""),
        "tenantRef": request.get("tenantRef", ""),
        "projectRef": request.get("projectRef", ""),
        "representation": request.get("representation", "RAW"),
        "textDigest": request.get("textDigest", ""),
        "offsetUnit": "CODE_POINT",
        "status": status,
        "results": results or [],
        "filtering": filtering_block(),
        "runtime": runtime_block(),
        "unsupported": unsupported or [],
    }
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
    raise SystemExit(0)


def read_request():
    line = sys.stdin.buffer.readline()
    if not line or len(line) > (1 << 21):
        die("FAILURE")
    try:
        # `raw_decode` plus an exact-length check: plain `json.loads` accepts trailing bytes after a
        # complete value, so two objects on one line would silently parse as the first.
        # Only the framing newline is stripped; whitespace inside the value is inside its quotes, so
        # `rstrip` cannot reach it, and anything else after the value is refused rather than ignored.
        decoded = line.decode("utf-8").rstrip("\r\n")
        request, consumed = json.JSONDecoder().raw_decode(decoded)
    except (ValueError, UnicodeDecodeError):
        die("FAILURE")
    if not isinstance(request, dict) or consumed != len(decoded):
        die("FAILURE")
    # Kept as soon as it is a dict, so a refusal that follows can still echo the binding and be named
    # by the adapter instead of being refused as a malformed frame.
    globals()["REQUEST"] = request
    if request.get("protocol") != PROTOCOL or request.get("version") != PROTOCOL_VERSION:
        die("FAILURE")
    if request.get("offsetUnit") != "CODE_POINT":
        die("FAILURE")
    text = request.get("text")
    if not isinstance(text, str) or not text or len(text) > MAX_INPUT_UNITS:
        die("FAILURE")
    for key in ("requestId", "inputRef", "tenantRef", "projectRef", "representation", "textDigest"):
        if not isinstance(request.get(key), str):
            die("FAILURE")
    return request


def safe_token(value):
    return isinstance(value, str) and 0 < len(value) <= 64 and all(character in TOKEN for character in value)


class NoEnhancer:
    """Explicit no-op context enhancement.

    `LemmaContextAwareEnhancer` needs tokens and lemmas from the analysed text, which the no-op NLP
    engine does not produce, so Presidio itself warns against that pairing. Rather than accept a
    degraded enhancer, context enhancement is switched off and the manifest records it as disabled.
    """

    def enhance_using_context(self, text, raw_results, nlp_artifacts, recognizers, context=None):
        return list(raw_results)


def build_engine(manifest):
    settings = manifest["configuration"]
    runtime = manifest["runtime"]
    # Presidio reads this at import time; bounding it is a resource control, not a tuning choice.
    os.environ["REGEX_TIMEOUT_SECONDS"] = str(runtime["regexTimeoutSeconds"])
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"

    import tldextract  # noqa: E402  imported after the offline configuration is in place
    # Presidio's `EmailRecognizer.validate_result` calls the module-level `tldextract.extract`, which
    # is a closure over the default `TLD_EXTRACTOR` created at import time and fetches the public
    # suffix list on first use. Both names are rebound to one explicitly offline instance so no
    # request leaves the process and no cache directory is written. This changes tldextract's
    # behaviour, not its code, and the manifest records it.
    offline = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True, cache_dir=None)
    tldextract.TLD_EXTRACTOR = offline
    tldextract.extract = offline.__call__

    from presidio_analyzer import AnalyzerEngine, PatternRecognizer  # noqa: E402
    from presidio_analyzer.nlp_engine import NoOpNlpEngine  # noqa: E402
    from presidio_analyzer.recognizer_registry import RecognizerRegistry  # noqa: E402
    from presidio_analyzer.predefined_recognizers import (  # noqa: E402
        EmailRecognizer, IpRecognizer, MacAddressRecognizer, PhoneRecognizer, UrlRecognizer,
    )
    from presidio_analyzer.predefined_recognizers.country_specific.us import (  # noqa: E402
        UsSsnRecognizer,
    )

    available = {
        "EmailRecognizer": EmailRecognizer,
        "IpRecognizer": IpRecognizer,
        "MacAddressRecognizer": MacAddressRecognizer,
        "PhoneRecognizer": PhoneRecognizer,
        "UrlRecognizer": UrlRecognizer,
        "UsSsnRecognizer": UsSsnRecognizer,
    }
    enabled = list(settings["recognizers"])
    if not enabled or any(name not in available for name in enabled):
        die("FAILURE")
    for name in enabled:
        if name != "PhoneRecognizer" and not issubclass(available[name], PatternRecognizer):
            die("FAILURE")

    language = settings["language"]
    nlp_engine = NoOpNlpEngine(models=[{"lang_code": language, "model_name": "none"}])
    registry = RecognizerRegistry(supported_languages=[language])
    # Explicit registration only. `load_predefined_recognizers` would add a SpacyRecognizer, which
    # NoOpNlpEngine refuses, and would enable recognizers this trial does not select.
    for name in enabled:
        registry.add_recognizer(available[name](supported_language=language))
    engine = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=[language],
                            default_score_threshold=float(settings["filtering"]["engineScoreThreshold"]),
                            context_aware_enhancer=NoEnhancer(),
                            log_decision_process=bool(runtime.get('logDecisionProcess', False)))
    if engine.nlp_engine.get_supported_entities():
        die("FAILURE")
    # Presidio's own `EntityRecognizer.id` embeds a per-process counter, so it changes between runs
    # and cannot be evidence for a pinned configuration. The class name is stable and is bound to
    # the recognizers this manifest enables, so it is what crosses the boundary instead.
    provenance = {recognizer.id: name for name, recognizer in zip(enabled, registry.recognizers)}
    return engine, language, provenance


def main():
    global MANIFEST
    # The request is read before the manifest so that every later failure - including a manifest this
    # worker cannot use - still has a binding to echo and can be named by the adapter rather than
    # refused as a malformed frame.
    try:
        request = read_request()
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 - no detail leaves this process
        die("FAILURE")
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            MANIFEST = json.load(handle)
    except Exception:  # noqa: BLE001 - an unreadable or malformed manifest is a fixed failure
        die("FAILURE")
    if not isinstance(MANIFEST, dict):
        die("FAILURE")
    if MANIFEST.get("protocol") != PROTOCOL or MANIFEST.get("version") != PROTOCOL_VERSION:
        die("FAILURE")
    settings = MANIFEST.get("configuration")
    if not isinstance(settings, dict) or not isinstance(settings.get("filtering"), dict):
        die("FAILURE")
    try:
        engine, language, recognizer_names = build_engine(MANIFEST)
    except Exception:  # noqa: BLE001 - a third-party import or configuration error is a fixed failure
        die("FAILURE")

    decision_process = bool(settings["filtering"]["decisionProcess"])
    try:
        results = engine.analyze(
            text=request["text"],
            language=language,
            entities=list(settings["entitiesRequested"]) or None,
            score_threshold=settings["filtering"]["requestScoreThreshold"],
            return_decision_process=decision_process,
            context=None,
            allow_list=[],
        )
    except Exception:  # noqa: BLE001 - never let a recognizer error become a zero-findings answer
        die("FAILURE")

    import presidio_analyzer  # noqa: E402

    # Every result is reported as the analyzer produced it. Whether a detector-native type means
    # anything to Hylja is the adapter's decision alone, so no recognizer output is dropped here.
    if len(results) > MAX_REPORTED_RESULTS:
        # Named refusal, never a truncation: the adapter reports `WORKER_REPORTED_FAILURE` and this run
        # yields no candidate at all, so a partial list can never read as a complete answer.
        die("FAILURE")
    mapped = []
    for result in results:

        item = {"entityType": result.entity_type, "start": int(result.start), "end": int(result.end),
                "score": float(result.score)}
        if decision_process and result.analysis_explanation is not None:
            # Only the two grammar-checked identifiers cross the boundary. `text_match` and `pattern`
            # are deliberately not read: they are raw content.
            seam = {}
            name = getattr(result.analysis_explanation, "pattern_name", None)
            if safe_token(name):
                seam["patternName"] = name
            identifier = (result.recognition_metadata or {}).get("recognizer_identifier")
            name_of = recognizer_names.get(identifier)
            if name_of is not None:
                seam["recognizerId"] = name_of
            enhanced = (result.recognition_metadata or {}).get(
                presidio_analyzer.RecognizerResult.IS_SCORE_ENHANCED_BY_CONTEXT_KEY)
            if isinstance(enhanced, bool):
                seam["enhancedByContext"] = enhanced
            if seam:
                item["seam"] = seam
        mapped.append(item)
    reply = {
        "version": PROTOCOL_VERSION,
        "protocol": PROTOCOL,
        "requestId": request["requestId"],
        "inputRef": request["inputRef"],
        "tenantRef": request["tenantRef"],
        "projectRef": request["projectRef"],
        "representation": request["representation"],
        "textDigest": request["textDigest"],
        "offsetUnit": "CODE_POINT",
        "status": "OK",
        "results": mapped,
        "filtering": filtering_block(),
        "runtime": runtime_block(installed_version(),
                                  bool(engine.nlp_engine.get_supported_entities())),
        "unsupported": [],
    }
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
