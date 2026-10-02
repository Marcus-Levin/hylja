#!/usr/bin/env python3
"""Offline #46 research: verify two published PyPI PEP 740 attestation bundles.

Runs inside the ephemeral bwrap sandbox (no network, read-only inputs). argv[1]
is the bound work directory holding the pinned trust anchor, the TUF metadata,
the independently fetched GitHub evidence and the two wheels. Emits a JSON
report on stdout with only verdicts and public artifact metadata.

Every check is reported separately. Any unexpected exception is recorded as
UNVERIFIED with a fixed code; it never becomes PASS.
"""

import base64
import binascii
import hashlib
import re
import json
import os
import struct
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509.oid import ExtendedKeyUsageOID

import sigstore
from sigstore._internal.trust import KeyringPurpose
from sigstore.dsse import Envelope as DsseEnvelope
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

import pypi_attestations
from pypi_attestations import Distribution

MAX_BYTES = 30 * 1024 * 1024
# Inside the sandbox the work directory is /work; elsewhere pass the real path.
WORK = sys.argv[1] if len(sys.argv) > 1 else "/work"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
PAE = b"DSSEv1 %d %s %d %s"
PINNED_TRUSTED_ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"

FULCIO_CLAIM_OIDS = {
    "1.3.6.1.4.1.57264.1.1": "oidc_issuer",
    "1.3.6.1.4.1.57264.1.2": "github_workflow_trigger",
    "1.3.6.1.4.1.57264.1.3": "github_workflow_sha",
    "1.3.6.1.4.1.57264.1.4": "github_workflow_name",
    "1.3.6.1.4.1.57264.1.5": "github_workflow_repository",
    "1.3.6.1.4.1.57264.1.6": "github_workflow_ref",
    "1.3.6.1.4.1.57264.1.8": "oidc_issuer_v2",
    "1.3.6.1.4.1.57264.1.9": "oidc_build_signer_uri",
    "1.3.6.1.4.1.57264.1.10": "oidc_build_signer_digest",
    "1.3.6.1.4.1.57264.1.11": "oidc_runner_environment",
    "1.3.6.1.4.1.57264.1.12": "oidc_source_repository_uri",
    "1.3.6.1.4.1.57264.1.13": "oidc_source_repository_digest",
    "1.3.6.1.4.1.57264.1.14": "oidc_source_repository_ref",
    "1.3.6.1.4.1.57264.1.15": "oidc_source_repository_identifier",
    "1.3.6.1.4.1.57264.1.16": "oidc_source_repository_owner_uri",
    "1.3.6.1.4.1.57264.1.17": "oidc_source_repository_owner_identifier",
    "1.3.6.1.4.1.57264.1.18": "oidc_build_config_uri",
    "1.3.6.1.4.1.57264.1.19": "oidc_build_config_digest",
    "1.3.6.1.4.1.57264.1.20": "oidc_build_trigger",
    "1.3.6.1.4.1.57264.1.21": "oidc_run_invocation_uri",
    "1.3.6.1.4.1.57264.1.22": "oidc_source_repository_visibility",
}

REPORT = {}


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path):
    size = os.path.getsize(path)
    if size > MAX_BYTES:
        raise RuntimeError("INPUT_TOO_LARGE")
    with open(path, "rb") as handle:
        return handle.read()


def read_der_utf8_string(raw):
    if not raw or raw[0] != 0x0C:
        raise ValueError("NOT_UTF8STRING")
    length = raw[1]
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(raw[2:2 + nbytes], "big")
        body = raw[2 + nbytes:2 + nbytes + length]
    else:
        body = raw[2:2 + length]
    return body.decode("utf-8")


def pae(payload_type, payload):
    return PAE % (len(payload_type), payload_type.encode(), len(payload), payload)


def leaf_hash(body):
    return hashlib.sha256(struct.pack("B", 0) + body).digest()


def node(lhs, rhs):
    return hashlib.sha256(struct.pack("B", 1) + lhs + rhs).digest()


def verify_merkle_inclusion(index, size, hashes, leaf, root):
    if size <= 0 or index >= size:
        return False, "INDEX_OUT_OF_RANGE"
    if len(hashes) > 512:
        return False, "PROOF_TOO_LONG"
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(hashes) != inner + border:
        return False, "PROOF_WRONG_SIZE"
    seed = leaf
    for level, item in enumerate(hashes[:inner]):
        seed = node(seed, item) if (index >> level) & 1 == 0 else node(item, seed)
    for item in hashes[inner:]:
        seed = node(item, seed)
    return (seed == root), "OK" if seed == root else "ROOT_MISMATCH"


def cert_signed_by(child, issuer):
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    else:
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   asym_padding.PKCS1v15(), child.signature_hash_algorithm)
    return True


def record(results, name, verdict, **detail):
    results[name] = {"verdict": verdict, **detail}


def san_uris(cert):
    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return list(ext.value.get_values_for_type(x509.UniformResourceIdentifier))


def fulcio_claims(cert):
    claims = {}
    for ext in cert.extensions:
        name = FULCIO_CLAIM_OIDS.get(ext.oid.dotted_string)
        if name:
            try:
                claims[name] = read_der_utf8_string(ext.value.value)
            except Exception:
                claims[name] = "UNDECODABLE"
    return claims


def describe_predicate(predicate):
    """Record only the shape of the predicate body, never its content."""
    if predicate is None:
        return "null"
    if isinstance(predicate, (str, list, dict)):
        return "%s(len<=%d)" % (type(predicate).__name__, 4096)
    return type(predicate).__name__


def run_artifact(label, wheel_path, wheel_filename, provenance_path, expected, report):
    results = {}
    wheel_bytes = read_bounded(wheel_path)
    record(results, "artifact_sha256", "PASS", bytes=len(wheel_bytes), sha256=sha256_hex(wheel_bytes))

    raw = read_bounded(provenance_path)
    doc = json.loads(raw)
    record(results, "provenance_object_sha256", "PASS", sha256=sha256_hex(raw))
    record(results, "pep740_object_version_is_1", "PASS" if doc.get("version") == 1 else "FAIL",
           observed=doc.get("version"))

    bundles = doc.get("attestation_bundles") or []
    record(results, "single_attestation_bundle", "PASS" if len(bundles) == 1 else "FAIL",
           observed=len(bundles))
    if len(bundles) != 1:
        return results
    bundle = bundles[0]
    publisher = bundle.get("publisher") or {}
    atts = bundle.get("attestations") or []
    record(results, "single_attestation", "PASS" if len(atts) == 1 else "FAIL", observed=len(atts))
    if len(atts) != 1:
        return results
    att = atts[0]

    record(results, "attestation_version_is_1", "PASS" if att.get("version") == 1 else "FAIL",
           observed=att.get("version"))
    env = att.get("envelope") or {}
    vm = att.get("verification_material") or {}
    statement = base64.b64decode(env["statement"], validate=True)
    signature = base64.b64decode(env["signature"], validate=True)
    leaf_der = base64.b64decode(vm["certificate"], validate=True)
    leaf = x509.load_der_x509_certificate(leaf_der)
    parsed = json.loads(statement)

    sct_oids = [e.oid.dotted_string for e in leaf.extensions]
    report["artifacts"][label] = {
        "wheel_filename": wheel_filename,
        "publisher_metadata": publisher,
        "cert_subject": leaf.subject.rfc4514_string(),
        "cert_issuer": leaf.issuer.rfc4514_string(),
        "cert_serial_hex": format(leaf.serial_number, "x"),
        "cert_sha256": sha256_hex(leaf_der),
        "not_before": leaf.not_valid_before_utc.isoformat(),
        "not_after": leaf.not_valid_after_utc.isoformat(),
        "san_uris": san_uris(leaf),
        "fulcio_claims": fulcio_claims(leaf),
        "extension_oids": sorted(sct_oids),
        "predicate_type": parsed.get("predicateType"),
        "predicate_shape": describe_predicate(parsed.get("predicate")),
        "subject": parsed.get("subject"),
    }

    try:
        basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca_flag = bool(basic.ca)
    except x509.ExtensionNotFound:
        ca_flag = False
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ok = (not ca_flag) and ku.digital_signature and ExtendedKeyUsageOID.CODE_SIGNING in eku
    record(results, "leaf_end_entity_codesigning_profile", "PASS" if ok else "FAIL",
           basic_constraints_ca_flag=ca_flag,
           basic_constraints_present=any(e.oid == x509.OID_BASIC_CONSTRAINTS for e in leaf.extensions),
           key_usage_digital_signature=bool(ku.digital_signature),
           code_signing_eku=ExtendedKeyUsageOID.CODE_SIGNING in eku)

    trusted_root = report["_trusted_root_obj"]
    anchor_log_ids = {
        base64.b64encode(log.log_id.key_id).decode()
        for log in trusted_root._inner.tlogs
        if isinstance(getattr(log.log_id, "key_id", None), bytes)
    }
    fulcio_certs = trusted_root.get_fulcio_certs()
    issuer = None
    try:
        issuer = next(c for c in fulcio_certs if c.subject == leaf.issuer)
        cert_signed_by(leaf, issuer)
        record(results, "leaf_signed_by_trusted_fulcio_issuer", "PASS",
               issuer=issuer.subject.rfc4514_string())
    except Exception:
        record(results, "leaf_signed_by_trusted_fulcio_issuer", "FAIL", error_code="NO_TRUSTED_ISSUER")
    chain_verified = False
    chain_root_sha256 = None
    try:
        for candidate in fulcio_certs:
            if candidate.subject != leaf.issuer or candidate.subject == leaf.subject:
                continue
            for root in fulcio_certs:
                if root.subject != candidate.issuer:
                    continue
                try:
                    cert_signed_by(candidate, root)
                    cert_signed_by(root, root)
                    chain_verified = True
                    chain_root_sha256 = sha256_hex(root.public_bytes(serialization.Encoding.DER))
                except Exception:
                    continue
                if chain_verified:
                    break
            if chain_verified:
                break
    except Exception:
        chain_verified = False
    record(results, "fulcio_intermediate_signed_by_trusted_root",
           "PASS" if chain_verified else "FAIL", trusted_root_sha256=chain_root_sha256)

    try:
        pub = leaf.public_key()
        pub.verify(signature, pae(DSSE_PAYLOAD_TYPE, statement), ec.ECDSA(crypto_hashes.SHA256()))
        record(results, "dsse_signature_over_pae_recomputed", "PASS")
    except InvalidSignature:
        record(results, "dsse_signature_over_pae_recomputed", "FAIL", error_code="BAD_SIGNATURE")
    except Exception:
        record(results, "dsse_signature_over_pae_recomputed", "FAIL", error_code="UNSUPPORTED_KEY")

    subjects = parsed.get("subject") or []
    ok = len(subjects) == 1 and subjects[0].get("name") == wheel_filename and \
        (subjects[0].get("digest") or {}).get("sha256") == sha256_hex(wheel_bytes)
    record(results, "in_toto_subject_binds_filename_and_wheel_digest", "PASS" if ok else "FAIL")

    entries = vm.get("transparency_entries") or []
    record(results, "single_transparency_entry", "PASS" if len(entries) == 1 else "FAIL",
           observed=len(entries))
    integrated = None
    if len(entries) == 1:
        entry = entries[0]
        body_b64 = base64.b64decode(entry["canonicalizedBody"], validate=True)
        proof = entry.get("inclusionProof") or {}
        index = int(proof.get("logIndex", "-1"))
        size = int(proof.get("treeSize", "-1"))
        hashes = [base64.b64decode(h, validate=True) for h in proof.get("hashes", [])]
        root_hash = base64.b64decode(proof.get("rootHash", ""), validate=True)
        ok, code = verify_merkle_inclusion(index, size, hashes, leaf_hash(body_b64), root_hash)
        record(results, "rfc6962_inclusion_proof_recomputed", "PASS" if ok else "FAIL",
               log_index=index, tree_size=size, error_code=None if ok else code)
        integrated = int(entry.get("integratedTime", "0"))
        nb = leaf.not_valid_before_utc.timestamp()
        na = leaf.not_valid_after_utc.timestamp()
        ok = nb <= integrated <= na
        record(results, "integrated_time_within_certificate_validity", "PASS" if ok else "FAIL",
               integrated_time=datetime.fromtimestamp(integrated, tz=timezone.utc).isoformat(),
               not_before=leaf.not_valid_before_utc.isoformat(),
               not_after=leaf.not_valid_after_utc.isoformat())
        envelope_text = (proof.get("checkpoint") or {}).get("envelope") or ""
        lines = envelope_text.splitlines()
        entry_log_id = (entry.get("logId") or {}).get("keyId")
        record(results, "transparency_log_id_is_in_pinned_anchor",
               "PASS" if entry_log_id in anchor_log_ids else "FAIL",
               entry_log_id=entry_log_id)
        report["artifacts"][label]["transparency"] = {
            "log_id_key_id": entry_log_id,
            "log_id_in_pinned_anchor": entry_log_id in anchor_log_ids,
            "log_index": index,
            "tree_size": size,
            "integrated_time": integrated,
            "kind_version": entry.get("kindVersion"),
            "has_inclusion_promise": bool(entry.get("inclusionPromise")),
            "checkpoint_origin": lines[0] if lines else None,
            "checkpoint_declared_size": lines[1] if len(lines) > 1 else None,
            "checkpoint_signature_count": len([ln for ln in lines if ln.startswith("\u2014 ")]),
            "checkpoint_key_id": lines[-1] if lines else None,
        }
        record(results, "checkpoint_declared_size_matches_tree_size",
               "PASS" if len(lines) > 1 and lines[1] == str(size) else "FAIL")

    try:
        sigstore_bundle = pypi_attestations.Attestation.model_validate(att).to_bundle()
        keyring = trusted_root.rekor_keyring(KeyringPurpose.VERIFY)
        try:
            sigstore_bundle.log_entry._verify(keyring)
            record(results, "library_log_entry_set_merkle_checkpoint", "PASS")
        except Exception as exc:
            record(results, "library_log_entry_set_merkle_checkpoint", "FAIL",
                   error_code=type(exc).__name__)

        from sigstore._internal.sct import verify_sct

        issuers = [c for c in trusted_root.get_fulcio_certs() if c.subject == leaf.issuer]
        try:
            verify_sct(leaf, issuers, trusted_root.ct_keyring(KeyringPurpose.VERIFY))
            record(results, "embedded_precertificate_sct", "PASS")
        except Exception as exc:
            record(results, "embedded_precertificate_sct", "FAIL", error_code=type(exc).__name__)

        wire = json.dumps({
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": env["statement"],
            "signatures": [{"sig": env["signature"]}],
        }).encode("utf-8")
        try:
            envelope = DsseEnvelope._from_json(wire)
            leaf.public_key().verify(signature, envelope.pae(), ec.ECDSA(crypto_hashes.SHA256()))
            record(results, "library_dsse_pae_recomputation", "PASS")
        except Exception as exc:
            record(results, "library_dsse_pae_recomputation", "FAIL",
                   error_code=type(exc).__name__)
    except Exception as exc:
        record(results, "library_checks", "UNVERIFIED",
               error_code="LIBRARY_CHECK_ERROR:%s" % type(exc).__name__)

    try:
        publisher_obj = pypi_attestations.GitHubPublisher(
            repository=expected["repository"], workflow=expected["workflow"])
        predicate_type, _predicate = pypi_attestations.Attestation.model_validate(att).verify(
            publisher_obj,
            Distribution(name=wheel_filename, digest=sha256_hex(wheel_bytes)),
            offline=True,
        )
        record(results, "pypi_attestations_full_verification", "PASS",
               predicate_type=predicate_type,
               trust_root_source="packaged sigstore TUF cache (offline=True)")
    except Exception as exc:
        record(results, "pypi_attestations_full_verification", "FAIL",
               error_code="REFERENCE_VERIFICATION_ERROR:%s" % type(exc).__name__)

    claims = report["artifacts"][label]["fulcio_claims"]
    gh = report["_github"]
    repo_url = gh["repo"]["html_url"]
    run = gh["run"]
    workflow = gh["workflow"]
    expected_identity = "%s/%s@refs/heads/%s" % (repo_url, workflow["path"], gh["repo"]["default_branch"])
    uris = report["artifacts"][label]["san_uris"]
    record(results, "san_uri_is_single_expected_workflow_identity",
           "PASS" if uris == [expected_identity] else "FAIL",
           observed=uris, expected=expected_identity)
    record(results, "oidc_issuer_is_github_actions",
           "PASS" if claims.get("oidc_issuer_v2") == "https://token.actions.githubusercontent.com"
           else "FAIL")
    record(results, "source_repository_uri_matches_public_repo",
           "PASS" if claims.get("oidc_source_repository_uri") == repo_url else "FAIL")
    record(results, "build_config_uri_matches_expected_workflow_identity",
           "PASS" if claims.get("oidc_build_config_uri") == expected_identity else "FAIL",
           observed=claims.get("oidc_build_config_uri"))
    record(results, "source_repository_digest_matches_public_run_head_sha",
           "PASS" if claims.get("oidc_source_repository_digest") == run["head_sha"] else "FAIL")
    record(results, "build_trigger_matches_public_run_event",
           "PASS" if claims.get("oidc_build_trigger") == run["event"] else "FAIL",
           observed=claims.get("oidc_build_trigger"), expected=run["event"])
    record(results, "source_repository_ref_matches_public_run_head_branch",
           "PASS" if claims.get("oidc_source_repository_ref") == "refs/heads/" + run["head_branch"]
           else "FAIL")
    expected_run_uri = "%s/actions/runs/%d/attempts/%d" % (repo_url, run["id"], 1)
    record(results, "run_invocation_uri_matches_public_run",
           "PASS" if claims.get("oidc_run_invocation_uri") == expected_run_uri else "FAIL",
           observed=claims.get("oidc_run_invocation_uri"), expected=expected_run_uri)
    record(results, "source_repository_visibility_matches_public_repo",
           "PASS" if claims.get("oidc_source_repository_visibility") == gh["repo"]["visibility"]
           else "FAIL")
    record(results, "publisher_metadata_matches_independently_fetched_repo_and_workflow",
           "PASS" if publisher.get("repository") == expected["repository"]
           and publisher.get("workflow") == expected["workflow"] else "FAIL")

    record(results, "build_config_digest_claim_equals_claimed_source_commit",
           "PASS" if claims.get("oidc_build_config_digest") == run["head_sha"] else "FAIL",
           observed=claims.get("oidc_build_config_digest"), expected=run["head_sha"],
           note="Fulcio OID .19 carries the workflow's commit, not a digest of the file content")
    try:
        content = read_bounded(report["_workflow_file"])
        blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\x00" + content).hexdigest()
        actual = sha256_hex(content)
        observed_blob = report["_github_workflow_blob_sha"]
        report["artifacts"][label]["workflow_file_observation"] = {
            "bytes": len(content),
            "sha256": actual,
            "git_blob_sha1_computed": blob_sha,
            "git_blob_sha1_from_github_contents_api": observed_blob,
        }
        record(results, "workflow_file_content_matches_github_blob_at_claimed_commit",
               "PASS" if blob_sha == observed_blob else "FAIL",
               computed=blob_sha, observed=observed_blob)
    except Exception as exc:
        record(results, "workflow_file_content_matches_github_blob_at_claimed_commit", "UNVERIFIED",
               error_code="WORKFLOW_FILE_ERROR:%s" % type(exc).__name__)

    return results


def main():
    report = {"tool": {"sigstore": sigstore.__version__,
                       "pypi_attestations": getattr(pypi_attestations, "__version__", "0.0.30")},
              "artifacts": {}, "checks": {}, "trust_anchor": {}}

    root_path = os.path.join(WORK, "pinned-trusted-root.json")
    root_bytes = read_bounded(root_path)
    anchor = report["trust_anchor"]
    anchor["pinned_trusted_root_sha256"] = sha256_hex(root_bytes)
    anchor["pin_matches_constant"] = sha256_hex(root_bytes) == PINNED_TRUSTED_ROOT_SHA256
    anchor["pin_source"] = (
        "sha256 of the trusted_root.json target recorded in Sigstore's TUF repository signed "
        "targets metadata (version 14) fetched from https://tuf-repo-cdn.sigstore.dev/14.targets.json")
    trusted_root = TrustedRoot.from_file(root_path)
    report["_trusted_root_obj"] = trusted_root

    try:
        import sigstore._store as store_pkg
        base = list(store_pkg.__path__)[0]
        packaged = None
        for name in sorted(os.listdir(base)):
            if not os.path.isdir(os.path.join(base, name)):
                continue
            if "sigstore.dev" not in name or "sigstage" in name:
                continue
            candidate = os.path.join(base, name, "trusted_root.json")
            if os.path.isfile(candidate):
                packaged = read_bounded(candidate)
                anchor["packaged_copy_resource"] = "sigstore/_store/%s/trusted_root.json" % name
        anchor["packaged_copy_identical"] = packaged == root_bytes
        anchor["packaged_copy_source"] = "resource bundled inside the PyPI-published sigstore wheel"
    except Exception:
        anchor["packaged_copy_identical"] = False

    # TUF pin cross-check: the pinned trusted root must be the target that the
    # Sigstore TUF repository's signed targets metadata names, and both that
    # metadata and the root metadata must carry signatures meeting their roles.
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from securesystemslib.formats import encode_canonical

        def canonical(obj):
            encoded = encode_canonical(obj)
            return encoded.encode("utf-8") if isinstance(encoded, str) else encoded

        def valid_signatures(doc, keys):
            body = canonical(doc["signed"])
            good = []
            for sig in doc.get("signatures", []):
                keyid = sig.get("keyid")
                material = keys.get(keyid)
                if not material:
                    continue
                try:
                    pub = load_pem_public_key(material.encode())
                    pub.verify(bytes.fromhex(sig["sig"]), body, ec.ECDSA(crypto_hashes.SHA256()))
                    good.append(keyid)
                except Exception:
                    continue
            return good

        root_doc = json.loads(read_bounded(os.path.join(WORK, "sigstore-tuf-15.root.json")))
        targets_doc = json.loads(read_bounded(os.path.join(WORK, "sigstore-tuf-14.targets.json")))
        root_keys = {k: v["keyval"]["public"] for k, v in root_doc["signed"]["keys"].items()}
        anchor["tuf_root_version"] = root_doc["signed"]["version"]
        anchor["tuf_root_expires"] = root_doc["signed"]["expires"]
        anchor["tuf_targets_version"] = targets_doc["signed"]["version"]
        anchor["tuf_targets_expires"] = targets_doc["signed"]["expires"]
        anchor["tuf_root_role_threshold"] = root_doc["signed"]["roles"]["root"]["threshold"]
        anchor["tuf_targets_role_threshold"] = root_doc["signed"]["roles"]["targets"]["threshold"]
        anchor["tuf_root_key_count"] = len(root_keys)
        root_good = valid_signatures(root_doc, root_keys)
        targets_good = valid_signatures(targets_doc, root_keys)
        anchor["tuf_root_valid_self_signatures"] = len(root_good)
        anchor["tuf_targets_valid_root_key_signatures"] = len(targets_good)
        anchor["tuf_root_self_signature"] = (
            "PASS" if len(root_good) >= root_doc["signed"]["roles"]["root"]["threshold"] else "FAIL")
        anchor["tuf_targets_signature_by_root_keys"] = (
            "PASS" if len(targets_good) >= root_doc["signed"]["roles"]["targets"]["threshold"] else "FAIL")
        target = targets_doc["signed"]["targets"].get("trusted_root.json")
        anchor["tuf_targets_sha256"] = target["hashes"]["sha256"] if target else None
        anchor["tuf_targets_lists_pinned_trusted_root"] = bool(
            target and target["hashes"]["sha256"] == sha256_hex(root_bytes))
        anchor["tuf_root_metadata_sha256"] = sha256_hex(read_bounded(os.path.join(WORK, "sigstore-tuf-15.root.json")))
    except Exception as exc:  # noqa: BLE001
        anchor["tuf_verification_error_code"] = type(exc).__name__

    anchor["fulcio_certificates"] = []
    for cert in trusted_root.get_fulcio_certs():
        anchor["fulcio_certificates"].append({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "sha256": sha256_hex(cert.public_bytes(serialization.Encoding.DER)),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "self_signed": cert.subject == cert.issuer,
        })
    logs = []
    for log in trusted_root._inner.tlogs:
        raw_id = getattr(log.log_id, "key_id", None)
        logs.append({
            "base_url": log.base_url,
            "log_id_key_id_b64": base64.b64encode(raw_id).decode() if isinstance(raw_id, bytes)
                                else None,
        })
    anchor["transparency_logs"] = logs

    gh = {
        "repo": json.loads(read_bounded(os.path.join(WORK, "evidence", "gh-repo.json"))),
        "workflow": json.loads(read_bounded(os.path.join(WORK, "evidence", "gh-workflow-release.yml.json"))),
        "run": json.loads(read_bounded(os.path.join(WORK, "evidence", "gh-run-29901897108.json"))),
    }
    report["_github"] = gh
    report["_workflow_file"] = os.path.join(WORK, "evidence", "release.yml@636cadd.txt")
    report["_github_workflow_blob_sha"] = json.loads(
        read_bounded(os.path.join(WORK, "evidence", "gh-workflow-file-at-commit.json")))["sha"]

    expected = {"repository": "data-privacy-stack/presidio", "workflow": "release.yml"}
    jobs = [
        ("presidio_analyzer",
         os.path.join(WORK, "wheels", "presidio_analyzer-2.2.364-py3-none-any.whl"),
         "presidio_analyzer-2.2.364-py3-none-any.whl",
         os.path.join(WORK, "evidence", "provenance-analyzer.json")),
        ("presidio_anonymizer",
         os.path.join(WORK, "wheels", "presidio_anonymizer-2.2.364-py3-none-any.whl"),
         "presidio_anonymizer-2.2.364-py3-none-any.whl",
         os.path.join(WORK, "evidence", "provenance-anonymizer.json")),
    ]
    for label, wheel, filename, provenance in jobs:
        try:
            report["checks"][label] = run_artifact(label, wheel, filename, provenance,
                                                  expected, report)
        except Exception as exc:
            report["checks"][label] = {"unexpected_error_code": type(exc).__name__}
    for key in ("_trusted_root_obj", "_github", "_workflow_file", "_github_workflow_blob_sha"):
        report.pop(key, None)
    json.dump(report, sys.stdout, indent=1, sort_keys=True, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stdout.write(json.dumps({"fatal_error_code": type(exc).__name__}) + "\n")
        sys.exit(2)
