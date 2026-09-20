# Foundation research record - 2026-09-19

Status: source record, not authority.

This document captures the main themes that motivated the initial Hylja foundation. Accepted outcomes are reflected in the numbered decisions and architecture/security documents.

## Problem

Enterprise AI/agent workflows can expose more than PII: logs, configuration, scripts, environment variables, URLs/ports, usernames, passwords, server names, IPs, cloud resource IDs, file paths, customer/project names, engineering tags, tool results, MCP resources, memory, and agent handoffs.

Traditional regex-only redaction loses utility and misses semantic confidentiality. Pure hosted-AI detection creates a privacy paradox because raw protected context may leave the trust boundary before it is classified.

## Direction

Use a layered detector ladder: bounded normalization -> structured parsers -> deterministic detectors -> local candidate generation -> semantic judgment for ambiguity -> deterministic policy. Keep reversible mappings in a hardened brokered vault and use realistic synthetic identities where task utility benefits.

Protect all supported source-to-sink flows, not only prompts. Track trust separately from sensitivity so Hylja also resists prompt injection, tool poisoning, memory poisoning, and untrusted influence.

Build continuous evaluation from the first executable slice. Production misses become sanitized regression cases. Stable semantic patterns migrate into deterministic functions over time.
