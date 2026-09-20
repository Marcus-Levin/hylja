# Slice 3: OpenAI-compatible gateway proof

Status: draft.

## Goal

Expose one local OpenAI-compatible model gateway backed by the same interaction, policy, vault, and evaluation contracts.

## Required behavior

- request and response interception;
- streaming holdback policy by sensitivity class;
- destination profiles;
- tool-call arguments/results represented as interactions where the protocol exposes them;
- policy denial stops release;
- egress sentinel immediately precedes external send;
- audit excludes raw protected payloads;
- limitations for hosted/provider-side tools are explicit.
