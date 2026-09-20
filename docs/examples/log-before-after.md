# Example: log cloaking

Synthetic example only.

## Input

```text
2026-09-19T08:14:33Z INFO user=alex.svensson host=tc-prod-17.customer.invalid ip=192.0.2.44 port=1433 project=Project-Freya token=secret-example-token
```

## Policy outcome

- user -> synthetic identity
- host/IP -> synthetic/tokenized infrastructure identity
- port 1433 -> keep because protocol semantics are useful
- project -> synthetic project identity
- token -> block/redact; never reversible for the model

## Outbound representation

```text
2026-09-19T08:14:33Z INFO user=erik.lund host=tc-prod-42.example.invalid ip=198.51.100.42 port=1433 project=Project-Aurora token=<SECRET_REDACTED>
```
