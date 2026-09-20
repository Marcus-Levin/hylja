# Example: use without reveal

The external agent sees:

```text
send_email(recipient="person://7b4f...", body="Please review the report")
```

The trusted tool gateway receives the token plus authenticated subject/project/purpose. Hylja authorizes `USE`, resolves the real email internally, and calls Gmail. The external model never receives the real address.

`DISPLAY` would be a separate authorization decision. `EXPORT` would be more restricted still.
