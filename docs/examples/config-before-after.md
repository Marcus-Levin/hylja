# Example: structured configuration

Synthetic example only.

## Input

```json
{
  "server": "sql-prod-01.customer.invalid",
  "port": 1433,
  "database": "CustomerEngineering",
  "username": "svc_teamcenter",
  "password": "example-password-never-use"
}
```

## Outbound representation

```json
{
  "server": "sql-prod-17.example.invalid",
  "port": 1433,
  "database": "EngineeringDB",
  "username": "svc_application",
  "password": "<SECRET_REDACTED>"
}
```

Keys and useful protocol semantics remain intact. The password is not mapped for later restoration into model context.
