# Example: MCP result protection

An MCP server returns a diagnostic object containing internal hostnames, file paths, and usernames. Before that result becomes model context, the MCP adapter emits `mcp.result`; Hylja classifies and transforms the result, preserving JSON structure. The external model receives synthetic infrastructure values. A later authorized local MCP/tool action may USE real values without revealing them to the model.
