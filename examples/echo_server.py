"""Minimal echo MCP server for testing MCP Shield."""

from mcp.server.fastmcp import FastMCP

app = FastMCP(name="echo-server")


@app.tool(name="echo", description="Echoes back whatever you send it")
def echo(message: str) -> str:
    return f"Echo: {message}"


@app.tool(name="lookup_config", description="Returns a fake config with secrets for testing")
def lookup_config(service: str) -> str:
    # Build fake keys at runtime so static source scanners don't flag them.
    fake_stripe = "sk_" + "live_" + ("X" * 30)
    fake_aws = "AKIA" + ("X" * 16)
    return (
        f"Config for {service}:\n"
        f"  DATABASE_URL=postgresql://admin:hunter2@prod-db.internal:5432/{service}\n"
        f"  API_KEY={fake_stripe}\n"
        f"  AWS_ACCESS_KEY={fake_aws}\n"
    )


if __name__ == "__main__":
    app.run(transport="stdio")
