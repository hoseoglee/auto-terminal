# Auto Terminal MCP Server

This directory contains an MCP (Model Context Protocol) server implementation for the Auto Terminal. This allows AI agents (like Claude or Cursor) to control your scripts and processes directly.

## Running the Server

**Automatic**: Launching the GUI Application (`gui_launcher.py`) will **automatically** start the MCP server in the background using SSE transport (default port 8000).

**Manual**: You can run the server manually if needed:

```bash
# Run with Stdio (Standard Input/Output) - for direct connecting
python mcp_server.py

# Run with SSE (Server-Sent Events) - for HTTP connecting
python mcp_server.py --sse
```

## connecting to the Server

Since the server is running via SSE when launched by the GUI, you should configure your agent (Cursor/Claude) to connect to the SSE endpoint.

### Cursor / Claude Desktop Configuration

Add this to your MCP settings:

```json
{
  "mcpServers": {
    "auto-terminal": {
      "url": "http://localhost:8000/sse",
      "transport": "sse"
    }
  }
}
```

(Note: If you prefer Stdio, you must run it manually or configure the client to run the command `python /path/to/autorun/mcp_server.py`, but this will be a separate instance from the GUI's background server).

## Features

The server exposes the following tools to the AI agent:

- **list_programs**: See all configured programs and their status.
- **start_program(name)**: Start a program.
- **run_terminal_command(command, name, cwd)**: Run any shell command.
- **stop_program(name)**: Stop a program.
- **restart_program(name)**: Restart a program.
- **get_program_logs(name)**: Read the recent stdout/stderr output.
- **send_program_input(name, input_text)**: Send text to the program's stdin.
- **add_program_config / remove_program_config**: Manage the `config.json`.

## Notes
- The MCP server launched by the GUI runs on `http://localhost:8000/sse`.
- If port 8000 is busy, it might fail or pick another port (check logs or console output).
