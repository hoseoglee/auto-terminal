# MCP Server Submission Info

Use the information below to register **Auto Terminal** on MCP directories.

## 1. General Info

*   **Name**: Auto Terminal
*   **Repository**: [https://github.com/hoseoglee/auto-terminal](https://github.com/hoseoglee/auto-terminal)
*   **Description**: A powerful process manager and terminal automation tool that doubles as an MCP server. It allows AI agents to execute shell commands, manage background processes, and monitor logs in real-time.
*   **Tags**: `mcp`, `python`, `terminal`, `automation`, `process-manager`, `tool`
*   **License**: MIT

## 2. Platforms & Submission Links

### [Awesome MCP Servers](https://mcpservers.org)
*   **Submit URL**: [https://mcpservers.org/submit](https://mcpservers.org/submit)
*   **Method**: Web Form
*   **Instructions**: Copy the fields from "General Info" above.

### [mcp.so](https://mcp.so)
*   **Submit Method**: GitHub Issue on [mcp-marketplace](https://github.com/mcp-marketplace/mcp-marketplace/issues)
*   **Issue Template**:
    ```markdown
    ### Server Name
    Auto Terminal

    ### Description
    A powerful process manager and terminal automation tool that doubles as an MCP server.

    ### Features
    - GUI & MCP Hybrid modes
    - Process start/stop/restart management
    - Real-time log monitoring
    - Arbitrary terminal command execution

    ### Connection Info
    - Transport: SSE (Server-Sent Events) or Stdio
    - URL: http://localhost:8000/sse

    ### Repository URL
    https://github.com/hoseoglee/auto-terminal
    ```

### [Glama (Pulse)](https://glama.ai)
*   **Method**: Check their [Discord Community](https://discord.com/invite/glama) for show-and-tell channels or look for a submission form on their dashboard if available.

## 3. Configuration JSON (for Users)

```json
{
  "mcpServers": {
    "auto-terminal": {
      "command": "python",
      "args": ["gui_launcher.py", "--mcp"]
    }
  }
}
```
