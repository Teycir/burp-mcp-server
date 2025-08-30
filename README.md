# Burp Suite MCP Server

A Model Context Protocol (MCP) server for integrating Burp Suite Professional with AI assistants.

## Features

- **Vulnerability Scanning**: Start and monitor security scans on target URLs
- **Issue Management**: Retrieve security issues and vulnerability definitions
- **HTTP Requests**: Send custom HTTP requests through Burp Suite
- **Connection Testing**: Verify Burp Suite API connectivity
- **No Authentication Required**: Configured to work without API keys

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd burp-mcp-server
```

2. Install dependencies:
```bash
npm install
```

## Configuration

### Burp Suite Setup

1. Open Burp Suite Professional
2. Go to **Settings → Suite → REST API**
3. Enable "REST API"
4. Set service URL to `http://127.0.0.1:1337`
5. Disable "API key required" (or leave API key empty)

### MCP Client Configuration

Add to your MCP client configuration:

```json
{
  "burp": {
    "command": "node",
    "args": ["path/to/burp-mcp-server/index.js"],
    "env": {
      "BURP_URL": "http://127.0.0.1:1337",
      "BURP_API_KEY": ""
    }
  }
}
```

## Available Tools

- `burp_scan_url` - Start a security scan on a target URL
- `burp_get_scan_status` - Get the status of a running scan
- `burp_get_issues` - Retrieve security issues found by Burp
- `burp_send_request` - Send HTTP requests through Burp Suite
- `burp_test_connection` - Test connectivity to Burp Suite API
- `burp_repeater_send` - Send request via Repeater
- `burp_decoder_encode` - Encode data (base64, URL)
- `burp_decoder_decode` - Decode data (base64, URL)
- `burp_comparer_compare` - Compare two responses

## Usage Examples

### Start a Scan
```javascript
burp_scan_url({
  "url": "https://example.com",
  "scan_type": "crawl_only"
})
```

### Check Scan Status
```javascript
burp_get_scan_status({
  "task_id": "your-task-id"
})
```

### Get Security Issues
```javascript
burp_get_issues({
  "task_id": "your-task-id"  // Optional
})
```

## Troubleshooting

1. **Connection Issues**: Ensure Burp Suite is running and REST API is enabled
2. **Port Conflicts**: Verify port 1337 is available and matches Burp Suite configuration
3. **Authentication Errors**: Confirm API key requirement is disabled in Burp Suite

## License

MIT