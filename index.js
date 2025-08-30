#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';

class BurpMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'burp-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.burpUrl = process.env.BURP_URL || 'http://127.0.0.1:1337';
    this.burpUrlHttps = this.burpUrl.replace('http://', 'https://');
    console.log('Burp URL:', this.burpUrl);
    console.log('Running without API authentication');
    
    this.setupToolHandlers();
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'burp_scan_url',
          description: 'Start a scan on a target URL',
          inputSchema: {
            type: 'object',
            properties: {
              url: { type: 'string', description: 'Target URL to scan' },
              scan_type: { type: 'string', enum: ['crawl_and_audit', 'crawl_only', 'audit_only'], default: 'crawl_and_audit' }
            },
            required: ['url']
          }
        },
        {
          name: 'burp_get_scan_status',
          description: 'Get status of a scan task',
          inputSchema: {
            type: 'object',
            properties: {
              task_id: { type: 'string', description: 'Scan task ID' }
            },
            required: ['task_id']
          }
        },
        {
          name: 'burp_get_issues',
          description: 'Get security issues found by Burp',
          inputSchema: {
            type: 'object',
            properties: {
              task_id: { type: 'string', description: 'Scan task ID (optional)' }
            }
          }
        },
        {
          name: 'burp_send_request',
          description: 'Send HTTP request through Burp proxy',
          inputSchema: {
            type: 'object',
            properties: {
              url: { type: 'string', description: 'Target URL' },
              method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE'], default: 'GET' },
              headers: { type: 'object', description: 'HTTP headers' },
              body: { type: 'string', description: 'Request body' }
            },
            required: ['url']
          }
        },
        {
          name: 'burp_test_connection',
          description: 'Test connection to Burp Suite API',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'burp_repeater_send',
          description: 'Send request via Repeater',
          inputSchema: {
            type: 'object',
            properties: {
              url: { type: 'string', description: 'Target URL' },
              method: { type: 'string', default: 'GET' },
              headers: { type: 'object' },
              body: { type: 'string' }
            },
            required: ['url']
          }
        },
        {
          name: 'burp_decoder_encode',
          description: 'Encode data',
          inputSchema: {
            type: 'object',
            properties: {
              data: { type: 'string', description: 'Data to encode' },
              encoding: { type: 'string', description: 'Encoding type' }
            },
            required: ['data', 'encoding']
          }
        },
        {
          name: 'burp_decoder_decode',
          description: 'Decode data',
          inputSchema: {
            type: 'object',
            properties: {
              data: { type: 'string', description: 'Data to decode' },
              encoding: { type: 'string', description: 'Encoding type' }
            },
            required: ['data', 'encoding']
          }
        },
        {
          name: 'burp_comparer_compare',
          description: 'Compare two responses',
          inputSchema: {
            type: 'object',
            properties: {
              data1: { type: 'string', description: 'First data' },
              data2: { type: 'string', description: 'Second data' }
            },
            required: ['data1', 'data2']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'burp_scan_url':
            return await this.scanUrl(args.url, args.scan_type || 'crawl_and_audit');
          case 'burp_get_scan_status':
            return await this.getScanStatus(args.task_id);
          case 'burp_get_issues':
            return await this.getIssues(args.task_id);
          case 'burp_send_request':
            return await this.sendRequest(args.url, args.method, args.headers, args.body);
          case 'burp_test_connection':
            return await this.testConnection();
          case 'burp_repeater_send':
            return await this.repeaterSend(args.url, args.method, args.headers, args.body);
          case 'burp_decoder_encode':
            return await this.decoderEncode(args.data, args.encoding);
          case 'burp_decoder_decode':
            return await this.decoderDecode(args.data, args.encoding);
          case 'burp_comparer_compare':
            return await this.comparerCompare(args.data1, args.data2);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        let errorMessage = error.message;
        if (error.response) {
          errorMessage += `\n${JSON.stringify(error.response.data, null, 2)}`;
        }
        return {
          content: [{ type: 'text', text: `Error: ${errorMessage}` }],
          isError: true
        };
      }
    });
  }

  async scanUrl(url, scanType) {
    if (!url || typeof url !== 'string') {
      return {
        content: [{
          type: 'text',
          text: 'Error: URL is required and must be a valid string'
        }]
      };
    }
    
    try {
      const response = await axios.post(`${this.burpUrl}/v0.1/scan`, {
        urls: [url]
      });

      const taskId = response.headers['location'] ? response.headers['location'].split('/').pop() : 'unknown';
      
      return {
        content: [{
          type: 'text',
          text: `✅ Scan started for ${url}\nTask ID: ${taskId}\nUse 'burp_get_scan_status' with task ID to check progress.`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Scan failed: ${error.response?.status || 'Network Error'} - ${error.message}`
        }]
      };
    }
  }

  async getScanStatus(taskId) {
    if (!taskId || taskId === 'unknown') {
      return {
        content: [{
          type: 'text',
          text: 'Task ID is required. Get it from burp_scan_url response.'
        }]
      };
    }
    
    try {
      const response = await axios.get(`${this.burpUrl}/v0.1/scan/${taskId}`);
      const status = response.data?.scan_status || 'unknown';
      const progress = response.data?.scan_metrics?.crawl_and_audit_progress || 0;
      
      return {
        content: [{
          type: 'text',
          text: `Scan Status: ${status}\nProgress: ${progress}%\nFull details: ${JSON.stringify(response.data, null, 2)}`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Status check failed: ${error.response?.status} - ${error.message}`
        }]
      };
    }
  }

  async getIssues(taskId) {
    try {
      const url = taskId ? 
        `${this.burpUrl}/v0.1/scan/${taskId}` : 
        `${this.burpUrl}/v0.1/knowledge_base/issue_definitions`;
      
      const response = await axios.get(url);
      const issues = taskId ? response.data?.issue_events || [] : response.data || [];
      
      if (!Array.isArray(issues) || issues.length === 0) {
        return {
          content: [{
            type: 'text',
            text: taskId ? `No issues found for scan ${taskId}` : 'No issue definitions available'
          }]
        };
      }

      const summary = issues.map(issue => 
        `${issue.name || issue.type_index || 'Unknown'}: ${issue.severity || 'N/A'} - ${issue.confidence || 'N/A'}`
      ).join('\n');

      return {
        content: [{
          type: 'text',
          text: `Found ${issues.length} ${taskId ? 'issues' : 'issue definitions'}:\n${summary}`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Get issues failed: ${error.response?.status} - ${error.message}`
        }]
      };
    }
  }

  async sendRequest(url, method = 'GET', headers = {}, body = '') {
    if (!url || typeof url !== 'string') {
      return {
        content: [{
          type: 'text',
          text: 'Error: URL is required and must be a valid string'
        }]
      };
    }
    
    try {
      const response = await axios.post(`${this.burpUrl}/v0.1/http-request`, {
        url, method: method || 'GET', headers: headers || {}, body: body || ''
      });
      
      return {
        content: [{
          type: 'text',
          text: `HTTP Request sent to ${url}\nResponse: ${JSON.stringify(response.data, null, 2)}`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Send request failed: ${error.response?.status || 'Network Error'} - ${error.message}`
        }]
      };
    }
  }

  async testConnection() {
    try {
      const response = await axios.get(`${this.burpUrl}/v0.1/knowledge_base/issue_definitions`, {
        timeout: 5000
      });
      
      return {
        content: [{
          type: 'text',
          text: `✅ Connection successful!\nBurp Suite REST API is accessible at ${this.burpUrl}\nStatus: ${response.status}`
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `❌ Connection failed: ${error.response?.status || 'Network Error'}\nCheck if Burp Suite is running and REST API is enabled at ${this.burpUrl}`
        }]
      };
    }
  }

  async repeaterSend(url, method = 'GET', headers = {}, body = '') {
    return await this.sendRequest(url, method, headers, body);
  }

  async decoderEncode(data, encoding) {
    const encodings = { base64: btoa, url: encodeURIComponent };
    const result = encodings[encoding] ? encodings[encoding](data) : data;
    return { content: [{ type: 'text', text: `Encoded: ${result}` }] };
  }

  async decoderDecode(data, encoding) {
    const decodings = { base64: atob, url: decodeURIComponent };
    try {
      const result = decodings[encoding] ? decodings[encoding](data) : data;
      return { content: [{ type: 'text', text: `Decoded: ${result}` }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `Decode failed: ${error.message}` }] };
    }
  }

  async comparerCompare(data1, data2) {
    const diff = data1 === data2 ? 'Identical' : 'Different';
    return { content: [{ type: 'text', text: `Comparison: ${diff}` }] };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.log('Burp MCP server started.');
  }
}

const server = new BurpMCPServer();
server.run().catch(console.error);