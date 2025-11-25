#!/usr/bin/env node

/**
 * This is an API MCP server that provides HTTP method tools.
 * It demonstrates core MCP concepts by allowing:
 * - Making HTTP requests via GET, POST, PUT, DELETE tools
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync, existsSync } from 'fs';
import { basename } from 'path';
import FormData from 'form-data';
import fetch, { RequestInit as NodeRequestInit } from 'node-fetch';

/**
 * Type alias for HTTP request configuration.
 */
type HttpRequestConfig = {
  url: string;
  headers?: Record<string, string>;
  body?: any;
  requestType?: 'json' | 'form-data';
  fieldFiles?: string[];
};

/**
 * Simple storage for request history (optional, for debugging).
 * In a real implementation, this might be logged to a file or database.
 */
const requestHistory: Array<{ method: string; config: HttpRequestConfig; timestamp: Date }> = [];

/**
 * Create an MCP server with capabilities for HTTP API tools.
 */
const server = new Server(
  {
    name: "api-mcp",
    version: "0.1.0",
  },
  {
    capabilities: {
            logging: {},     
      tools: {},
    },
  }
);

/**
 * Handler that lists available tools.
 * Exposes HTTP method tools: GET, POST, PUT, DELETE.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "get",
        description: "Make a GET HTTP request",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to make the GET request to"
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
              additionalProperties: {
                type: "string"
              }
            }
          },
          required: ["url"]
        }
      },
      {
        name: "post",
        description: "Make a pOST HTTP request",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to make the POST request to"
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
              additionalProperties: {
                type: "string"
              }
            },
            body: {
              description: "The request body (JSON object, string, etc.)"
            },
            requestType: {
              type: "string",
              enum: ["json", "form-data"],
              description: "Request type: 'json' for JSON data, 'form-data' for form data with file uploads"
            },
            fieldFiles: {
              type: "array",
              items: {
                type: "string"
              },
              description: "Array of field names that should be treated as files. Values can be URLs (http/https) for remote files or local file paths for local files. The system will automatically download remote files or read local files and include them as file attachments in the form data."
            }
          },
          required: ["url"]
        }
      },
      {
        name: "put",
        description: "Make a PUT HTTP request",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to make the PUT request to"
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
              additionalProperties: {
                type: "string"
              }
            },
            body: {
              description: "The request body (JSON object, string, etc.)"
            },
            requestType: {
              type: "string",
              enum: ["json", "form-data"],
              description: "Request type: 'json' for JSON data, 'form-data' for form data with file uploads"
            },
            fieldFiles: {
              type: "array",
              items: {
                type: "string"
              },
              description: "Array of field names that should be treated as files. Values can be URLs (http/https) for remote files or local file paths for local files. The system will automatically download remote files or read local files and include them as file attachments in the form data."
            }
          },
          required: ["url"]
        }
      },
      {
        name: "delete",
        description: "Make a DELETE HTTP request",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to make the DELETE request to"
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
              additionalProperties: {
                type: "string"
              }
            }
          },
          required: ["url"]
        }
      }
    ]
  };
});

/**
 * Get file extension from content type
 */
function getMimeType(fileName: string): string {
  const ext = fileName.toLowerCase().split('.').pop();
  const mimeTypes: Record<string, string> = {
    // Images
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'svg': 'image/svg+xml',
    'bmp': 'image/bmp',
    'ico': 'image/x-icon',
    // Documents
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    // Text files
    'txt': 'text/plain',
    'csv': 'text/csv',
    'json': 'application/json',
    'xml': 'application/xml',
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'ts': 'application/typescript',
    // Audio
    'mp3': 'audio/mpeg',
    'wav': 'audio/wav',
    'ogg': 'audio/ogg',
    // Video
    'mp4': 'video/mp4',
    'avi': 'video/x-msvideo',
    'mov': 'video/quicktime',
    // Archives
    'zip': 'application/zip',
    'rar': 'application/vnd.rar',
    '7z': 'application/x-7z-compressed',
    'tar': 'application/x-tar',
    'gz': 'application/gzip'
  };
  return mimeTypes[ext || ''] || 'application/octet-stream';
}

/**
 * Helper function to create FormData from body and field files.
 */
async function createFormData(body: any, fieldFiles: string[] = []): Promise<FormData> {
  const formData = new FormData();
  
  server.sendLoggingMessage({
    level: "info",
    data: `Creating FormData with body: ${JSON.stringify(body)} and fieldFiles: ${JSON.stringify(fieldFiles)}`,
  });
  
  // Parse body if it's a JSON string
  let parsedBody = body;
  if (typeof body === 'string') {
    try {
      parsedBody = JSON.parse(body);
      server.sendLoggingMessage({
        level: "info",
        data: `Parsed JSON string body to object: ${JSON.stringify(parsedBody)}`,
      });
    } catch (error) {
      server.sendLoggingMessage({
        level: "error",
        data: `Failed to parse body as JSON: ${error instanceof Error ? error.message : String(error)}`,
      });
      throw new Error(`Invalid JSON body: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  for (const [key, value] of Object.entries(parsedBody)) {
    server.sendLoggingMessage({
      level: "info",
      data: `Processing field: ${key} = ${value} (type: ${typeof value})`,
    });
    
    if (fieldFiles.includes(key) && typeof value === 'string') {
      server.sendLoggingMessage({
        level: "info",
        data: `Field '${key}' is marked as file field with value: ${value}`,
      });
      
      // Handle file field - download the file if it's a URL or read local file
      if (value.startsWith('http://') || value.startsWith('https://')) {
        try {
          server.sendLoggingMessage({
            level: "info",
            data: `Downloading file from: ${value}`,
          });
          
          const fileResponse = await fetch(value);
          if (!fileResponse.ok) {
            throw new Error(`Failed to download file: ${fileResponse.statusText}`);
          }
          const buffer = await fileResponse.arrayBuffer();
          const contentType = fileResponse!.headers.get('content-type') || 'application/octet-stream';
          const filename = key + getExtensionFromContentType(contentType);

          server.sendLoggingMessage({
            level: "info",
            data: `Downloaded file: ${filename}, size: ${buffer.byteLength} bytes, contentType: ${contentType}`,
          });

          // Use form-data package API
          formData.append(key, Buffer.from(buffer), {
            filename: filename,
            contentType: contentType
          });
          
          server.sendLoggingMessage({
            level: "info",
            data: `Added file to FormData: ${filename} (${buffer.byteLength} bytes)`,
          });
        } catch (error) {
          server.sendLoggingMessage({
            level: "error",
            data: `Failed to download file from URL '${value}': ${error instanceof Error ? error.message : String(error)}`,
          });
          throw new Error(`Failed to download file from URL '${value}': ${error instanceof Error ? error.message : String(error)}`);
        }
      } else if (existsSync(value)) {
        // Handle local file path
        try {
          server.sendLoggingMessage({
            level: "info",
            data: `Reading local file: ${value}`,
          });
          
          const fileBuffer = readFileSync(value);
          const fileName = basename(value);
          const mimeType = getMimeType(fileName);

          server.sendLoggingMessage({
            level: "info",
            data: `Read local file: ${fileName}, size: ${fileBuffer.length} bytes, mimeType: ${mimeType}`,
          });

          // Use form-data package API
          formData.append(key, fileBuffer, {
            filename: fileName,
            contentType: mimeType
          });
          
          server.sendLoggingMessage({
            level: "info",
            data: `Added local file to FormData: ${fileName} (${fileBuffer.length} bytes)`,
          });
        } catch (error) {
          server.sendLoggingMessage({
            level: "error",
            data: `Failed to read local file '${value}': ${error instanceof Error ? error.message : String(error)}`,
          });
          throw new Error(`Failed to read local file '${value}': ${error instanceof Error ? error.message : String(error)}`);
        }
      } else {
        server.sendLoggingMessage({
          level: "error",
          data: `Invalid file source: ${value}. Must be a valid URL or existing file path.`,
        });
        throw new Error(`Invalid file source: ${value}. Must be a valid URL or existing file path.`);
      }
    } else {
      // Handle regular field
      server.sendLoggingMessage({
        level: "info",
        data: `Adding regular field to FormData: ${key} = ${String(value)}`,
      });
      formData.append(key, String(value));
    }
  }
  
  server.sendLoggingMessage({
    level: "info",
    data: `FormData created successfully with ${Object.keys(parsedBody).length} fields`,
  });
  
  return formData;
}

/**
 * Get file extension from content type
 */
function getExtensionFromContentType(contentType: string): string {
  const extensions: Record<string, string> = {
    'image/jpeg': '.jpg',
    'image/jpg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'text/plain': '.txt',
    'application/pdf': '.pdf',
    'application/json': '.json',
    'application/xml': '.xml',
    'text/html': '.html',
    'text/css': '.css',
    'application/javascript': '.js',
    'application/typescript': '.ts',
    'audio/mpeg': '.mp3',
    'audio/wav': '.wav',
    'video/mp4': '.mp4',
    'application/zip': '.zip'
  };
  return extensions[contentType.toLowerCase()] || '';
}
/**
 * Helper function to make HTTP requests.
 */
async function makeHttpRequest(method: string, config: HttpRequestConfig) {
  try {
    server.sendLoggingMessage({
      level: "info",
      data: `Starting ${method.toUpperCase()} request to: ${config.url}`,
    });

    const options: NodeRequestInit = {
      method: method.toUpperCase(),
      headers: {
        ...config.headers,
      },
    };

    if (config.body && (method === 'POST' || method === 'PUT')) {
      if (config.requestType === 'form-data') {
        server.sendLoggingMessage({
          level: "info",
          data: `Using form-data request type with fieldFiles: ${JSON.stringify(config.fieldFiles)}`,
        });
        
        // Use FormData for form-data requests
        const formData = await createFormData(config.body, config.fieldFiles);
        options.body = formData as any; // Cast to any to handle type incompatibility
        
        server.sendLoggingMessage({
          level: "info",
          data: `FormData prepared, not setting Content-Type header (will be auto-set with boundary)`,
        });
        // Don't set Content-Type header for FormData, let the system set it with boundary
      } else {
        server.sendLoggingMessage({
          level: "info",
          data: `Using JSON request type`,
        });
        
        // Use JSON for regular requests
        options.headers = {
          'Content-Type': 'application/json',
          ...options.headers,
        };
        options.body = typeof config.body === 'string' ? config.body : JSON.stringify(config.body);
        
        server.sendLoggingMessage({
          level: "info",
          data: `JSON body prepared: ${options.body}`,
        });
      }
    } else if (!config.body && method !== 'GET' && method !== 'DELETE') {
      // Set default Content-Type for POST/PUT without body
      options.headers = {
        'Content-Type': 'application/json',
        ...options.headers,
      };
    }

    server.sendLoggingMessage({
      level: "info",
      data: `Request headers: ${JSON.stringify(options.headers)}`,
    });

    server.sendLoggingMessage({
      level: "info",
      data: `Making HTTP request...`,
    });

    const response = await fetch(config.url, options);
    
    server.sendLoggingMessage({
      level: "info",
      data: `Response received: ${response.status} ${response.statusText}`,
    });

    const responseText = await response.text();
    
    server.sendLoggingMessage({
      level: "info",
      data: `Response body: ${responseText}`,
    });
    
    // Try to parse as JSON, fallback to text
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = responseText;
    }

    // Store in history
    requestHistory.push({
      method: method.toUpperCase(),
      config,
      timestamp: new Date()
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      data: responseData
    };
  } catch (error) {
    server.sendLoggingMessage({
      level: "error",
      data: `HTTP ${method.toUpperCase()} request failed: ${error instanceof Error ? error.message : String(error)}`,
    });
    throw new Error(`HTTP ${method.toUpperCase()} request failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Handler for HTTP method tools.
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  switch (name) {
    case "get": {
      const url = String(args?.url || '');
      const headers = args?.headers as Record<string, string> || {};
      
      if (!url) {
        throw new Error("URL is required for GET request");
      }

      const result = await makeHttpRequest('GET', { url, headers });
      
      return {
        content: [{
          type: "text",
          text: `GET ${url}\nStatus: ${result.status} ${result.statusText}\nResponse: ${JSON.stringify(result.data, null, 2)}`
        }]
      };
    }

    case "post": {
      const url = String(args?.url || '');
      const headers = args?.headers as Record<string, string> || {};
      const body = args?.body;
      const requestType = args?.requestType as 'json' | 'form-data' || 'json';
      const fieldFiles = args?.fieldFiles as string[] || [];
      
      if (!url) {
        throw new Error("URL is required for POST request");
      }

      const result = await makeHttpRequest('POST', { url, headers, body, requestType, fieldFiles });
      
      return {
        content: [{
          type: "text",
          text: `POST ${url}\nRequest Type: ${requestType}\nStatus: ${result.status} ${result.statusText}\nResponse: ${JSON.stringify(result.data, null, 2)}`
        }]
      };
    }

    case "put": {
      const url = String(args?.url || '');
      const headers = args?.headers as Record<string, string> || {};
      const body = args?.body;
      const requestType = args?.requestType as 'json' | 'form-data' || 'json';
      const fieldFiles = args?.fieldFiles as string[] || [];
      
      if (!url) {
        throw new Error("URL is required for PUT request");
      }

      const result = await makeHttpRequest('PUT', { url, headers, body, requestType, fieldFiles });
      
      return {
        content: [{
          type: "text",
          text: `PUT ${url}\nRequest Type: ${requestType}\nStatus: ${result.status} ${result.statusText}\nResponse: ${JSON.stringify(result.data, null, 2)}`
        }]
      };
    }

    case "delete": {
      const url = String(args?.url || '');
      const headers = args?.headers as Record<string, string> || {};
      
      if (!url) {
        throw new Error("URL is required for DELETE request");
      }

      const result = await makeHttpRequest('DELETE', { url, headers });
      
      return {
        content: [{
          type: "text",
          text: `DELETE ${url}\nStatus: ${result.status} ${result.statusText}\nResponse: ${JSON.stringify(result.data, null, 2)}`
        }]
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

/**
 * Start the server using stdio transport.
 * This allows the server to communicate via standard input/output streams.
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
