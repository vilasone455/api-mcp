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
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { basename, join } from 'path';
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

type AuthConfig = {
  folder?: string;
  user_title?: string;
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
            },
            auth: {
              type: "object",
              description: "Optional auth configuration to load a stored bearer token",
              properties: {
                folder: {
                  type: "string",
                  description: "Folder where tokens are stored (tokens.json)"
                },
                user_title: {
                  type: "string",
                  description: "User title to pick the token from storage (default: 'default')"
                }
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
            },
            auth: {
              type: "object",
              description: "Optional auth configuration to load a stored bearer token",
              properties: {
                folder: {
                  type: "string",
                  description: "Folder where tokens are stored (tokens.json)"
                },
                user_title: {
                  type: "string",
                  description: "User title to pick the token from storage (default: 'default')"
                }
              }
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
            },
            auth: {
              type: "object",
              description: "Optional auth configuration to load a stored bearer token",
              properties: {
                folder: {
                  type: "string",
                  description: "Folder where tokens are stored (tokens.json)"
                },
                user_title: {
                  type: "string",
                  description: "User title to pick the token from storage (default: 'default')"
                }
              }
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
            },
            auth: {
              type: "object",
              description: "Optional auth configuration to load a stored bearer token",
              properties: {
                folder: {
                  type: "string",
                  description: "Folder where tokens are stored (tokens.json)"
                },
                user_title: {
                  type: "string",
                  description: "User title to pick the token from storage (default: 'default')"
                }
              }
            }
          },
          required: ["url"]
        }
      },
      {
        name: "auth_login",
        description: "Authenticate against an API, extract a JWT, and store it locally for reuse",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "The URL to make the authentication request to"
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the auth request",
              additionalProperties: {
                type: "string"
              }
            },
            body: {
              description: "The request body for authentication"
            },
            requestType: {
              type: "string",
              enum: ["json", "form-data"],
              description: "Request type for the auth call"
            },
            fieldFiles: {
              type: "array",
              items: {
                type: "string"
              },
              description: "Array of field names that should be treated as files for form-data auth requests"
            },
            jwtPath: {
              type: "string",
              description: "Dot-notation path to the JWT in the response (e.g., token.access_token)"
            },
            folder: {
              type: "string",
              description: "Folder where the token file will be stored"
            },
            user_title: {
              type: "string",
              description: "Optional label for the stored token (default: 'default')"
            }
          },
          required: ["url", "jwtPath", "folder"]
        }
      },
      {
        name: "list_user",
        description: "List stored users and tokens from a token store",
        inputSchema: {
          type: "object",
          properties: {
            folder: {
              type: "string",
              description: "Folder where the token file is stored"
            },
            file: {
              type: "string",
              description: "Optional token file name (default: tokens.json)"
            },
            titlesOnly: {
              type: "boolean",
              description: "Return only user titles instead of full token entries"
            }
          },
          required: ["folder"]
        }
      },
      {
        name: "clear_user",
        description: "Remove a specific user or clear the token store",
        inputSchema: {
          type: "object",
          properties: {
            folder: {
              type: "string",
              description: "Folder where the token file is stored"
            },
            file: {
              type: "string",
              description: "Optional token file name (default: tokens.json)"
            },
            user_title: {
              type: "string",
              description: "Specific user title to remove. If omitted, all users are removed."
            },
            preserveDefault: {
              type: "boolean",
              description: "When clearing all users, keep the 'default' user entry if it exists"
            }
          },
          required: ["folder"]
        }
      }
    ]
  };
});

function resolveTokenFilePath(folder: string): string {
  return join(folder, 'tokens.json');
}

function resolveCustomTokenPath(folder: string, file?: string): string {
  return join(folder, file || 'tokens.json');
}

function readTokenStore(folder: string, file?: string): { filePath: string; tokens: any[] } {
  const filePath = resolveCustomTokenPath(folder, file);

  if (!existsSync(filePath)) {
    throw new Error(`Token store not found at ${filePath}`);
  }

  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);

    if (!Array.isArray(parsed)) {
      throw new Error(`Token store at ${filePath} is not an array`);
    }

    return { filePath, tokens: parsed };
  } catch (error) {
    throw new Error(
      `Unable to read token store at ${filePath}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

function loadStoredTokens(folder: string): Array<{ user_title_name: string; token: string }> {
  const tokenFile = resolveTokenFilePath(folder);
  if (!existsSync(tokenFile)) {
    return [];
  }

  try {
    const data = readFileSync(tokenFile, 'utf-8');
    const parsed = JSON.parse(data);
    if (Array.isArray(parsed)) {
      return parsed;
    }
    return [];
  } catch (error) {
    server.sendLoggingMessage({
      level: "error",
      data: `Failed to read token file at ${tokenFile}: ${error instanceof Error ? error.message : String(error)}`,
    });
    throw new Error(`Unable to read token file at ${tokenFile}`);
  }
}

function writeTokenStore(filePath: string, folder: string, tokens: any[]) {
  mkdirSync(folder, { recursive: true });
  writeFileSync(filePath, JSON.stringify(tokens, null, 2), 'utf-8');
}

function saveToken(folder: string, userTitle: string, token: string) {
  const tokenFile = resolveTokenFilePath(folder);
  mkdirSync(folder, { recursive: true });

  const tokens = loadStoredTokens(folder);
  const existingIndex = tokens.findIndex((entry) => entry.user_title_name === userTitle);

  if (existingIndex >= 0) {
    tokens[existingIndex].token = token;
  } else {
    tokens.push({ user_title_name: userTitle, token });
  }

  writeFileSync(tokenFile, JSON.stringify(tokens, null, 2), 'utf-8');
}

function extractValueByPath(obj: any, path: string): any {
  return path.split('.').reduce((current, key) => {
    if (current && typeof current === 'object' && key in current) {
      return current[key as keyof typeof current];
    }
    return undefined;
  }, obj);
}

function applyAuthHeader(headers: Record<string, string>, auth?: AuthConfig): Record<string, string> {
  if (!auth) {
    return headers;
  }

  const folder = auth.folder;
  if (!folder) {
    throw new Error("auth.folder is required when using auth configuration");
  }

  if (headers.Authorization) {
    return headers;
  }

  const userTitle = auth.user_title || 'default';
  const tokens = loadStoredTokens(folder);
  const tokenEntry = tokens.find((entry) => entry.user_title_name === userTitle);

  if (!tokenEntry) {
    throw new Error(`No token found for user_title '${userTitle}' in folder '${folder}'`);
  }

  return {
    ...headers,
    Authorization: `Bearer ${tokenEntry.token}`,
  };
}

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
      const auth = args?.auth as AuthConfig | undefined;
      const headers = applyAuthHeader(args?.headers as Record<string, string> || {}, auth);
      
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
      const auth = args?.auth as AuthConfig | undefined;
      const headers = applyAuthHeader(args?.headers as Record<string, string> || {}, auth);
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
      const auth = args?.auth as AuthConfig | undefined;
      const headers = applyAuthHeader(args?.headers as Record<string, string> || {}, auth);
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
      const auth = args?.auth as AuthConfig | undefined;
      const headers = applyAuthHeader(args?.headers as Record<string, string> || {}, auth);
      
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

    case "auth_login": {
      const url = String(args?.url || '');
      const headers = args?.headers as Record<string, string> || {};
      const body = args?.body;
      const requestType = args?.requestType as 'json' | 'form-data' || 'json';
      const fieldFiles = args?.fieldFiles as string[] || [];
      const jwtPath = String(args?.jwtPath || '');
      const folder = String(args?.folder || '');
      const userTitle = String(args?.user_title || 'default');

      if (!url) {
        throw new Error("URL is required for auth_login");
      }

      if (!jwtPath) {
        throw new Error("jwtPath is required to extract the token");
      }

      if (!folder) {
        throw new Error("folder is required to store the token");
      }

      const result = await makeHttpRequest('POST', { url, headers, body, requestType, fieldFiles });

      const token = extractValueByPath(result.data, jwtPath);

      if (!token || typeof token !== 'string') {
        throw new Error(`Could not find a token at path '${jwtPath}' in the response`);
      }

      saveToken(folder, userTitle, token);

      return {
        content: [{
          type: "text",
          text: `Stored token for user '${userTitle}' at ${resolveTokenFilePath(folder)}`
        }]
      };
    }

    case "list_user": {
      const folder = String(args?.folder || '');
      const file = args?.file ? String(args.file) : undefined;
      const titlesOnly = Boolean(args?.titlesOnly);

      if (!folder) {
        throw new Error("folder is required to read the token store");
      }

      try {
        const { filePath, tokens } = readTokenStore(folder, file);
        const result = titlesOnly
          ? tokens
              .map((entry) => entry?.user_title_name)
              .filter((title): title is string => Boolean(title))
          : tokens;

        return {
          content: [{
            type: "text",
            text: JSON.stringify(
              {
                file: filePath,
                users: result
              },
              null,
              2
            )
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify(
              {
                error: 'Unable to list users from token store',
                details: error instanceof Error ? error.message : String(error)
              },
              null,
              2
            )
          }]
        };
      }
    }

    case "clear_user": {
      const folder = String(args?.folder || '');
      const file = args?.file ? String(args.file) : undefined;
      const userTitle = args?.user_title ? String(args.user_title) : undefined;
      const preserveDefault = Boolean(args?.preserveDefault);

      if (!folder) {
        throw new Error("folder is required to clear users from the token store");
      }

      try {
        const { filePath, tokens } = readTokenStore(folder, file);
        let updatedTokens = tokens;
        let message: string | undefined;

        if (userTitle) {
          const remaining = tokens.filter((entry) => entry?.user_title_name !== userTitle);
          const removedCount = tokens.length - remaining.length;

          if (removedCount === 0) {
            message = `No entry found for user_title '${userTitle}' in ${filePath}`;
          }

          updatedTokens = remaining;
        } else {
          updatedTokens = preserveDefault
            ? tokens.filter((entry) => entry?.user_title_name === 'default')
            : [];

          if (preserveDefault && tokens.some((entry) => entry?.user_title_name === 'default')) {
            message = `Cleared all users except default from ${filePath}`;
          }
        }

        writeTokenStore(filePath, folder, updatedTokens);

        const responsePayload = {
          file: filePath,
          users: updatedTokens,
          message: message || (userTitle
            ? `Removed user '${userTitle}' from ${filePath}`
            : `Cleared token store at ${filePath}`)
        };

        return {
          content: [{
            type: "text",
            text: JSON.stringify(responsePayload, null, 2)
          }]
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
          content: [{
            type: "text",
            text: JSON.stringify(
              {
                error: 'Unable to clear user(s) from token store',
                details: errorMessage
              },
              null,
              2
            )
          }]
        };
      }
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
