import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'url'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import { randomUUID, randomBytes, createHash } from 'node:crypto'
import express from 'express'

import { initProxy, ValidationError } from '../src/init-server'

// ── Token store for OAuth-issued user keys ──────────────────────────
// Maps userKey -> { notionToken, workspaceName, botId, owner }
type UserEntry = {
  notionToken: string
  workspaceName?: string
  botId?: string
  owner?: string
  createdAt: string
}

const TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || '/data/tokens.json'

function loadTokenStore(): Record<string, UserEntry> {
  try {
    const data = fs.readFileSync(TOKEN_STORE_PATH, 'utf-8')
    return JSON.parse(data)
  } catch {
    return {}
  }
}

function saveTokenStore(store: Record<string, UserEntry>) {
  const dir = path.dirname(TOKEN_STORE_PATH)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
  fs.writeFileSync(TOKEN_STORE_PATH, JSON.stringify(store, null, 2))
}

function lookupNotionToken(userKey: string): string | undefined {
  const store = loadTokenStore()
  return store[userKey]?.notionToken
}

export async function startServer(args: string[] = process.argv) {
  const filename = fileURLToPath(import.meta.url)
  const directory = path.dirname(filename)
  const specPath = path.resolve(directory, '../scripts/notion-openapi.json')
  
  const baseUrl = process.env.BASE_URL ?? undefined

  // Parse command line arguments manually (similar to slack-mcp approach)
  function parseArgs() {
    const args = process.argv.slice(2);
    let transport = 'stdio'; // default
    let port = 3000;
    let authToken: string | undefined;
    let disableAuth = false;

    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--transport' && i + 1 < args.length) {
        transport = args[i + 1];
        i++; // skip next argument
      } else if (args[i] === '--port' && i + 1 < args.length) {
        port = parseInt(args[i + 1], 10);
        i++; // skip next argument
      } else if (args[i] === '--auth-token' && i + 1 < args.length) {
        authToken = args[i + 1];
        i++; // skip next argument
      } else if (args[i] === '--disable-auth') {
        disableAuth = true;
      } else if (args[i] === '--help' || args[i] === '-h') {
        console.log(`
Usage: notion-mcp-server [options]

Options:
  --transport <type>     Transport type: 'stdio' or 'http' (default: stdio)
  --port <number>        Port for HTTP server when using Streamable HTTP transport (default: 3000)
  --auth-token <token>   Bearer token for HTTP transport authentication (optional)
  --disable-auth         Disable bearer token authentication for HTTP transport
  --help, -h             Show this help message

Environment Variables:
  NOTION_TOKEN           Notion integration token (recommended)
  OPENAPI_MCP_HEADERS    JSON string with Notion API headers (alternative)
  AUTH_TOKEN             Bearer token for HTTP transport authentication (alternative to --auth-token)

Examples:
  notion-mcp-server                                    # Use stdio transport (default)
  notion-mcp-server --transport stdio                  # Use stdio transport explicitly
  notion-mcp-server --transport http                   # Use Streamable HTTP transport on port 3000
  notion-mcp-server --transport http --port 8080       # Use Streamable HTTP transport on port 8080
  notion-mcp-server --transport http --auth-token mytoken # Use Streamable HTTP transport with custom auth token
  notion-mcp-server --transport http --disable-auth    # Use Streamable HTTP transport without authentication
  AUTH_TOKEN=mytoken notion-mcp-server --transport http # Use Streamable HTTP transport with auth token from env var
`);
        process.exit(0);
      }
      // Ignore unrecognized arguments (like command name passed by Docker)
    }

    return { transport: transport.toLowerCase(), port, authToken, disableAuth };
  }

  const options = parseArgs()
  const transport = options.transport

  if (transport === 'stdio') {
    // Use stdio transport (default)
    const proxy = await initProxy(specPath, baseUrl)
    await proxy.connect(new StdioServerTransport())
    return proxy.getServer()
  } else if (transport === 'http') {
    // Use Streamable HTTP transport
    const app = express()
    app.use(express.json())

    // Generate or use provided auth token (from CLI arg or env var) only if auth is enabled
    let authToken: string | undefined
    if (!options.disableAuth) {
      authToken = options.authToken || process.env.AUTH_TOKEN || randomBytes(32).toString('hex')
      if (!options.authToken && !process.env.AUTH_TOKEN) {
        console.log(`Generated auth token: ${authToken}`)
        console.log(`Use this token in the Authorization header: Bearer ${authToken}`)
      }
    }

    // Health endpoint (no authentication required)
    app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        transport: 'http',
        port: options.port
      })
    })

    // ── Notion OAuth flow ──────────────────────────────────────────
    const NOTION_CLIENT_ID = process.env.NOTION_OAUTH_CLIENT_ID
    const NOTION_CLIENT_SECRET = process.env.NOTION_OAUTH_CLIENT_SECRET
    const PUBLIC_URL = process.env.PUBLIC_URL || `https://nulegal-notion-mcp.fly.dev`

    if (NOTION_CLIENT_ID && NOTION_CLIENT_SECRET) {
      // Step 1: Redirect to Notion OAuth
      app.get('/auth/notion', (req, res) => {
        const redirectUri = `${PUBLIC_URL}/auth/notion/callback`
        const url = `https://api.notion.com/v1/oauth/authorize?client_id=${NOTION_CLIENT_ID}&response_type=code&owner=user&redirect_uri=${encodeURIComponent(redirectUri)}`
        res.redirect(url)
      })

      // Step 2: Handle callback, exchange code for token, issue user key
      app.get('/auth/notion/callback', async (req, res) => {
        const code = req.query.code as string | undefined
        const error = req.query.error as string | undefined

        if (error || !code) {
          res.status(400).send(`<h2>Authorization failed</h2><p>${error || 'No code received'}</p>`)
          return
        }

        try {
          // Exchange code for access token
          const redirectUri = `${PUBLIC_URL}/auth/notion/callback`
          const basicAuth = Buffer.from(`${NOTION_CLIENT_ID}:${NOTION_CLIENT_SECRET}`).toString('base64')

          const tokenRes = await fetch('https://api.notion.com/v1/oauth/token', {
            method: 'POST',
            headers: {
              'Authorization': `Basic ${basicAuth}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              grant_type: 'authorization_code',
              code,
              redirect_uri: redirectUri,
            }),
          })

          if (!tokenRes.ok) {
            const errBody = await tokenRes.text()
            console.error('Notion OAuth token exchange failed:', errBody)
            res.status(500).send(`<h2>Token exchange failed</h2><pre>${errBody}</pre>`)
            return
          }

          const tokenData = await tokenRes.json() as {
            access_token: string
            workspace_name?: string
            bot_id?: string
            owner?: { user?: { name?: string; person?: { email?: string } } }
          }

          // Generate a unique user key
          const userKey = `nmc_${randomBytes(24).toString('hex')}`

          // Store the mapping
          const store = loadTokenStore()
          const ownerName = tokenData.owner?.user?.name || tokenData.owner?.user?.person?.email || 'unknown'
          store[userKey] = {
            notionToken: tokenData.access_token,
            workspaceName: tokenData.workspace_name,
            botId: tokenData.bot_id,
            owner: ownerName,
            createdAt: new Date().toISOString(),
          }
          saveTokenStore(store)

          // Show the user their config
          const serverAuthToken = authToken || '<SERVER_AUTH_TOKEN>'
          res.send(`<!DOCTYPE html>
<html><head><title>Notion MCP — Connected!</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; background: #fafafa; }
  h1 { color: #2d2d2d; }
  .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 16px; border-radius: 8px; margin: 20px 0; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
  .key { color: #9cdcfe; } .str { color: #ce9178; }
  code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  .warn { background: #fff3cd; border: 1px solid #ffeeba; padding: 12px; border-radius: 8px; margin: 16px 0; }
</style></head>
<body>
  <h1>Connected to Notion!</h1>
  <div class="success">
    <strong>Workspace:</strong> ${tokenData.workspace_name || 'N/A'}<br>
    <strong>User:</strong> ${ownerName}
  </div>
  <h2>Your MCP Config</h2>
  <p>Add this to your <code>.cursor/mcp.json</code> or Claude Code MCP settings:</p>
  <pre>{
  <span class="key">"mcpServers"</span>: {
    <span class="key">"notion"</span>: {
      <span class="key">"url"</span>: <span class="str">"${PUBLIC_URL}/mcp"</span>,
      <span class="key">"headers"</span>: {
        <span class="key">"Authorization"</span>: <span class="str">"Bearer ${userKey}"</span>
      }
    }
  }
}</pre>
  <div class="warn">
    <strong>Keep your key private.</strong> It grants access to your Notion workspace through this server.
    Your personal key starts with <code>nmc_</code>.
  </div>
  <p>That's it — no other setup needed. The server handles everything.</p>
</body></html>`)
        } catch (err) {
          console.error('OAuth callback error:', err)
          res.status(500).send(`<h2>Something went wrong</h2><pre>${err}</pre>`)
        }
      })

      console.log(`Notion OAuth enabled: ${PUBLIC_URL}/auth/notion`)
    }

    // ── Auth middleware (supports admin token + OAuth user keys) ────
    const authenticateAndResolveToken = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
      const authHeader = req.headers['authorization']
      const token = authHeader && authHeader.split(' ')[1] // Bearer TOKEN

      if (!token) {
        res.status(401).json({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Unauthorized: Missing bearer token' },
          id: null,
        })
        return
      }

      // Check if it's the admin/shared auth token
      if (authToken && token === authToken) {
        // Admin token — Notion token must come via X-Notion-Token header
        next()
        return
      }

      // Check if it's an OAuth-issued user key (starts with nmc_)
      if (token.startsWith('nmc_')) {
        const notionToken = lookupNotionToken(token)
        if (notionToken) {
          // Inject the Notion token into the request for downstream use
          req.headers['x-notion-token'] = notionToken
          next()
          return
        }
      }

      res.status(403).json({
        jsonrpc: '2.0',
        error: { code: -32002, message: 'Forbidden: Invalid bearer token' },
        id: null,
      })
    }

    // Apply authentication to all /mcp routes only if auth is enabled
    if (!options.disableAuth) {
      app.use('/mcp', authenticateAndResolveToken)
    }

    // Map to store transports by session ID
    const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {}

    // Handle POST requests for client-to-server communication
    app.post('/mcp', async (req, res) => {
      try {
        // Check for existing session ID
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        let transport: StreamableHTTPServerTransport

        if (sessionId && transports[sessionId]) {
          // Reuse existing transport
          transport = transports[sessionId]
        } else if (!sessionId && isInitializeRequest(req.body)) {
          // New initialization request
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId) => {
              // Store the transport by session ID
              transports[sessionId] = transport
            }
          })

          // Clean up transport when closed
          transport.onclose = () => {
            if (transport.sessionId) {
              delete transports[transport.sessionId]
            }
          }

          // Multi-tenant: extract per-user Notion token from request headers
          const notionToken = req.headers['x-notion-token'] as string | undefined
          let perSessionHeaders: Record<string, string> | undefined
          if (notionToken) {
            perSessionHeaders = {
              'Authorization': `Bearer ${notionToken}`,
              'Notion-Version': '2025-09-03',
            }
          }

          const proxy = await initProxy(specPath, baseUrl, perSessionHeaders)
          await proxy.connect(transport)
        } else {
          // Invalid request
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Bad Request: No valid session ID provided',
            },
            id: null,
          })
          return
        }

        // Handle the request
        await transport.handleRequest(req, res, req.body)
      } catch (error) {
        console.error('Error handling MCP request:', error)
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          })
        }
      }
    })

    // Handle GET requests for server-to-client notifications via Streamable HTTP
    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID')
        return
      }
      
      const transport = transports[sessionId]
      await transport.handleRequest(req, res)
    })

    // Handle DELETE requests for session termination
    app.delete('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID')
        return
      }
      
      const transport = transports[sessionId]
      await transport.handleRequest(req, res)
    })

    const port = options.port
    app.listen(port, '0.0.0.0', () => {
      console.log(`MCP Server listening on port ${port}`)
      console.log(`Endpoint: http://0.0.0.0:${port}/mcp`)
      console.log(`Health check: http://0.0.0.0:${port}/health`)
      if (options.disableAuth) {
        console.log(`Authentication: Disabled`)
      } else {
        console.log(`Authentication: Bearer token required`)
        if (options.authToken) {
          console.log(`Using provided auth token`)
        }
      }
    })

    // Return a dummy server for compatibility
    return { close: () => {} }
  } else {
    throw new Error(`Unsupported transport: ${transport}. Use 'stdio' or 'http'.`)
  }
}

startServer(process.argv).catch(error => {
  if (error instanceof ValidationError) {
    console.error('Invalid OpenAPI 3.1 specification:')
    error.errors.forEach(err => console.error(err))
  } else {
    console.error('Error:', error)
  }
  process.exit(1)
})
