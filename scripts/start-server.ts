import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'url'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import { randomUUID, randomBytes, createHash, timingSafeEqual } from 'node:crypto'
import express from 'express'

import { initProxy, ValidationError } from '../src/init-server'

// ── Persistent store ─────────────────────────────────────────────────
// All state lives in a single JSON file on the Fly.io volume.

const DATA_DIR = process.env.DATA_DIR || '/data'
const STORE_PATH = path.join(DATA_DIR, 'store.json')

type UserEntry = {
  notionToken: string
  workspaceName?: string
  botId?: string
  owner?: string
  createdAt: string
}

type OAuthClient = {
  clientId: string
  clientSecretHash: string
  clientName: string
  redirectUris: string[]
  grantTypes: string[]
  scope: string
  createdAt: string
}

type AuthCode = {
  code: string
  clientId: string
  redirectUri: string
  scope: string
  codeChallenge: string
  codeChallengeMethod: string
  userKey: string         // nmc_ key that maps to a Notion token
  expiresAt: number       // epoch ms
  used: boolean
}

type McpAccessToken = {
  tokenHash: string
  userKey: string         // nmc_ key
  clientId: string
  scope: string
  expiresAt: number       // epoch ms
  refreshTokenHash?: string
}

type Store = {
  users: Record<string, UserEntry>       // nmc_key -> UserEntry
  oauthClients: Record<string, OAuthClient> // clientId -> OAuthClient
  authCodes: Record<string, AuthCode>    // code -> AuthCode
  mcpTokens: Record<string, McpAccessToken> // tokenHash -> McpAccessToken
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true })
  }
}

function loadStore(): Store {
  try {
    const data = fs.readFileSync(STORE_PATH, 'utf-8')
    const parsed = JSON.parse(data)
    return {
      users: parsed.users || {},
      oauthClients: parsed.oauthClients || {},
      authCodes: parsed.authCodes || {},
      mcpTokens: parsed.mcpTokens || {},
    }
  } catch {
    return { users: {}, oauthClients: {}, authCodes: {}, mcpTokens: {} }
  }
}

function saveStore(store: Store) {
  ensureDataDir()
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2))
}

// Migrate old token store format if needed
function migrateOldTokenStore() {
  const oldPath = process.env.TOKEN_STORE_PATH || path.join(DATA_DIR, 'tokens.json')
  if (fs.existsSync(oldPath) && !fs.existsSync(STORE_PATH)) {
    try {
      const oldData = JSON.parse(fs.readFileSync(oldPath, 'utf-8'))
      const store = loadStore()
      store.users = oldData
      saveStore(store)
      console.log(`Migrated ${Object.keys(oldData).length} users from old token store`)
    } catch (e) {
      console.error('Failed to migrate old token store:', e)
    }
  }
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

function lookupNotionToken(userKey: string): string | undefined {
  const store = loadStore()
  return store.users[userKey]?.notionToken
}

// Look up a Notion token from an MCP access token (issued via OAuth 2.1)
function lookupNotionTokenFromMcpToken(bearerToken: string): string | undefined {
  const store = loadStore()
  const hash = hashToken(bearerToken)
  const mcpToken = store.mcpTokens[hash]
  if (!mcpToken) return undefined
  if (mcpToken.expiresAt < Date.now()) return undefined
  return store.users[mcpToken.userKey]?.notionToken
}

// ── Pending OAuth states (in-memory, transient) ──────────────────────
// Tracks the OAuth 2.1 authorize → Notion OAuth → callback chain.
type PendingOAuthState = {
  clientId: string
  redirectUri: string
  codeChallenge: string
  codeChallengeMethod: string
  scope: string
  state?: string
  createdAt: number
}
const pendingOAuthStates: Record<string, PendingOAuthState> = {}

// Clean up expired states every 5 minutes
setInterval(() => {
  const now = Date.now()
  for (const [key, val] of Object.entries(pendingOAuthStates)) {
    if (now - val.createdAt > 10 * 60 * 1000) delete pendingOAuthStates[key]
  }
}, 5 * 60 * 1000)

// ── Server ───────────────────────────────────────────────────────────

export async function startServer(args: string[] = process.argv) {
  const filename = fileURLToPath(import.meta.url)
  const directory = path.dirname(filename)
  const specPath = path.resolve(directory, '../scripts/notion-openapi.json')

  const baseUrl = process.env.BASE_URL ?? undefined

  function parseArgs() {
    const args = process.argv.slice(2);
    let transport = 'stdio';
    let port = 3000;
    let authToken: string | undefined;
    let disableAuth = false;

    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--transport' && i + 1 < args.length) {
        transport = args[i + 1];
        i++;
      } else if (args[i] === '--port' && i + 1 < args.length) {
        port = parseInt(args[i + 1], 10);
        i++;
      } else if (args[i] === '--auth-token' && i + 1 < args.length) {
        authToken = args[i + 1];
        i++;
      } else if (args[i] === '--disable-auth') {
        disableAuth = true;
      } else if (args[i] === '--help' || args[i] === '-h') {
        console.log(`
Usage: notion-mcp-server [options]

Options:
  --transport <type>     Transport type: 'stdio' or 'http' (default: stdio)
  --port <number>        Port for HTTP server (default: 3000)
  --auth-token <token>   Bearer token for admin access (optional)
  --disable-auth         Disable authentication entirely
  --help, -h             Show this help message
`);
        process.exit(0);
      }
    }

    return { transport: transport.toLowerCase(), port, authToken, disableAuth };
  }

  const options = parseArgs()
  const transport = options.transport

  if (transport === 'stdio') {
    const proxy = await initProxy(specPath, baseUrl)
    await proxy.connect(new StdioServerTransport())
    return proxy.getServer()
  } else if (transport === 'http') {
    // Migrate old token store on startup
    migrateOldTokenStore()

    const app = express()
    app.use(express.json())
    app.use(express.urlencoded({ extended: true }))

    // Admin auth token (for direct API access + legacy nmc_ keys)
    let authToken: string | undefined
    if (!options.disableAuth) {
      authToken = options.authToken || process.env.AUTH_TOKEN || randomBytes(32).toString('hex')
      if (!options.authToken && !process.env.AUTH_TOKEN) {
        console.log(`Generated auth token: ${authToken}`)
      }
    }

    const PUBLIC_URL = process.env.PUBLIC_URL || `https://nulegal-notion-mcp.fly.dev`
    const NOTION_CLIENT_ID = process.env.NOTION_OAUTH_CLIENT_ID
    const NOTION_CLIENT_SECRET = process.env.NOTION_OAUTH_CLIENT_SECRET

    // ── Health endpoint ────────────────────────────────────────────
    app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        transport: 'http',
        port: options.port
      })
    })

    // ── OAuth 2.1 Discovery (RFC 9728 + RFC 8414) ─────────────────

    // Protected Resource Metadata (RFC 9728)
    app.get('/.well-known/oauth-protected-resource', (req, res) => {
      res.json({
        resource: PUBLIC_URL,
        authorization_servers: [PUBLIC_URL],
        scopes_supported: ['read', 'write'],
        bearer_methods_supported: ['header'],
      })
    })

    // Authorization Server Metadata (RFC 8414)
    app.get('/.well-known/oauth-authorization-server', (req, res) => {
      res.json({
        issuer: PUBLIC_URL,
        authorization_endpoint: `${PUBLIC_URL}/oauth/authorize`,
        token_endpoint: `${PUBLIC_URL}/oauth/token`,
        registration_endpoint: `${PUBLIC_URL}/oauth/register`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
        scopes_supported: ['read', 'write'],
        code_challenge_methods_supported: ['S256'],
      })
    })

    // ── Dynamic Client Registration (RFC 7591) ────────────────────

    app.post('/oauth/register', (req, res) => {
      const { client_name, redirect_uris, grant_types, scope } = req.body

      if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' })
        return
      }

      // Validate redirect URIs (must be HTTPS, or HTTP for localhost)
      for (const uri of redirect_uris) {
        try {
          const parsed = new URL(uri)
          if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(parsed.hostname)) {
            res.status(400).json({ error: 'invalid_redirect_uri', error_description: `Non-HTTPS URI not allowed: ${uri}` })
            return
          }
        } catch {
          res.status(400).json({ error: 'invalid_redirect_uri', error_description: `Invalid URI: ${uri}` })
          return
        }
      }

      const clientId = randomUUID()
      const rawSecret = randomBytes(32).toString('base64url')

      const store = loadStore()
      store.oauthClients[clientId] = {
        clientId,
        clientSecretHash: hashToken(rawSecret),
        clientName: client_name || 'Unknown Client',
        redirectUris: redirect_uris,
        grantTypes: grant_types || ['authorization_code', 'refresh_token'],
        scope: scope || 'read write',
        createdAt: new Date().toISOString(),
      }
      saveStore(store)

      console.log(`Registered OAuth client: ${clientId} (${client_name || 'Unknown'})`)

      res.status(201).json({
        client_id: clientId,
        client_secret: rawSecret,
        client_name: client_name || 'Unknown Client',
        redirect_uris,
        grant_types: grant_types || ['authorization_code', 'refresh_token'],
        scope: scope || 'read write',
      })
    })

    // ── OAuth Authorize Endpoint ──────────────────────────────────
    // Claude.ai redirects the user here. We chain to Notion OAuth.

    app.get('/oauth/authorize', (req, res) => {
      const {
        client_id,
        redirect_uri,
        response_type,
        scope,
        state,
        code_challenge,
        code_challenge_method,
      } = req.query as Record<string, string>

      if (response_type !== 'code') {
        res.status(400).json({ error: 'unsupported_response_type' })
        return
      }

      if (!code_challenge) {
        res.status(400).json({ error: 'invalid_request', error_description: 'PKCE code_challenge required' })
        return
      }

      if (code_challenge_method && code_challenge_method !== 'S256') {
        res.status(400).json({ error: 'invalid_request', error_description: 'Only S256 code_challenge_method supported' })
        return
      }

      // Validate client
      const store = loadStore()
      const client = store.oauthClients[client_id]
      if (!client) {
        res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' })
        return
      }

      if (!client.redirectUris.includes(redirect_uri)) {
        res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri not registered' })
        return
      }

      if (!NOTION_CLIENT_ID || !NOTION_CLIENT_SECRET) {
        res.status(500).json({ error: 'server_error', error_description: 'Notion OAuth not configured' })
        return
      }

      // Generate a state token to track this OAuth flow through Notion
      const oauthStateKey = randomBytes(24).toString('base64url')
      pendingOAuthStates[oauthStateKey] = {
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method || 'S256',
        scope: scope || 'read write',
        state,
        createdAt: Date.now(),
      }

      // Redirect to Notion OAuth — user will authorize Notion access
      const notionRedirectUri = `${PUBLIC_URL}/oauth/notion-callback`
      const notionAuthUrl = `https://api.notion.com/v1/oauth/authorize?client_id=${NOTION_CLIENT_ID}&response_type=code&owner=user&redirect_uri=${encodeURIComponent(notionRedirectUri)}&state=${oauthStateKey}`

      res.redirect(notionAuthUrl)
    })

    // ── Notion OAuth Callback (chained from /oauth/authorize) ─────
    // Notion redirects here after user authorizes. We exchange the
    // Notion code, store the token, create an MCP auth code, and
    // redirect back to Claude.ai's callback.

    app.get('/oauth/notion-callback', async (req, res) => {
      const notionCode = req.query.code as string | undefined
      const oauthStateKey = req.query.state as string | undefined
      const error = req.query.error as string | undefined

      if (error || !notionCode || !oauthStateKey) {
        res.status(400).send(`<h2>Authorization failed</h2><p>${error || 'Missing code or state'}</p>`)
        return
      }

      const pending = pendingOAuthStates[oauthStateKey]
      if (!pending) {
        res.status(400).send('<h2>Invalid or expired authorization request</h2>')
        return
      }
      delete pendingOAuthStates[oauthStateKey]

      try {
        // Exchange Notion code for Notion access token
        const notionRedirectUri = `${PUBLIC_URL}/oauth/notion-callback`
        const basicAuth = Buffer.from(`${NOTION_CLIENT_ID}:${NOTION_CLIENT_SECRET}`).toString('base64')

        const tokenRes = await fetch('https://api.notion.com/v1/oauth/token', {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${basicAuth}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            grant_type: 'authorization_code',
            code: notionCode,
            redirect_uri: notionRedirectUri,
          }),
        })

        if (!tokenRes.ok) {
          const errBody = await tokenRes.text()
          console.error('Notion token exchange failed:', errBody)
          res.status(500).send(`<h2>Notion token exchange failed</h2><pre>${errBody}</pre>`)
          return
        }

        const tokenData = await tokenRes.json() as {
          access_token: string
          workspace_name?: string
          bot_id?: string
          owner?: { user?: { name?: string; person?: { email?: string } } }
        }

        // Store the Notion token under an nmc_ key
        const userKey = `nmc_${randomBytes(24).toString('hex')}`
        const store = loadStore()
        const ownerName = tokenData.owner?.user?.name || tokenData.owner?.user?.person?.email || 'unknown'
        store.users[userKey] = {
          notionToken: tokenData.access_token,
          workspaceName: tokenData.workspace_name,
          botId: tokenData.bot_id,
          owner: ownerName,
          createdAt: new Date().toISOString(),
        }

        // Create an MCP authorization code
        const mcpCode = randomBytes(32).toString('base64url')
        store.authCodes[mcpCode] = {
          code: mcpCode,
          clientId: pending.clientId,
          redirectUri: pending.redirectUri,
          scope: pending.scope,
          codeChallenge: pending.codeChallenge,
          codeChallengeMethod: pending.codeChallengeMethod,
          userKey,
          expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
          used: false,
        }
        saveStore(store)

        console.log(`OAuth flow complete for ${ownerName} (workspace: ${tokenData.workspace_name})`)

        // Redirect back to Claude.ai with the authorization code
        const redirectUrl = new URL(pending.redirectUri)
        redirectUrl.searchParams.set('code', mcpCode)
        if (pending.state) {
          redirectUrl.searchParams.set('state', pending.state)
        }

        res.redirect(redirectUrl.toString())
      } catch (err) {
        console.error('OAuth notion-callback error:', err)
        res.status(500).send(`<h2>Something went wrong</h2><pre>${err}</pre>`)
      }
    })

    // ── OAuth Token Endpoint ──────────────────────────────────────
    // Claude.ai exchanges the authorization code for an access token.

    app.post('/oauth/token', async (req, res) => {
      // Support both form-encoded and JSON
      const grant_type = req.body.grant_type
      const code = req.body.code
      const redirect_uri = req.body.redirect_uri
      const code_verifier = req.body.code_verifier
      const refresh_token = req.body.refresh_token

      // Extract client credentials (from body or Basic auth header)
      let clientId = req.body.client_id as string | undefined
      let clientSecret = req.body.client_secret as string | undefined

      const authHeader = req.headers['authorization']
      if (authHeader?.startsWith('Basic ')) {
        try {
          const decoded = Buffer.from(authHeader.slice(6), 'base64').toString()
          const [hId, hSecret] = decoded.split(':', 2)
          if (hId) clientId = hId
          if (hSecret) clientSecret = hSecret
        } catch { /* ignore malformed */ }
      }

      if (!clientId) {
        res.status(400).json({ error: 'invalid_request', error_description: 'client_id required' })
        return
      }

      const store = loadStore()
      const client = store.oauthClients[clientId]
      if (!client) {
        res.status(401).json({ error: 'invalid_client' })
        return
      }

      // Validate client secret (if provided — public clients may not send one)
      if (clientSecret) {
        const providedHash = hashToken(clientSecret)
        if (providedHash !== client.clientSecretHash) {
          res.status(401).json({ error: 'invalid_client' })
          return
        }
      }

      if (grant_type === 'authorization_code') {
        if (!code || !redirect_uri) {
          res.status(400).json({ error: 'invalid_request', error_description: 'code and redirect_uri required' })
          return
        }

        const authCode = store.authCodes[code]
        if (!authCode) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' })
          return
        }

        if (authCode.used) {
          delete store.authCodes[code]
          saveStore(store)
          res.status(400).json({ error: 'invalid_grant', error_description: 'Code already used' })
          return
        }

        if (authCode.clientId !== clientId) {
          res.status(400).json({ error: 'invalid_grant' })
          return
        }

        if (authCode.redirectUri !== redirect_uri) {
          res.status(400).json({ error: 'invalid_grant' })
          return
        }

        if (authCode.expiresAt < Date.now()) {
          delete store.authCodes[code]
          saveStore(store)
          res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' })
          return
        }

        // PKCE verification
        if (code_verifier) {
          const expectedChallenge = createHash('sha256')
            .update(code_verifier)
            .digest('base64url')

          if (expectedChallenge !== authCode.codeChallenge) {
            console.error('PKCE verification failed')
            res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' })
            return
          }
        } else if (authCode.codeChallenge) {
          // PKCE was used in authorize but verifier not provided
          res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' })
          return
        }

        // Mark code as used
        authCode.used = true

        // Issue MCP access token + refresh token
        const rawAccessToken = randomBytes(48).toString('base64url')
        const rawRefreshToken = randomBytes(48).toString('base64url')
        const accessHash = hashToken(rawAccessToken)
        const refreshHash = hashToken(rawRefreshToken)

        store.mcpTokens[accessHash] = {
          tokenHash: accessHash,
          userKey: authCode.userKey,
          clientId,
          scope: authCode.scope,
          expiresAt: Date.now() + 3600 * 1000, // 1 hour
          refreshTokenHash: refreshHash,
        }

        // Clean up used code
        delete store.authCodes[code]
        saveStore(store)

        console.log(`Issued MCP access token for user key ${authCode.userKey.slice(0, 12)}...`)

        res.json({
          access_token: rawAccessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: rawRefreshToken,
          scope: authCode.scope,
        })
        return
      }

      if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token required' })
          return
        }

        const refreshHash = hashToken(refresh_token)

        // Find the token with this refresh hash
        let oldToken: McpAccessToken | undefined
        let oldHash: string | undefined
        for (const [hash, token] of Object.entries(store.mcpTokens)) {
          if (token.refreshTokenHash === refreshHash) {
            oldToken = token
            oldHash = hash
            break
          }
        }

        if (!oldToken || !oldHash) {
          res.status(400).json({ error: 'invalid_grant' })
          return
        }

        if (oldToken.clientId !== clientId) {
          res.status(400).json({ error: 'invalid_client' })
          return
        }

        // Issue new tokens (rotation)
        const rawAccessToken = randomBytes(48).toString('base64url')
        const rawRefreshToken = randomBytes(48).toString('base64url')
        const newAccessHash = hashToken(rawAccessToken)
        const newRefreshHash = hashToken(rawRefreshToken)

        store.mcpTokens[newAccessHash] = {
          tokenHash: newAccessHash,
          userKey: oldToken.userKey,
          clientId,
          scope: oldToken.scope,
          expiresAt: Date.now() + 3600 * 1000,
          refreshTokenHash: newRefreshHash,
        }

        // Delete old token
        delete store.mcpTokens[oldHash]
        saveStore(store)

        console.log(`Refreshed MCP token for user key ${oldToken.userKey.slice(0, 12)}...`)

        res.json({
          access_token: rawAccessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: rawRefreshToken,
          scope: oldToken.scope,
        })
        return
      }

      res.status(400).json({ error: 'unsupported_grant_type' })
    })

    // ── Legacy Notion OAuth (direct, for Cursor/Claude Code) ──────
    if (NOTION_CLIENT_ID && NOTION_CLIENT_SECRET) {
      app.get('/auth/notion', (req, res) => {
        const redirectUri = `${PUBLIC_URL}/auth/notion/callback`
        const url = `https://api.notion.com/v1/oauth/authorize?client_id=${NOTION_CLIENT_ID}&response_type=code&owner=user&redirect_uri=${encodeURIComponent(redirectUri)}`
        res.redirect(url)
      })

      app.get('/auth/notion/callback', async (req, res) => {
        const code = req.query.code as string | undefined
        const error = req.query.error as string | undefined

        if (error || !code) {
          res.status(400).send(`<h2>Authorization failed</h2><p>${error || 'No code received'}</p>`)
          return
        }

        try {
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

          const userKey = `nmc_${randomBytes(24).toString('hex')}`
          const store = loadStore()
          const ownerName = tokenData.owner?.user?.name || tokenData.owner?.user?.person?.email || 'unknown'
          store.users[userKey] = {
            notionToken: tokenData.access_token,
            workspaceName: tokenData.workspace_name,
            botId: tokenData.bot_id,
            owner: ownerName,
            createdAt: new Date().toISOString(),
          }
          saveStore(store)

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
  </div>
</body></html>`)
        } catch (err) {
          console.error('OAuth callback error:', err)
          res.status(500).send(`<h2>Something went wrong</h2><pre>${err}</pre>`)
        }
      })

      console.log(`Notion OAuth (direct): ${PUBLIC_URL}/auth/notion`)
    }

    // ── MCP Auth Middleware ────────────────────────────────────────
    // Supports: admin token, nmc_ keys, and OAuth 2.1 bearer tokens.
    // Returns 401 with WWW-Authenticate for Claude.ai OAuth discovery.

    const authenticateAndResolveToken = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
      const authHeader = req.headers['authorization']
      const token = authHeader && authHeader.split(' ')[1]

      if (!token) {
        // Return 401 with resource_metadata for OAuth 2.1 discovery
        res.status(401)
          .set('WWW-Authenticate', `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`)
          .json({
            jsonrpc: '2.0',
            error: { code: -32001, message: 'Unauthorized: Bearer token required' },
            id: null,
          })
        return
      }

      // 1. Admin token
      if (authToken && token === authToken) {
        next()
        return
      }

      // 2. Legacy nmc_ user key (from /auth/notion direct flow)
      if (token.startsWith('nmc_')) {
        const notionToken = lookupNotionToken(token)
        if (notionToken) {
          req.headers['x-notion-token'] = notionToken
          next()
          return
        }
      }

      // 3. MCP OAuth 2.1 access token
      const notionToken = lookupNotionTokenFromMcpToken(token)
      if (notionToken) {
        req.headers['x-notion-token'] = notionToken
        next()
        return
      }

      res.status(403).json({
        jsonrpc: '2.0',
        error: { code: -32002, message: 'Forbidden: Invalid bearer token' },
        id: null,
      })
    }

    // Apply auth to /mcp routes
    if (!options.disableAuth) {
      app.use('/mcp', authenticateAndResolveToken)
    }

    // ── MCP Transport ─────────────────────────────────────────────
    const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {}

    app.post('/mcp', async (req, res) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        let transport: StreamableHTTPServerTransport

        if (sessionId && transports[sessionId]) {
          transport = transports[sessionId]
        } else if (!sessionId && isInitializeRequest(req.body)) {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId) => {
              transports[sessionId] = transport
            }
          })

          transport.onclose = () => {
            if (transport.sessionId) {
              delete transports[transport.sessionId]
            }
          }

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
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: null,
          })
          return
        }

        await transport.handleRequest(req, res, req.body)
      } catch (error) {
        console.error('Error handling MCP request:', error)
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          })
        }
      }
    })

    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID')
        return
      }
      await transports[sessionId].handleRequest(req, res)
    })

    app.delete('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined
      if (!sessionId || !transports[sessionId]) {
        res.status(400).send('Invalid or missing session ID')
        return
      }
      await transports[sessionId].handleRequest(req, res)
    })

    // ── Start ─────────────────────────────────────────────────────
    const port = options.port
    app.listen(port, '0.0.0.0', () => {
      console.log(`MCP Server listening on port ${port}`)
      console.log(`Endpoint: ${PUBLIC_URL}/mcp`)
      console.log(`Health: ${PUBLIC_URL}/health`)
      console.log(`OAuth metadata: ${PUBLIC_URL}/.well-known/oauth-authorization-server`)
      if (NOTION_CLIENT_ID) {
        console.log(`OAuth authorize: ${PUBLIC_URL}/oauth/authorize`)
        console.log(`Direct auth: ${PUBLIC_URL}/auth/notion`)
      }
    })

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
