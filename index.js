import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { MCPAuth, fetchServerConfig, MCPAuthTokenVerificationError } from 'mcp-auth';
import express from 'express';

const server = new McpServer({
  name: 'WhoAmI',
  version: '0.0.0',
});

const authIssuer = 'https://api.asgardeo.io/t/sagaraorg/oauth2/token';
const mcpAuth = new MCPAuth({
    server: await fetchServerConfig(authIssuer, { type: 'oidc' }),
});

const verifyToken = async (token) => {
    const { issuer, userinfoEndpoint } = mcpAuth.config.server.metadata;

    const response = await fetch(userinfoEndpoint, {
        headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
        throw new MCPAuthTokenVerificationError('token_verification_failed', response);
    }

    const userInfo = await response.json();

    if (typeof userInfo !== 'object' || userInfo === null || !('sub' in userInfo)) {
        throw new MCPAuthTokenVerificationError('invalid_token', response);
    }

    return {
        token,
        issuer,
        subject: String(userInfo.sub), 
        clientId: '', 
        scopes: [],
        claims: userInfo,
    };
};

server.tool('whoami', ({ authInfo }) => {
  return {
    content: [
      { type: 'text', text: JSON.stringify(authInfo?.claims ?? { error: 'Not authenticated' }) },
    ],
  };
});


const PORT = 3001;
const app = express();

app.use(mcpAuth.delegatedRouter());
app.use(mcpAuth.bearerAuth(verifyToken));

const transports = {};

app.get('/sse', async (_req, res) => {
  const transport = new SSEServerTransport('/messages', res);
  transports[transport.sessionId] = transport;

  res.on('close', () => {
    delete transports[transport.sessionId];
  });

  await server.connect(transport);
});

app.post('/messages', async (req, res) => {
  const sessionId = String(req.query.sessionId);
  const transport = transports[sessionId];
  if (transport) {
    await transport.handlePostMessage(req, res, req.body);
  } else {
    res.status(400).send('No transport found for sessionId');
  }
});

app.listen(PORT);