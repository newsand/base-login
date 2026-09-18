# Guia de Integração — LoginBuskar

Guia para clientes (front-ends, BFFs, apps mobile) consumirem o serviço de autenticação.

**Escopo do serviço:** identidade via JWT. O LoginBuskar **não** gerencia roles, permissões ou RBAC — isso é responsabilidade do sistema que consome o JWT (Buskar, Vistoria, etc.).

---

## Índice

1. [Visão Geral dos Tokens](#visão-geral-dos-tokens)
2. [Armazenamento de Tokens](#armazenamento-de-tokens)
3. [Fluxo: Login](#fluxo-login)
4. [Fluxo: Refresh com Proteção contra Loop Infinito](#fluxo-refresh-com-proteção-contra-loop-infinito)
5. [Fluxo: Login com 2FA](#fluxo-login-com-2fa)
6. [Fluxo: Recuperação de Senha](#fluxo-recuperação-de-senha)
7. [Fluxo: Invite (Accept)](#fluxo-invite-accept)
8. [Fluxo: Magic Link](#fluxo-magic-link)
9. [Service Key — Uso Exclusivo Server-Side](#service-key--uso-exclusivo-server-side)
10. [Impacto de Usuário Desabilitado](#impacto-de-usuário-desabilitado)
11. [Referência de Erros](#referência-de-erros)
12. [Anti-Patterns (Checklist)](#anti-patterns-checklist)

---

## Visão Geral dos Tokens

| Token | Tipo | TTL | Uso |
|-------|------|-----|-----|
| `access_token` | JWT (HS256) | 15 minutos | Header `Authorization: Bearer <token>` em toda requisição protegida |
| `refresh_token` | Opaco (hex) | 14 dias | Único uso: obter novo par de tokens via `/v1/auth/refresh` |

**Rotação obrigatória:** cada uso do `refresh_token` o invalida e emite um novo par. Se um `refresh_token` já usado for apresentado novamente, o servidor revoga **toda a família** de tokens daquela sessão (proteção contra roubo).

### Estrutura do Access JWT

```json
{
  "sub": "uuid-v4-do-usuario",
  "iat": 1726664400,
  "exp": 1726665300,
  "jti": "uuid-v4-do-token",
  "2fa_verified": true
}
```

- `sub`: ID do usuário (use para correlacionar com seu sistema de roles)
- `2fa_verified`: sempre `true` se o token foi emitido (nunca emite sem 2FA verificado quando habilitado)

---

## Armazenamento de Tokens

### Recomendação Padrão: BFF com Cookie HttpOnly

Se sua arquitetura permite um Backend-For-Frontend (Node, Go, Python entre o browser e APIs), armazene o `refresh_token` em cookie HttpOnly+Secure+SameSite=Strict. O BFF faz o refresh e repassa apenas o `access_token` (curto) para o front.

**Vantagens:**
- XSS não consegue ler o refresh token
- CSRF mitigado por SameSite

### Alternativa SPA (sem BFF): Memory + localStorage

Se não há BFF, armazene:
- `access_token` em memória (variável JavaScript)
- `refresh_token` em `localStorage` (persistência entre refreshes de página)

**⚠️ Risco:** `localStorage` é acessível via XSS. Se seu app tiver vulnerabilidade XSS, o atacante pode exfiltrar o refresh token. Mitigue com CSP rigoroso e sanitização de inputs.

```javascript
// Exemplo simplificado
let accessToken = null;

function storeTokens(tokens) {
  accessToken = tokens.access_token;
  localStorage.setItem('refresh_token', tokens.refresh_token);
}

function clearTokens() {
  accessToken = null;
  localStorage.removeItem('refresh_token');
}
```

---

## Fluxo: Login

### Passos

1. Usuário submete email + senha
2. POST `/v1/auth/login`
3. **Se 2FA desabilitado:** recebe tokens → armazena → usuário autenticado
4. **Se 2FA habilitado:** recebe `requires_2fa: true` → segue para [Fluxo 2FA](#fluxo-login-com-2fa)

### Request

```bash
curl -X POST https://auth.example.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@exemplo.com",
    "password": "senhasegura123"
  }'
```

### Response — Sucesso (sem 2FA)

```http
HTTP/1.1 200 OK
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Response — Requer 2FA

```http
HTTP/1.1 200 OK
```
```json
{
  "requires_2fa": true,
  "challenge_token": "f7e8d9c0b1a2..."
}
```

### Response — Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request"}` | JSON malformado ou campos ausentes |
| 401 | `{"error": "invalid credentials"}` | Email não existe, senha incorreta, ou conta sem senha definida |
| 401 | `{"error": "account disabled"}` | Conta desabilitada pelo admin |
| 429 | `{"error": "account temporarily locked"}` | Muitas tentativas falhas (lockout) |
| 500 | `{"error": "internal error"}` | Erro interno |

### Diagrama de Sequência

```
┌────────┐          ┌────────────┐
│ Client │          │ LoginBuskar│
└───┬────┘          └─────┬──────┘
    │  POST /v1/auth/login│
    │  {email, password}  │
    │────────────────────>│
    │                     │
    │   [2FA desabilitado]│
    │<────────────────────│
    │   {access_token,    │
    │    refresh_token,   │
    │    token_type,      │
    │    expires_in}      │
    │                     │
    │   [2FA habilitado]  │
    │<────────────────────│
    │   {requires_2fa,    │
    │    challenge_token} │
    ▼                     ▼
```

---

## Fluxo: Refresh com Proteção contra Loop Infinito

O refresh token renova o access token antes/após expiração. **Crítico:** implemente proteção contra loop infinito de refresh.

### Algoritmo Obrigatório

```
QUANDO receber 401 em qualquer requisição protegida:
  SE já estou fazendo refresh (flag isRefreshing = true):
    → NÃO tente refresh novamente
    → Falhe a requisição original
  
  SE refresh já falhou nesta sessão (flag refreshFailed = true):
    → logout() → limpa tokens → redireciona para login
    → NÃO tente refresh
  
  SENÃO:
    → isRefreshing = true
    → tenta POST /v1/auth/refresh
    
    SE refresh sucesso:
      → armazena novos tokens
      → isRefreshing = false
      → retry da requisição original (UMA vez só)
    
    SE refresh falha (401):
      → refreshFailed = true
      → isRefreshing = false
      → logout() → limpa tokens → redireciona para login
```

### Implementação de Referência (JavaScript/TypeScript)

```javascript
let isRefreshing = false;
let refreshFailed = false;
let pendingRequests = [];

async function fetchWithAuth(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (response.status === 401 && !options._isRetry) {
    return handleUnauthorized(url, options);
  }

  return response;
}

async function handleUnauthorized(url, options) {
  // Já falhou refresh nesta sessão? Logout.
  if (refreshFailed) {
    logout();
    throw new Error('Session expired');
  }

  // Já está fazendo refresh? Espera na fila.
  if (isRefreshing) {
    return new Promise((resolve, reject) => {
      pendingRequests.push({ resolve, reject, url, options });
    });
  }

  isRefreshing = true;

  try {
    const newTokens = await refreshTokens();
    storeTokens(newTokens);
    isRefreshing = false;

    // Processa fila de requisições pendentes
    pendingRequests.forEach(({ resolve, url, options }) => {
      resolve(fetchWithAuth(url, { ...options, _isRetry: true }));
    });
    pendingRequests = [];

    // Retry da requisição original
    return fetchWithAuth(url, { ...options, _isRetry: true });

  } catch (error) {
    isRefreshing = false;
    refreshFailed = true;

    // Rejeita todas as pendentes
    pendingRequests.forEach(({ reject }) => reject(error));
    pendingRequests = [];

    logout();
    throw error;
  }
}

async function refreshTokens() {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    throw new Error('No refresh token');
  }

  const response = await fetch('https://auth.example.com/v1/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    throw new Error('Refresh failed');
  }

  return response.json();
}

function logout() {
  clearTokens();
  refreshFailed = false;
  window.location.href = '/login';
}
```

### Request Refresh

```bash
curl -X POST https://auth.example.com/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4e5f6..."
  }'
```

### Response — Sucesso

```http
HTTP/1.1 200 OK
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "novo-token-opaco...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**⚠️ Importante:** O `refresh_token` retornado é **diferente** do enviado. Descarte o antigo imediatamente.

### Response — Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request"}` | JSON malformado ou campo ausente |
| 401 | `{"error": "invalid refresh token"}` | Token não encontrado, já usado, ou reuse detectado |
| 401 | `{"error": "refresh token expired"}` | TTL expirado (14 dias) |
| 401 | `{"error": "account disabled"}` | Usuário foi desabilitado após login |
| 500 | `{"error": "internal error"}` | Erro interno |

---

## Fluxo: Login com 2FA

Quando o usuário tem 2FA habilitado, o login retorna um `challenge_token` ao invés de tokens. O cliente deve coletar o código TOTP e enviá-lo.

### Passos

1. POST `/v1/auth/login` → recebe `{"requires_2fa": true, "challenge_token": "..."}`
2. Exibe tela de entrada do código (6 dígitos do app autenticador)
3. POST `/v1/auth/2fa/verify` com `challenge_token` + `code`
4. Recebe tokens → armazena → usuário autenticado

### Request

```bash
curl -X POST https://auth.example.com/v1/auth/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_token": "f7e8d9c0b1a2...",
    "code": "123456"
  }'
```

### Response — Sucesso

```http
HTTP/1.1 200 OK
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Response — Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request"}` | JSON malformado ou campos ausentes |
| 401 | `{"error": "invalid or expired challenge"}` | Challenge não encontrado ou expirado (TTL: 5 min) |
| 401 | `{"error": "2FA not enabled"}` | Usuário não tem 2FA habilitado |
| 401 | `{"error": "invalid code"}` | Código TOTP incorreto |
| 500 | `{"error": "internal error"}` | Erro interno |

### Diagrama de Sequência

```
┌────────┐          ┌────────────┐          ┌───────────────┐
│ Client │          │ LoginBuskar│          │ Authenticator │
└───┬────┘          └─────┬──────┘          └───────┬───────┘
    │  POST /v1/auth/login│                         │
    │────────────────────>│                         │
    │                     │                         │
    │  {requires_2fa,     │                         │
    │   challenge_token}  │                         │
    │<────────────────────│                         │
    │                     │                         │
    │  Usuário abre app   │                         │
    │─────────────────────────────────────────────> │
    │                     │                         │
    │  Código TOTP        │                         │
    │<─────────────────────────────────────────────│
    │                     │                         │
    │  POST /v1/auth/2fa/verify                     │
    │  {challenge_token, code}                      │
    │────────────────────>│                         │
    │                     │                         │
    │  {access_token,     │                         │
    │   refresh_token...} │                         │
    │<────────────────────│                         │
    ▼                     ▼                         ▼
```

---

## Fluxo: Recuperação de Senha

### Passos

1. Usuário clica "Esqueci minha senha"
2. POST `/v1/password/forgot` com email
3. **Resposta sempre sucesso** (não revela se email existe)
4. Se email existe, usuário recebe link OOB (email) com token
5. Usuário clica no link, front extrai o token
6. POST `/v1/password/reset` com token + nova senha
7. Todos os refresh tokens são revogados → usuário deve fazer login novamente

### Request — Forgot

```bash
curl -X POST https://auth.example.com/v1/password/forgot \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@exemplo.com"
  }'
```

### Response — Forgot (sempre 200)

```http
HTTP/1.1 200 OK
```
```json
{
  "message": "if the email exists, a recovery link will be sent"
}
```

### Request — Reset

```bash
curl -X POST https://auth.example.com/v1/password/reset \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456...",
    "new_password": "novasenhasegura123"
  }'
```

### Response — Reset Sucesso

```http
HTTP/1.1 200 OK
```
```json
{
  "message": "password reset successful"
}
```

### Response — Reset Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request", "details": "..."}` | JSON malformado ou senha < 8 chars |
| 401 | `{"error": "invalid or expired token"}` | Token não encontrado, já usado, ou expirado (TTL: 1h) |
| 500 | `{"error": "internal error"}` | Erro interno |

---

## Fluxo: Invite (Accept)

Convites são criados por sistemas externos via service key. O usuário recebe um link OOB (email) e aceita definindo sua senha.

### Passos

1. Admin/sistema cria invite via `POST /v1/invites` (service key)
2. Usuário recebe email com link contendo token
3. Front coleta senha (obrigatória) e nome (opcional)
4. POST `/v1/invites/accept` com token + password + nome
5. Conta ativada → usuário pode fazer login

### Request

```bash
curl -X POST https://auth.example.com/v1/invites/accept \
  -H "Content-Type: application/json" \
  -d '{
    "token": "convite-token-abc123...",
    "password": "senhasegura123",
    "nome": "Nome do Usuário"
  }'
```

### Response — Sucesso

```http
HTTP/1.1 200 OK
```
```json
{
  "message": "account activated",
  "user_id": "uuid-v4-do-usuario"
}
```

**Nota:** O accept **não** retorna tokens. Após aceitar, o usuário deve fazer login normalmente.

### Response — Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request", "details": "..."}` | JSON malformado ou senha < 8 chars |
| 401 | `{"error": "invalid or expired invite"}` | Token não encontrado, já usado, ou expirado (TTL: 7 dias) |
| 409 | `{"error": "account already exists"}` | Conta já existe com senha definida |
| 500 | `{"error": "internal error"}` | Erro interno |

---

## Fluxo: Magic Link

Magic link permite login sem senha para usuários existentes com senha já definida.

### Restrições

- **Não cria conta:** apenas usuários já existentes e ativos
- **Requer senha definida:** contas que só receberam invite mas nunca aceitaram não podem usar magic link
- **2FA ainda exigido:** se o usuário tem 2FA habilitado, após consumir o magic link ainda precisa do código TOTP

### Passos

1. Usuário informa email
2. POST `/v1/auth/magic-link` → **sempre 200** (não revela se email existe)
3. Se email existe, usuário recebe link OOB (email)
4. Front extrai token e POST `/v1/auth/magic-link/consume`
5. **Se 2FA desabilitado:** recebe tokens → autenticado
6. **Se 2FA habilitado:** recebe `requires_2fa` → segue para verificação TOTP

### Request — Solicitar Magic Link

```bash
curl -X POST https://auth.example.com/v1/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@exemplo.com"
  }'
```

### Response — Solicitar (sempre 200)

```http
HTTP/1.1 200 OK
```
```json
{
  "message": "if the email exists, a magic link will be sent"
}
```

### Request — Consumir Magic Link

```bash
curl -X POST https://auth.example.com/v1/auth/magic-link/consume \
  -H "Content-Type: application/json" \
  -d '{
    "token": "magic-token-xyz789..."
  }'
```

### Response — Consumir Sucesso (sem 2FA)

```http
HTTP/1.1 200 OK
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Response — Consumir com 2FA

```http
HTTP/1.1 200 OK
```
```json
{
  "requires_2fa": true,
  "challenge_token": "f7e8d9c0b1a2..."
}
```

Após receber `requires_2fa`, siga o [Fluxo 2FA](#fluxo-login-com-2fa) com o `challenge_token`.

### Response — Consumir Erros

| HTTP | Body | Causa |
|------|------|-------|
| 400 | `{"error": "invalid request"}` | JSON malformado ou campo ausente |
| 401 | `{"error": "invalid or expired token"}` | Token não encontrado, já usado, expirado (TTL: 15 min), ou usuário desabilitado |
| 500 | `{"error": "internal error"}` | Erro interno |

### Diagrama de Sequência

```
┌────────┐          ┌────────────┐          ┌───────┐
│ Client │          │ LoginBuskar│          │ Email │
└───┬────┘          └─────┬──────┘          └───┬───┘
    │  POST /v1/auth/magic-link                 │
    │  {email}            │                     │
    │────────────────────>│                     │
    │                     │                     │
    │  {"message":        │  [se existe]        │
    │   "if the email..."}│  envia magic link   │
    │<────────────────────│────────────────────>│
    │                     │                     │
    │                     │                     │
    │  Usuário clica link │                     │
    │<─────────────────────────────────────────│
    │                     │                     │
    │  POST /v1/auth/magic-link/consume         │
    │  {token}            │                     │
    │────────────────────>│                     │
    │                     │                     │
    │  [sem 2FA]          │                     │
    │  {access_token...}  │                     │
    │<────────────────────│                     │
    │                     │                     │
    │  [com 2FA]          │                     │
    │  {requires_2fa,     │                     │
    │   challenge_token}  │                     │
    │<────────────────────│                     │
    ▼                     ▼                     ▼
```

---

## Service Key — Uso Exclusivo Server-Side

**⚠️ CRÍTICO: Service keys NUNCA devem estar no browser, app mobile, ou qualquer código client-side.**

Service keys são segredos de máquina para sistemas backend chamarem CRUD e invite. Se vazarem, um atacante pode criar/desabilitar usuários arbitrários.

### Uso Correto

```
┌──────────┐       ┌─────────────┐       ┌────────────┐
│ Browser  │──────>│ Seu Backend │──────>│ LoginBuskar│
│ (SPA)    │       │ (BFF/API)   │       │            │
└──────────┘       └─────────────┘       └────────────┘
     │                   │                     │
     │ request sem       │ Authorization:      │
     │ service key       │ Bearer <SERVICE_KEY>│
     │                   │                     │
```

### Endpoints que Requerem Service Key

- `POST /v1/users` — criar usuário
- `GET /v1/users` — listar usuários
- `GET /v1/users/:id` — obter usuário
- `PATCH /v1/users/:id` — atualizar/desabilitar usuário
- `POST /v1/invites` — criar convite

### Exemplo Server-Side (Node.js)

```javascript
// Backend (Node.js) — NUNCA exponha isso ao front
const SERVICE_KEY = process.env.AUTH_SERVICE_KEY;

async function createInvite(email) {
  const response = await fetch('https://auth.example.com/v1/invites', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${SERVICE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email }),
  });
  
  return response.json();
}
```

---

## Impacto de Usuário Desabilitado

Quando um admin desabilita um usuário via `PATCH /v1/users/:id` com `disabled_at`:

| Token | Comportamento |
|-------|---------------|
| `refresh_token` | **Revogado imediatamente** — qualquer tentativa de refresh retorna 401 `account disabled` |
| `access_token` | **Permanece válido até TTL** (~15 min) — o middleware não re-verifica `disabled_at` a cada request |

### Implicações para o Cliente

1. **Logout não é instantâneo:** Um usuário desabilitado pode continuar usando o sistema por até 15 minutos com um access token já emitido.

2. **Para forçar logout imediato** em sistemas críticos, considere:
   - Reduzir `ACCESS_TOKEN_TTL` (trade-off: mais refreshes)
   - Implementar blacklist de `jti` no seu sistema (fora do escopo deste serviço)
   - Aceitar o delay de 15 minutos (adequado para maioria dos casos)

3. **Refresh falha imediatamente:** Mesmo com access válido, o usuário não conseguirá renovar. Após expirar, será forçado a fazer login (que falhará).

---

## Referência de Erros

### Erros de Autenticação (401)

| Erro | Endpoint(s) | Significado |
|------|-------------|-------------|
| `missing authorization header` | Qualquer protegido | Header `Authorization` ausente |
| `invalid authorization header` | Qualquer protegido | Formato inválido (esperado: `Bearer <token>`) |
| `invalid token` | Qualquer com JWT | JWT inválido, expirado, ou assinatura incorreta |
| `invalid service key` | CRUD/Invites | Service key não reconhecida |
| `invalid credentials` | Login, 2FA disable | Email/senha incorretos |
| `account disabled` | Login, Refresh | Conta desabilitada |
| `invalid refresh token` | Refresh | Token não encontrado ou já usado |
| `refresh token expired` | Refresh | TTL expirado |
| `invalid or expired token` | Magic consume, Reset | Token one-shot inválido/expirado/usado |
| `invalid or expired challenge` | 2FA verify | Challenge expirado (5 min) |
| `invalid or expired invite` | Accept invite | Convite inválido/expirado/usado |
| `invalid code` | 2FA verify/enable | Código TOTP incorreto |
| `2FA not enabled` | 2FA verify | Usuário não tem 2FA |

### Erros de Validação (400)

| Erro | Significado |
|------|-------------|
| `invalid request` | JSON malformado ou campos obrigatórios ausentes |
| `password must be at least 8 characters` | Senha muito curta |
| `password or code required` | 2FA disable sem autenticação |
| `2FA already enabled` | Tentativa de habilitar 2FA já ativo |
| `2FA not enabled` | Tentativa de desabilitar 2FA inativo |
| `setup 2FA first by calling without code` | Enable 2FA com código antes de gerar secret |

### Erros de Conflito (409)

| Erro | Significado |
|------|-------------|
| `email already exists` | Email já cadastrado |
| `account already exists` | Invite para conta já ativa |

### Outros

| HTTP | Erro | Significado |
|------|------|-------------|
| 404 | `user not found` | ID de usuário não existe |
| 429 | `account temporarily locked` | Lockout por tentativas falhas |
| 500 | `internal error` | Erro interno do servidor |

---

## Anti-Patterns (Checklist)

Use esta lista para code review de integrações:

### ❌ Service Key no Client-Side

```javascript
// ERRADO — nunca faça isso
const response = await fetch('/v1/users', {
  headers: { 'Authorization': `Bearer ${VITE_SERVICE_KEY}` } // ← VAZOU
});
```

**Correção:** Mova chamadas CRUD para seu backend.

### ❌ Loop Infinito de Refresh

```javascript
// ERRADO — pode loopar para sempre
async function fetchWithAuth(url) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` }});
  if (res.status === 401) {
    await refresh(); // e se refresh também der 401?
    return fetchWithAuth(url); // loop infinito!
  }
}
```

**Correção:** Use flags `isRefreshing` e `refreshFailed` como mostrado na seção [Refresh](#fluxo-refresh-com-proteção-contra-loop-infinito).

### ❌ Ignorar `requires_2fa`

```javascript
// ERRADO — assume que login sempre retorna tokens
const { access_token } = await login(email, password);
localStorage.setItem('token', access_token); // undefined se 2FA!
```

**Correção:** Verifique `requires_2fa` antes de acessar tokens.

```javascript
const result = await login(email, password);
if (result.requires_2fa) {
  redirectTo2FA(result.challenge_token);
} else {
  storeTokens(result);
}
```

### ❌ Tratar Magic Link 200 como Erro

```javascript
// ERRADO — 200 não significa que email existe
const res = await requestMagicLink(email);
if (res.message.includes('will be sent')) {
  showSuccess('Enviamos o link!'); // ← OK
} else {
  showError('Email não encontrado'); // ← NUNCA acontece, sempre 200
}
```

**Correção:** Sempre exiba mensagem genérica de sucesso. A API nunca revela se o email existe.

### ❌ Não Descartar Refresh Token Antigo

```javascript
// ERRADO — guarda token que já foi invalidado
const newTokens = await refresh(oldRefreshToken);
tokens.push(newTokens.refresh_token); // acumula tokens inválidos!
```

**Correção:** Substitua, não acumule.

```javascript
const newTokens = await refresh(currentRefreshToken);
currentRefreshToken = newTokens.refresh_token; // substitui
```

### ❌ Retry Infinito no 401

```javascript
// ERRADO — retenta para sempre
async function fetchWithRetry(url, retries = Infinity) {
  // ...
}
```

**Correção:** Máximo 1 retry após refresh bem-sucedido. Se refresh falhar, logout.

### ❌ Refresh Sem Verificar se Já Está em Andamento

```javascript
// ERRADO — múltiplos refreshes simultâneos
interceptor.onError = async (error) => {
  if (error.status === 401) {
    await refresh(); // 5 requests falham = 5 refreshes!
  }
};
```

**Correção:** Use mutex/flag `isRefreshing` e fila de requests pendentes.

---

## Logout

Para logout explícito do usuário:

### Request

```bash
curl -X POST https://auth.example.com/v1/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

### Response

```http
HTTP/1.1 200 OK
```
```json
{
  "message": "logged out"
}
```

O logout revoga todos os refresh tokens do usuário. O access token atual continua válido até expirar (stateless), mas não poderá ser renovado.

---

## GET /me

Obtém informações do usuário autenticado.

### Request

```bash
curl https://auth.example.com/v1/me \
  -H "Authorization: Bearer <access_token>"
```

### Response

```http
HTTP/1.1 200 OK
```
```json
{
  "id": "uuid-v4-do-usuario",
  "email": "usuario@exemplo.com",
  "nome": "Nome do Usuário",
  "2fa_enabled": false
}
```

**Nota:** Não retorna roles — autorização é responsabilidade do sistema que consome o JWT.
