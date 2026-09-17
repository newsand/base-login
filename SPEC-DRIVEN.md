# LoginBuskar / base-login — Spec-Driven Design (pré-código)

**Repo:** https://github.com/newsand/base-login  
**Produto:** serviço de identidade JWT (sem redirect, sem roles)  
**Canônico de produto:** `AUTH-MVP.md` (mesma pasta / raiz do repo)

## 1. Problema

Fronts (Buskar, Vistoria, etc.) precisam autenticar usuários sem OAuth bounce. Um serviço único prova identidade e emite JWT; autorização fica nos produtos.

## 2. Fora / dentro

Ver `AUTH-MVP.md` §1. Resumo: login, refresh (rotação+reuse), logout, recover, magic link, invite, CRUD via service key, 2FA on/off opcional, rate limit/lockout, Postgres. Sem roles, sem signup aberto, sem redirect.

## 3. Arquitetura (obrigatória — enxuta)

**Proibido:** hexagonal, clean architecture, DDD, camadas repository/service genéricas, pastas `domain`/`usecase`/`infrastructure`.

**Permitido / desejado:**

- Separar por **feature** (`features/auth`, `features/users`, `features/health`, …), não por camada.
- Um `main.go` fino: carrega config, inicia singletons, registra rotas, sobe HTTP.
- **Logger singleton** — sem lib de log; `fmt`/`print` colorido no stdio; `LOG_LEVEL` env; `gin.ForceConsoleColor()`.
- **DBManager singleton** — Postgres; padrão Gin de config/DB; pool único.
- **GORM Active Record; no ORM/DB swap abstractions.**
- Rotas com **Router groups** do Gin (`/v1/auth`, `/v1/users`, …).
- Complexidade sobe só quando uma feature exige.

## 4. Stack

- Go **≥ 1.25** (versão mais recente estável disponível no build)
- Gin
- GORM (Postgres driver)
- Postgres
- Deploy: **Nixpacks** (homolog/prod)
- Local/test: **docker compose** = app + Postgres

## 5. Runtime

- No startup: logar **versão do código** (ex. git describe / `VERSION` file).
- `GET /health` (ou `/v1/health`): liveness + **version = alfa** (string explícita `alfa` / `alpha` conforme README).
- Env: `PORT`, `DATABASE_URL`, `LOG_LEVEL`, `JWT_SECRET`, `SERVICE_KEYS` (dual), TTLs, mailer stub, bootstrap opcional.

## 6. Entregáveis no repo

1. `docs/` ou raiz: `AUTH-MVP.md` + este `SPEC-DRIVEN.md`
2. Código Go conforme §3–5 implementando o MVP
3. `README.md` = **manual de deploy e uso** (não essay de arquitetura)
4. `docker-compose.yml` (postgres + app)
5. Nixpacks (`nixpacks.toml` / o que for necessário) para homolog/prod
6. `.env.example`

## 7. Critério de pronto

- `docker compose up` sobe app+Postgres; health retorna versão alfa
- Login/refresh/logout/recover/magic/invite/CRUD(service key) batem com `AUTH-MVP.md`
- Sem pastas/camadas proibidas; features only
- Moriaty ataca o código contra `AUTH-MVP.md`

## 8. Decisões pós-MVP (registradas aqui para não parecer spec drift)

- **`POST /v1/invites` devolve o token no corpo quando `MAILER_STUB=true`** (`token` +
  `expires_at`, além de `message`/`email`). O invite continua sendo entregue OOB por
  contrato (§7 do `AUTH-MVP.md`); a diferença é só que, sem mailer real configurado, o
  serviço precisa devolver o valor pra quem chamou poder entregá-lo de outro jeito (ex.:
  montar o link do magic-link). Com `MAILER_STUB=false` o campo `token` não existe na
  resposta — o token volta a ser estritamente OOB, hash-only no DB como sempre foi.

## 9. Integração por produtos consumidores

Todo produto que usa este serviço para identidade (roles/dados ficam no produto, nunca
aqui) deve seguir o guia em `../doc-integracao/`, que documenta o padrão de integração
usado pelo `crazy-back`/`crazy-front` (JWT com segredo compartilhado, service key só no
backend do produto, fluxo de invite/magic-link ponta a ponta).
