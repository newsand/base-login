# LoginBuskar — MVP enxuto (auth only)

**Status:** proposta fechada para ataque (2026-09-16)  
**Job do serviço:** provar quem é. Emite JWT. **Sem** redirect OAuth/SSO.  
**Não é job:** roles, permissões ou RBAC — isso fica **nos sistemas acessados** (Buskar, Vistoria, etc.). Este serviço só identidade + JWT.

---

## 1. Escopo

| Entra | Não entra (MVP) |
|---|---|
| DB de usuários | Multi-portal SSO / redirect |
| Login email+senha → access JWT + refresh | Hierarquia de parceiros |
| Refresh com política abaixo | Sessão unificada entre apps |
| Logout / revoke | Obrigar 2FA |
| Recover password (one-shot) | Autorização fina por portal |
| Flag `2fa_enabled` (default off) | Stub que emite access sem 2º fator se 2FA on |
| Rate limit + lockout (conta+IP) | Signup público aberto |
| CRUD usuários (service key) + invite + magic link | Roles / RBAC neste serviço |
| UUID por usuário | Signup público / verify-e-mail genérico |
| Política mínima de senha | “Sair de todos os devices” (próximo corte) |

---

## 2. Usuário (persistência mínima)

Campos MVP: `id` (**UUID v4** opaco, gerado na criação), `email` (único), `password_hash` (nullable até accept), `nome`, `telefone` (opcional), `cpf` (opcional), `2fa_enabled` (bool, default `false`), `2fa_secret` (nullable), `created_at`, `updated_at`, `disabled_at` (nullable).

**Sem coluna `roles`.** Papéis vivem nos produtos que consomem o JWT (`sub` = uuid).

**UUID:** todo user recebe UUID v4 na criação. **Não** embutir e-mail/tenant/papel dentro do UUID (vazamento + colisão + não rotaciona). Metadados vão em campos/tabelas; o `sub` do JWT é só o UUID. Se precisar ordenação temporal depois, ULID é ADR separado — MVP = UUID v4.

Senha: hash forte (Argon2id ou bcrypt cost alto). Nunca plaintext.

### Provisionamento (fechado)

**Sem signup público aberto.** Contas entram por:

1. **CRUD** (`/users` — create/read/update/disable; delete = soft `disabled_at`) — só **service key** (não há role admin neste serviço).
2. **Invite** — admin cria convite (e-mail + TTL one-shot) → usuário aceita (define senha ou segue magic link) → conta ativa. Não é cadastro aberto.
3. **Seed/API interna** quando outro sistema provisiona.

Verify-e-mail genérico fora; invite já prova o e-mail do destinatário ao consumir o token.

---

## 3. Claims do access JWT (fechado)

**Access token — claims mínimos:**

| Claim | Obrigatório | Notas |
|---|---|---|
| `sub` | sim | user id |
| `iat` / `exp` | sim | |
| `jti` | sim | id do access (revoke pontual opcional) |
| `2fa_verified` | sim | `true` se 2FA off **ou** após 2º fator ok; se `2fa_enabled` e ainda não verificou → **não emite access** |

**Papéis / tenant / portal: fora deste serviço e fora do access JWT.**  
Clientes chamam **`GET /me`** só para identidade (Bearer access).

### Shape mínimo de `GET /me` (fechado)

```json
{
  "id": "<uuid-v4>",
  "email": "user@example.com",
  "nome": "...",
  "2fa_enabled": false
}
```

- **Sem `roles`.** Autorização = responsabilidade do sistema que recebe o JWT.
- Rejeitado: `roles`/`tenant` no access JWT ou neste serviço.

---

## 4. Refresh — política (fechado)

| Regra | Valor MVP |
|---|---|
| Access TTL | **15 minutos** |
| Refresh TTL | **14 dias** |
| Armazenamento | refresh **opaco** no DB (só hash); nunca JWT longo como refresh |
| Rotação | **sim** — cada uso de refresh emite novo par access+refresh e **invalida** o refresh usado |
| Reuse detection | se refresh **já revogado/usado** for apresentado de novo → **revoga a família inteira** (todos os refresh do user ou da `family_id`) |
| Logout | revoga refresh atual (e opcionalmente família) |
| Família | cada login cria `family_id`; rotação mantém a família |

Sem essas regras, refresh = access eterno. Implementação deve ter testes para rotação e reuse.

---

## 5. Recover password (fechado)

1. `POST /password/forgot` com email → **sempre** responde 204/200 genérico (não vaza se email existe).  
2. Se user existe: gera token **one-shot** (opaco, só hash no DB), TTL **1 hora**, invalida tokens de recover anteriores do user.  
3. Entrega **out-of-band** (e-mail). Canal concreto = dependência de infra; contrato da API e do token ficam fechados mesmo se o mailer for stub em dev.  
4. `POST /password/reset` com token + nova senha → valida one-shot + TTL → troca hash → **consome** token → revoga **todas** as famílias de refresh do user.  
5. Sem token válido / expirado / reusado → erro genérico.

---

## 6. 2FA `on/off`

| `2fa_enabled` | Comportamento login |
|---|---|
| `false` (default) | email+senha → emite access (`2fa_verified=true`) + refresh |
| `true` | email+senha → **não** emite access; emite só desafio/ticket de curta duração → após TOTP/código ok → access + refresh |

Nesta versão: pode entregar só o **schema + ramo off completo** e o ramo on como “desafio obrigatório sem bypass”. Se o ramo on não estiver pronto, **não** ligar `2fa_enabled=true` em produção. Nunca emitir access com 2FA on sem o segundo fator.

**Enable/disable (por usuário):** `2fa_enabled=true` só após TOTP válido na ativação (senão tranca a conta). Disable exige reauth (senha **ou** TOTP) — session roubada não desliga 2FA.

---

## 7. Endpoints MVP (contrato)

- `POST /auth/login`  
- `POST /auth/refresh`  
- `POST /auth/logout`  
- `GET /me`  
- `POST /password/forgot`  
- `POST /password/reset`  
- CRUD usuários (service key): `GET/POST /users`, `GET/PATCH /users/:id` (disable via `disabled_at`)
- Invite: `POST /invites`, `POST /invites/accept`
- Magic link: `POST /auth/magic-link` (pede e-mail), `POST /auth/magic-link/consume` (token one-shot → JWT)
- (opcional v0.1) `POST /auth/2fa/verify`, `POST /me/2fa/enable|disable`

### Magic link (fechado)

- **Não cria conta.** Só user **já existente** e ativo; senão bypass de invite.
- Token opaco one-shot, TTL curto (**15 min**), só hash no DB.
- Pedido sempre genérico (não vaza se e-mail existe) + rate limit.
- User **sem senha definida** (só convidado, ainda não accept): magic **bloqueado** até accept do invite (evita conta zumbi).
- Consume → emite access+refresh; se `2fa_enabled`, ainda exige TOTP antes do access.
- Sem redirect OAuth; o front abre deep-link/URL própria e posta o token na API.

### Invite (fechado)

- One-shot + TTL (**7 dias**); e-mail OOB; só hash no DB.
- Token **amarra o e-mail**: accept com outro e-mail = rejeita.
- Novo invite para o mesmo e-mail **invalida** invites anteriores desse e-mail.
- Accept: cria/ativa user, define senha (obrigatório no accept se ainda sem senha); depois login ou magic liberados.
- Invite ≠ signup público: só quem recebeu token entra.
- Até o accept, login por senha falha (sem hash) e magic fica bloqueado.

### Bootstrap e quem chama o CRUD (fechado)

- **Sem role admin neste serviço.** Não existe “user admin” no LoginBuskar.
- **Service key:** segredo de máquina (não é senha de pessoa) que Buskar/Vistoria/ops usam pra chamar CRUD e invite. Header `Authorization: Bearer <service_key>`.
- **Bootstrap:** só configurar a service key (env); user seed opcional sem privilégio extra. CRUD nunca abre por JWT de usuário.
- **Key hygiene (fechado):** no mínimo **duas keys** ativas (current + previous) pra rotação sem downtime; revogar a antiga após trocar; escopo implícito do MVP = só mutações de user/invite neste serviço (não é JWT assinado pra fronts). Logar uso da key sem logar o valor.
- Produtos mapeiam `sub` → papéis no **próprio** banco.


Sem redirects / sem OAuth bounce. Cada front/sistema tem a própria tela de login e chama este serviço; **toda** chamada protegida usa `Authorization: Bearer <access>`. Sem JWT válido → 401. O auth não redireciona o browser de volta a lugar nenhum.

---

## 8. Critérios de aceite desta página

1. Job = identidade via JWT; **sem roles** neste serviço — autorização nos produtos.  
2. Refresh: TTL + rotação + reuse → revoke família.  
3. Recover: one-shot + TTL + e-mail OOB + revoke refresh no reset.  
4. 2FA off não quebra login; 2FA on não emite access sem 2º fator.

---

## 9. Banco (fechado)

**Postgres** (fonte da verdade: users, refresh families, invites, magic tokens).  
Redis opcional só para rate-limit. SQLite rejeitado neste MVP por write path do refresh.

---

*— fim —*
