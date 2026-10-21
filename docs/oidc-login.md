# Login OIDC com sessão e App Roles

## Diagnóstico e escopo

O pedido original menciona `eclv-bff-login`, mas o repositório disponível é `adapter_EntraID`.
Foi confirmado que a implementação deve ocorrer neste repositório e preservar a API Bearer.
Não foram feitas alterações em outro microsserviço nem na configuração do Azure.

| Aspecto inspecionado | Situação anterior e decisão |
| --- | --- |
| Java / Spring Boot | Java 21 / Spring Boot 3.5.16, mantidos |
| Stack web | Spring MVC/Servlet; nenhuma API WebFlux adicionada |
| Segurança existente | OAuth2 Resource Server, JWT RS256 e escopo `access_as_user` |
| Contratos | `/api/me`: 401 sem Bearer, 403 sem escopo; `/health` público, preservados |
| Pacotes | `identity.entraid`, `config`, `mapping`; mantidos |
| Configuração | `application.properties`, variáveis de ambiente e `.env.example`; mesma convenção |
| Credenciais | Apenas IDs na API; o login acrescenta secret externo, nunca versionado |
| Testes existentes | 23 cenários com JWTs assinados localmente; mantidos |
| Sessão, CSRF e CORS | Antes sem sessão e CSRF desabilitado; cadeia separada evita aplicar essa política ao BFF |
| Filtros/interceptadores adicionais | Nenhum encontrado antes desta mudança |
| Outros serviços de autenticação / persistência | Nenhum encontrado |
| Especificação arquitetural adicional | Não localizada; contrato Bearer explicitamente preservado |

Dependências novas: `spring-boot-starter-oauth2-client` e `spring-security-test` (somente testes).
Ambas usam as versões gerenciadas pelo parent existente. Não foi adicionado banco de dados,
framework reativo, biblioteca JWT própria ou novo serviço.

## Fluxo e separação dos contratos

```mermaid
sequenceDiagram
    participant Browser as Navegador
    participant BFF as adapter_EntraID
    participant Entra as Microsoft Entra ID
    Browser->>BFF: GET /private
    BFF-->>Browser: 302 /oauth2/authorization/entra
    Browser->>BFF: Iniciar login
    BFF-->>Browser: 302 authorize (state, nonce, PKCE S256)
    Browser->>Entra: Autenticar
    Entra-->>Browser: Callback com code e state
    Browser->>BFF: GET /login/oauth2/code/entra
    BFF->>Entra: Trocar code, client secret e code_verifier
    Entra-->>BFF: ID Token e Access Token
    BFF->>Entra: Obter/cachear chaves públicas JWKS
    Note over BFF: Spring valida assinatura, issuer, audience, tempo e nonce
    Note over BFF: Mapeia App Role do ID Token e troca ID da sessão
    BFF-->>Browser: Cookie de sessão e 302 /private
    Browser->>BFF: GET /admin/test com cookie
    BFF-->>Browser: 200 com role; 403 sem role
```

A cadeia de ordem 1 atende `/api/**` e `/health`. Ela continua stateless e ignora a
sessão OIDC: mesmo com login válido, `/api/me` exige seu próprio access token e escopo.
Um Bearer token, por sua vez, não autentica `/private` nem `/admin/test`.

A cadeia de ordem 2 atende o fluxo OIDC. O login é opt-in (`ENTRA_LOGIN_ENABLED=true`)
para preservar instalações que usam somente Bearer. Se desabilitado, não há registro
OIDC nem endpoints de teste liberados. Uma cadeia final de ordem 3 sempre nega rotas
não atendidas, inclusive se a opção de habilitação receber um valor incorreto.

O sucesso sempre retorna a `/private`; a aplicação não guarda URLs de retorno fornecidas
pelo usuário. Depois do login, acesse `/admin/test` para verificar a autorização.

Os endpoints públicos do tenant são derivados de `ENTRA_TENANT_ID`, incluindo issuer
`https://login.microsoftonline.com/<TENANT_ID>/v2.0`. Não há descoberta remota no startup.
O decoder OIDC nativo do Spring faz a validação do ID Token; o decoder Bearer existente
continua independente. Não há chamada UserInfo ou Microsoft Graph no fluxo de login.

## Variáveis de ambiente

| Variável | Uso / valor |
| --- | --- |
| `ENTRA_TENANT_ID` | UUID do tenant, obrigatório para ambos os fluxos |
| `ENTRA_AUDIENCE` | Client ID da API Bearer existente; continua obrigatório |
| `ENTRA_LOGIN_ENABLED` | `true` habilita OIDC; padrão `false` |
| `ENTRA_CLIENT_ID` | Client ID do registro web/BFF; obrigatório com login habilitado |
| `ENTRA_CLIENT_SECRET` | **Valor** do secret do registro web, não seu identificador |
| `ENTRA_REDIRECT_URI` | URL absoluta; padrão `http://localhost:8080/login/oauth2/code/entra` |
| `SESSION_COOKIE_SECURE` | Padrão `true`; `false` somente para desenvolvimento HTTP localhost |
| `PORT` | Porta HTTP, padrão `8080` |

`ENTRA_CLIENT_ID` e `ENTRA_AUDIENCE` representam papéis diferentes. Podem coincidir se
o registro existente já atende aos dois papéis, mas isso deve ser verificado no tenant.
A App Role deve estar no registro que emite o ID Token para o BFF.

A Redirect URI deve corresponder exatamente à URI **já registrada**, inclusive esquema,
host, porta e caminho. Esta implementação atende `/login/oauth2/code/entra` na raiz da
aplicação. Hosts e portas são configuráveis; HTTP só é aceito para `localhost`.
Se a URI já registrada usar outro caminho, há uma incompatibilidade a resolver no código
antes do teste, sem alterar silenciosamente o registro Azure. Não foi feita alteração no Azure.

## Configuração externa no Entra ID

Antes dos testes manuais de autorização:

1. Localize a aplicação single-tenant já registrada e confirme seu tenant/client ID.
2. Confirme a plataforma **Web** e a Redirect URI existente. O backend é um cliente
   confidencial; o fluxo usa Authorization Code, não implicit grant.
3. Verifique se existe uma App Role **habilitada**, com valor exato `Gateway.AdminGlobal`
   e tipo de membro permitido **Users/Groups** (o valor técnico corresponde a `User`).
4. Em **Enterprise applications → aplicação → Users and groups**, atribua diretamente
   o usuário de teste à role `Gateway.AdminGlobal`. Não é necessário criar um grupo.
5. Disponibilize um secret válido ao processo por ambiente/secret manager. Não envie
   o valor em tickets, logs ou commits. Confirme expiração e procedimento de rotação.
6. Confirme consentimento para os escopos OIDC `openid profile`, conforme a política do tenant.

App Roles são permissões da aplicação, não funções administrativas do tenant. O backend
mapeia apenas `Gateway.AdminGlobal` para `APPROLE_Gateway.AdminGlobal`, a partir do
ID Token validado. Roles em UserInfo, headers, parâmetros ou autoridades injetadas pelo
frontend não concedem esse acesso.

Se **Assignment required** estiver habilitado na enterprise application, um usuário
não atribuído poderá ser bloqueado no Entra antes de chegar ao backend. Para testar
o 403 local, use uma identidade que possa autenticar sem a role administrativa, conforme
a política aprovada pelo IAM; não reduza controles do tenant apenas para obter um teste.

Não dependemos de grupos ou Conditional Access. A existência/atribuição da role, o
secret e a URI não foram verificados neste tenant. Os créditos promocionais Azure não
são usados como evidência de licenciamento ou disponibilidade de recursos de identidade.

## Execução local

```sh
cp .env.example .env
# Edite .env localmente com os IDs, secret e Redirect URI existentes.
# ENTRA_LOGIN_ENABLED=true
# SESSION_COOKIE_SECURE=false apenas para http://localhost
set -a
source .env
set +a
mvn verify
mvn spring-boot:run
```

O `.env` não é carregado automaticamente pelo Spring e está ignorado pelo Git.
Valores com caracteres especiais devem ser corretamente delimitados no arquivo shell.
Também é possível injetar as variáveis diretamente pela IDE ou secret manager.
Para continuar executando apenas Bearer, defina `ENTRA_LOGIN_ENABLED=false`.

1. Abra `http://localhost:8080/private` no navegador.
2. Faça login com o usuário de teste. O callback deve resultar em `/private` com
   `{"status":"authenticated"}`.
3. Abra `/admin/test`: com a role correta, retorna `{"status":"authorized"}`; sem ela, 403.
4. Confirme que `/api/me` continua retornando 401 sem Bearer, inclusive após o login.
5. Para logout, execute no console do navegador **na mesma origem**:

```javascript
const csrf = await fetch('/csrf', { credentials: 'same-origin' }).then(r => r.json());
await fetch('/logout', {
  method: 'POST',
  credentials: 'same-origin',
  headers: { [csrf.headerName]: csrf.token }
});
```

O token de `/csrf` é um token anti-CSRF, não um access token nem um ID Token. Não há
endpoint que retorne tokens OIDC. Logout retorna 204, invalida a sessão e remove o cookie.
Um POST sem CSRF válido retorna 403 e não faz logout.

## Sessões, cookies e revogação

- Cookie `JSESSIONID`: HttpOnly, Secure por padrão, SameSite=Lax, sem reescrita de URL.
  Lax permite o callback de navegação GET vindo do Entra; não configurar `form_post`
  sem reavaliar a política de cookies/CSRF.
- CSRF fica ativo na cadeia OIDC, incluindo logout. Não foi liberado CORS; use mesma
  origem ou defina uma política explícita de origens antes de integrar outro frontend.
- O ID da sessão é trocado após autenticação. Ociosidade máxima: 20 minutos.
- A sessão autenticada também é invalidada no próximo acesso quando o ID Token expira,
  mesmo se estiver ativa. A navegação é redirecionada ao login; a sessão SSO no Entra
  poderá autenticar novamente sem pedir senha.
- Access/ID Tokens e cliente autorizado ficam somente na sessão do servidor. Não há
  refresh token (`offline_access` não é solicitado), refresh automático ou chamada downstream.
  A expiração do Access Token, isoladamente, não encerra a sessão; ele não é usado para
  operações neste exemplo. Integrações downstream exigirão uma política própria.
- Remover uma role no Entra não atualiza sessões abertas. A autorização anterior pode
  permanecer até logout, expiração por inatividade ou expiração do ID Token. Um novo login
  obtém as claims atualizadas, sujeito à propagação no Entra. Não há revogação contínua.
- Logout é **local**. Não encerra a sessão SSO do Entra nem de outras aplicações.
  Logout coordenado exigirá decisão do IAM sobre impacto, post-logout URI registrada
  e integração com o handler OIDC nativo; não foi presumida essa autorização/configuração.
- Sessões estão em memória: reinício exige novo login. Múltiplas réplicas precisam de
  estratégia de sessão aprovada (afinidade ou armazenamento compartilhado); não foi
  adicionada persistência sem necessidade demonstrada.

## Falhas e observabilidade

| Situação | Comportamento / investigação |
| --- | --- |
| Sem sessão ou sessão expirada | Recomeça o login OIDC |
| Sem App Role | 403 no endpoint administrativo |
| Callback inválido, state divergente ou replay | 401, não estabelece nova sessão |
| Assinatura, issuer, audience, expiração ou nonce inválidos | Autenticação rejeitada pelo Spring |
| Client ID/secret inválido ou secret expirado | Rejeição pelo Entra; callback/processamento retorna falha genérica |
| Tenant incorreto | Erro no provedor ou rejeição de issuer; não há fallback multi-tenant |
| Redirect URI divergente | Entra pode mostrar o erro antes de chamar o callback; comparar URI exata |
| Entra indisponível | Pode falhar no navegador, token endpoint ou JWKS; nunca autoriza por fallback |

Respostas de falha do callback: `401 {"error":"authentication_failed"}`. Não retornam
mensagens do provedor, secrets ou tokens. A troca do código usa timeouts de conexão e
leitura de 5 segundos, sem retry manual de um código de uso único. A obtenção de chaves
OIDC usa cache e timeouts padrão do Spring/Nimbus; o caminho Bearer mantém seus timeouts de 5 s.

Logs de segurança são eventos constantes: `oidc_login_started`, `oidc_login_succeeded`,
`oidc_login_failed`, `oidc_access_denied`, `oidc_logout`, `oidc_session_expired` e
`session_destroyed`. Não incluem usuário, IDs de sessão, payloads, códigos ou tokens.
O evento de destruição é emitido pelo listener do servlet container e também cobre inatividade.
Não habilite TRACE/DEBUG de bibliotecas OAuth/HTTP nem registre query strings do callback,
corpos do token endpoint, Cookie ou Authorization no proxy/APM.

## Testes e evidências

```sh
mvn verify
```

- `ApiSecurityTest`: regressões do contrato Bearer com verificação criptográfica real.
- `AppRoleAuthoritiesMapperTest`: origem confiável da role e preservação das demais authorities.
- `EntraLoginPropertiesTest`: configuração inválida, Redirect URI e ausência de secret.
- `OidcLoginTest`: fluxo Authorization Code completo contra token/JWKS em servidor loopback,
  chaves RSA geradas durante o teste, state, nonce, PKCE, troca do ID da sessão, App Roles,
  CSRF, logout, expiração, replay, erros do provedor e isolamento entre as duas cadeias.
  Um teste HTTP contra o servlet container real verifica os atributos do cookie.

No teste de integração, apenas as URLs de token/JWKS são apontadas ao servidor local.
O cliente de troca do código, o decoder OIDC oficial, os validadores e os filtros de
produção são executados sem bypass. As fixtures e chaves existem somente em `src/test`.
Os testes de expiração de sessão e mapeamento usam identidades sintéticas em testes;
não há simulação de sucesso na aplicação real.

O build não precisa de conexão com o Azure. O primeiro download de dependências Maven
precisa de Maven Central; testes locais abrem portas efêmeras em loopback.
Relatórios: `target/surefire-reports`; artefato: `target/adapter-entraid-0.0.1-SNAPSHOT.jar`.

Evidência desta implementação: `mvn verify` concluído, 52 testes sem falhas (23 Bearer,
19 OIDC, 2 de mapeamento e 8 de configuração). `git diff --check` não apontou erros.
Não foram encontradas ferramentas Gitleaks, Semgrep ou Trivy no ambiente; não foi
executada uma análise SAST/SCA dedicada. A revisão e os testes não substituem essa análise.

A execução automatizada não comprova login com o tenant real, MFA, Conditional Access,
governança, rotação de secrets ou conformidade bancária. Esses aceites continuam externos.

## DEV versus HOMOL e pendências

| Aspecto | DEV local | HOMOL |
| --- | --- | --- |
| Transporte | HTTP localhost permitido | HTTPS obrigatório |
| Cookie Secure | `false` exclusivamente em HTTP local | `true` |
| Redirect URI | URI local já registrada | URI exata aprovada/registrada para HOMOL |
| Credenciais | Ambiente local ignorado pelo Git | Secret manager e rotação corporativa |
| Usuário/role | Atribuição direta do usuário de teste | Governança validada pelo IAM |
| Grupos e Conditional Access | Não são pré-requisitos | Definição e teste pelo IAM |
| Sessões | Memória, uma instância | Definir estratégia por topologia |
| Proxy | Acesso direto | Preservar esquema HTTPS e callback; confiar apenas em proxies conhecidos |

Antes do aceite real, confirmar App Role e atribuição, secret válido, Redirect URI e
tenant/client ID; executar login com e sem role, logout, expiração e regressão Bearer.
As rotas `/private` e `/admin/test` são diagnósticas e retornam apenas status; substituir
ou remover quando houver endpoints de negócio, preservando a política de autorização.

Rollback funcional: `ENTRA_LOGIN_ENABLED=false` seguido de reinício desativa o login
sem alterar `/api/**`. Não há migrações de banco. Sessões abertas são perdidas no reinício.

## Fontes oficiais

- [Spring Security: configuração avançada OIDC e authorities](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html)
- [Spring Security: logout](https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html)
- [Microsoft: App Roles e claims em ID Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
