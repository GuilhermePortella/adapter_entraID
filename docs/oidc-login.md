# PoC: login Microsoft Entra ID e identidade em JSON

## Diagnóstico e decisão

O repositório confirmado para implementação é `adapter_EntraID`, embora a especificação
use o nome `eclv-bff-login`. A estrutura existente foi preservada: Java 21, Spring Boot
3.5.16, Maven, Spring MVC/Servlet e pacotes `identity.entraid`/`config`. Não há WebFlux,
banco de dados ou outros serviços de autenticação. A configuração usa
`application.properties`, variáveis de ambiente e perfis `local`/`prod`.
Consulte [configuração de produção](production.md).

OAuth2 Client, Resource Server e Spring Security Test já estavam disponíveis no BOM
existente. Nenhuma dependência foi adicionada nesta revisão.

Esta especificação substitui o teste administrativo anterior: foram removidos o mapper
de App Roles, seu teste e os endpoints `/private` e `/admin/test`. A PoC não depende de
RBAC, grupos, Conditional Access ou Microsoft Graph. O contrato Bearer `/api/me` foi
preservado, conforme a decisão anterior; cookies de sessão não autenticam essa API.

## Fluxo

```mermaid
sequenceDiagram
    participant N as Navegador
    participant B as Backend
    participant E as Microsoft Entra ID
    N->>B: GET /login
    B-->>N: Página de login com botão Microsoft
    N->>B: Iniciar OAuth2
    B-->>N: 302 authorize com state, nonce e PKCE
    N->>E: Autenticar usuário
    E-->>N: Callback com code e state
    N->>B: GET /login/oauth2/code/entra
    B->>E: Trocar code + code_verifier + client secret
    E-->>B: Tokens
    Note over B: Spring valida ID Token e nonce; troca o ID da sessão
    B-->>N: 302 /demo/index.html
    N->>B: Abrir página de teste
    N->>B: GET /auth/me com sessão
    B-->>N: 200 + identidade em JSON
```

O cliente usa Authorization Code, PKCE S256 e `client_secret_post`, com escopos
`openid profile email`. Os endpoints públicos Microsoft são derivados do UUID do
único tenant configurado. Issuer: `https://login.microsoftonline.com/<TENANT_ID>/v2.0`.
Spring Security obtém/cacheia JWKS e valida assinatura, issuer, audience, validade
 e nonce. `state` vincula o callback à solicitação armazenada na sessão.
Não há implementação própria de criptografia nem chamada UserInfo/Graph.

## Endpoints e contrato

| Endpoint | Política |
| --- | --- |
| `GET /demo/index.html` | Sessão autenticada; sem sessão válida retorna HTML com status 403 |
| `GET /login` | Público; redireciona para `/oauth2/authorization/entra` |
| `GET /oauth2/authorization/entra` | Inicia OAuth2 pelo Spring |
| `GET /login/oauth2/code/entra` | Callback processado pelo Spring |
| `GET /auth/me` | Sessão OIDC válida; sem sessão, redireciona ao início OAuth2 |
| `GET /health` | Público, contrato anterior |
| `GET /api/me` | Bearer com escopo `access_as_user`, contrato anterior |
| `GET /csrf` e `POST /logout` | Controles de sessão já existentes; logout exige CSRF |
| Demais rotas | Negadas |

Resposta de `/auth/me`, com dados ilustrativos:

```json
{
  "authenticated": true,
  "provider": "Microsoft Entra ID",
  "user": {
    "name": "Usuario Teste",
    "email": "usuario@exemplo.com",
    "subject": "identificador-do-usuario",
    "tenantId": "identificador-do-tenant"
  }
}
```

Os campos vêm exclusivamente do ID Token validado: `name`, `email`, `sub` e `tid`.
`name`, `email` e `tenantId` são `null` quando ausentes. Não há fallback para
`preferred_username`; ele não é tratado como e-mail verificado. `subject` é o `sub`,
não o Object ID. A resposta inclui `claims` com os claims do ID Token validado e `access` com
`groups`, `roles`, `directoryRoles` (claim `wids`) e `groupsStatus`. Não retorna o JWT
serializado, access token, secrets ou cookies. A resposta mantém `Cache-Control: no-store` do Spring Security.

## Configuração e execução local

| Variável | Uso |
| --- | --- |
| `ENTRA_CLIENT_ID` | Application (Client) ID do registro web |
| `ENTRA_TENANT_ID` | Directory (Tenant) ID, UUID single-tenant |
| `ENTRA_CLIENT_SECRET` | **Client Secret Value**, nunca Client Secret ID |
| `ENTRA_LOGIN_ENABLED` | `true` para habilitar a PoC; padrão `false` preserva execução somente Bearer |
| `ENTRA_REDIRECT_URI` | `http://localhost:8080/login/oauth2/code/entra` |
| `SESSION_COOKIE_SECURE` | `false` apenas para HTTP localhost; padrão `true` em HTTPS |
| `ENTRA_AUDIENCE` | Client ID da API Bearer preservada, obrigatório pela configuração existente |
| `PORT` | `8080` |

Client ID da API Bearer e do cliente web só devem coincidir se o mesmo registro tiver
ambos os papéis. Object ID e Client Secret ID não são utilizados.

```sh
cp .env.example .env
# Edite .env localmente com os valores reais, sem versioná-los.
set -a
source .env
export SPRING_PROFILES_ACTIVE=local
set +a
mvn verify
mvn spring-boot:run
```

Spring não carrega `.env` automaticamente. O arquivo é ignorado pelo Git. Delimite
corretamente valores especiais no arquivo shell, ou injete as variáveis pela IDE/secret
manager. A alternativa empacotada é `java -jar target/adapter-entraid-0.0.1-SNAPSHOT.jar --spring.profiles.active=local`.
Não salve valores reais no `application.properties`, exemplos, histórico ou logs.

## Teste manual no tenant verdadeiro

1. Confirme que o registro é single-tenant, plataforma **Web**, com a URI já cadastrada
   `http://localhost:8080/login/oauth2/code/entra`. Nenhuma alteração foi feita no Azure.
2. Configure os IDs e um Client Secret **Value** válido. Confirme consentimento para
   `openid profile email` conforme as políticas existentes.
3. Inicie a aplicação na porta 8080 e abra `http://localhost:8080/login` no navegador.
4. Autentique o usuário permitido no tenant e aguarde o callback.
5. Confirme o retorno a `/demo/index.html`, que consulta `/auth/me` e mostra os dados.
   A consulta `/auth/me` deve retornar HTTP 200 e o contrato JSON.
6. Verifique ausência de tokens/secrets e volte a `/auth/me` usando a mesma sessão.
7. Teste cancelamento e expiração de sessão: não devem retornar identidade autenticada.
8. Tente uma conta não admitida pelo tenant. Não deve obter uma sessão. Um convidado
   B2B autorizado no tenant configurado pode receber tokens desse tenant: single-tenant
   restringe o emissor, não implica bloquear todos os convidados.
9. Confirme que `/api/me` continua retornando 401 sem Bearer, mesmo após login OIDC.

Se a enterprise application exigir atribuição de usuários, o usuário de teste deve
estar autorizado pela política já existente. Esta PoC não cria roles/grupos nem reduz
políticas de acesso. Não depende de Conditional Access personalizado.

O teste real **não foi executado** nesta entrega. A autenticação com Microsoft,
credenciais, consentimento e configuração do registro continuam como aceite manual.

## Sessão e segurança mantidas

As cadeias são separadas: `/api/**` e `/health` mantêm o contrato stateless; as rotas
OIDC usam sessão e CSRF; uma cadeia final nega caminhos não atendidos. Não há CORS
permissivo. A sessão troca de ID após login e o cookie usa HttpOnly, SameSite=Lax e
Secure por padrão. Lax é compatível com o callback GET; não mudar para `form_post`
sem reavaliar cookies/CSRF. O callback padrão é fixo, sem depender de Host enviado pelo cliente.

A sessão expira no máximo 40 minutos após o login, mesmo com atividade, ou antes
se o ID Token expirar. O timeout de inatividade também é 40 minutos. O filtro de expiração já existente foi
mantido: também invalida a sessão no próximo acesso se o ID Token expirar. Não há refresh
manual nem `offline_access`. O Access Token não é usado para chamadas externas; sua
expiração isolada não encerra a sessão. Tokens ficam somente na sessão do servidor.

Logout local existente, executado pelo console na mesma origem:

```javascript
const csrf = await fetch('/csrf').then(r => r.json());
await fetch('/logout', { method: 'POST', headers: { [csrf.headerName]: csrf.token } });
```

O token acima é anti-CSRF, não um token de identidade. Logout retorna 204 e invalida
a sessão; sem CSRF, retorna 403. A sessão SSO Microsoft não é encerrada, mas cada novo fluxo envia `prompt=login` para solicitar reautenticação. Não há armazenamento de sessões em banco/Redis.
Reiniciar a aplicação exige novo login. HTTPS e estratégia de sessão para múltiplas
réplicas precisam de definição corporativa fora desta PoC local.

## Falhas e diagnóstico

| Situação | Comportamento / verificação |
| --- | --- |
| Client ID incorreto | Erro no Entra; verificar Application ID do registro web |
| Tenant inválido | UUID inválido impede startup; tenant inexistente/incorreto falha no provedor |
| Secret inválido ou expirado | Troca do código falha; conferir Value e expiração |
| Redirect URI divergente | Entra pode rejeitar antes do callback; comparar a URI exatamente |
| Cancelamento, state/nonce inválidos, callback sem solicitação ou replay | 401 sem estabelecer nova sessão |
| ID Token inválido, expirado ou emitido por outro issuer | Rejeição pelo Spring |
| Sem sessão ou sessão expirada | Novo fluxo OIDC |
| Email ausente | HTTP 200 com `user.email: null` |
| Loop de login local | Verificar cookie Secure: usar `SESSION_COOKIE_SECURE=false` somente em HTTP localhost |

Falhas de callback retornam `401 {"error":"authentication_failed"}`; nenhum detalhe
sensível do provedor é repassado. A troca do código tem timeouts de conexão/leitura
de 5 s e não repete manualmente códigos de uso único. JWKS OIDC mantém os timeouts/cache
padrão do Spring/Nimbus. TLS e validação de tokens permanecem habilitados.

Logs técnicos constantes registram início/sucesso/falha do login, acessos negados,
logout e fim de sessão. Não incluem identidade, tokens ou secrets. Evite TRACE/DEBUG
OAuth/HTTP e captura de query strings do callback, Cookie, Authorization ou corpos
na aplicação, proxy e APM.

## Testes e evidências

`mvn verify` passou com **51 testes**: 23 de regressão Bearer, 20 OIDC e 8 de configuração.
Os testes OIDC usam token/JWKS em loopback e chaves RSA temporárias exclusivamente em
`src/test`; a troca do código, o decoder oficial e os filtros reais são exercitados.
Não há mocks no fluxo de produção nem conexão com Azure durante os testes. Dependências
Maven precisam ser baixadas antes de executar o build completamente offline.

Cobertura da PoC: `/login`, proteção de `/auth/me`, sessão autenticada, JSON exato,
email e demais claims opcionais ausentes, cancelamento, assinatura/issuer/audience/
expiração/nonce inválidos, state incorreto, callback incompleto e replay. Também foram
mantidos testes de CSRF/logout, expiração de sessão, isolamento Bearer e atributos
reais do cookie no servlet container.

Relatórios: `target/surefire-reports`. Não foi executada análise SAST/SCA dedicada.
Testes locais não comprovam MFA, Conditional Access, governança ou prontidão para produção.

## Arquivos impactados

- `LoginController.java`: início de login e DTO com campos explícitos de identidade.
- `OidcLoginConfig.java`: rotas da PoC, escopo email e destino `/demo/index.html`; remoção do mapper de roles.
- `OidcLoginTest.java`: contrato JSON, claims opcionais e cancelamento, preservando testes do protocolo.
- `.env.example`, `README.md` e este documento: execução e escopo atualizados.
- Removidos `AppRoleAuthoritiesMapper.java` e `AppRoleAuthoritiesMapperTest.java`.

## Referências oficiais

- [Microsoft: claims do ID Token e email opcional](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
- [Spring Security: OAuth2 Login](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html)

## Claims e grupos no JSON

A seção “Ver resposta JSON” mostra também os claims recebidos no ID Token validado,
incluindo claims opcionais e extensões enviados pelo Entra. Datas são serializadas pelo
Jackson a partir dos tipos convertidos pelo Spring; este JSON não é o JWT original.
`access` resume grupos, roles de aplicativo e roles de diretório, sem conceder novas
permissões nos endpoints Java.

`access.groupsStatus` distingue:
- `included`: o token contém o claim `groups` (conforme o escopo configurado no Entra).
- `not_provided`: o token não contém grupos; isso não prova ausência de associações.
- `requires_graph`: há indicação de excesso de grupos; a lista não está completa no token.

Para incluir grupos, abra o registro do aplicativo no Entra ID, vá a **Token configuration >
Add groups claim** e configure os grupos desejados para o ID Token. Faça logout local e
entre novamente para receber os novos claims. Os grupos normalmente são identificados
por IDs; esta aplicação não consulta o Microsoft Graph para resolver nomes nem listar
associações ausentes. Roles dependem das atribuições e configuração do aplicativo.

Referência: https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles

A página 403 fica em `src/main/resources/pages/403.html`, com CSS e JavaScript
embutidos no JAR. O backend bloqueia o HTML de identidade antes de servi-lo; os
easter eggs não alteram autenticação. Uma sessão expirada também recebe 403 nessa rota.

O deadline absoluto fica apenas na sessão do servidor e é validado em cada requisição
OIDC protegida. Sessões sem deadline são invalidadas. `/auth/me` inclui
`session.expiresAt` e `session.serverTime` para a página limpar os dados e voltar a
`/login` ao vencer o prazo. A verificação no Java independe do JavaScript e do relógio
do navegador. Abas suspensas são revalidadas ao voltar ao primeiro plano.
O prazo não estende a validade de um ID Token que expire antes de 40 minutos.

Referência para reautenticação: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
