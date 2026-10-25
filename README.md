# Microsoft Entra ID: API Bearer e login BFF

Implementação básica em Java 21, Spring Boot e Spring Security OAuth2 Resource Server.
Aceita access tokens JWT v2 de **um único tenant da nuvem pública Microsoft**, destinados
a esta API. O cliente obtém o token no Entra ID e envia `Authorization: Bearer <access_token>`.
O contrato Bearer foi preservado e não precisa de client secret.

Há também um fluxo opcional de **login OIDC com sessão**, Authorization Code + PKCE,
retorno de identidade em JSON, CSRF e logout local. Ele precisa de `ENTRA_CLIENT_ID`,
`ENTRA_CLIENT_SECRET` e `ENTRA_LOGIN_ENABLED=true`, além do tenant.
Consulte [configuração, arquitetura e validação do login BFF](docs/oidc-login.md).
As seções abaixo descrevem o contrato Bearer existente.

O esqueleto Ant/NetBeans foi migrado para Maven e o layout `src/main/java` e `src/test/java`.
No NetBeans, reabra a pasta como projeto Maven pelo `pom.xml`.

## Página HTML de teste

Abra **http://localhost:8080/login** após iniciar o Java com OIDC habilitado.
O pequeno frontend fica em [redirect-demo](redirect-demo/README.md), sem npm ou servidor adicional.
Após login, o navegador volta à página, que mostra os dados de `/auth/me`.
O callback Azure continua `http://localhost:8080/login/oauth2/code/entra`.

## Endpoints

| Método e caminho | Permissão | Resposta |
| --- | --- | --- |
| `GET /health` | Público | `{"status":"UP"}` |
| `GET /api/me` | Token válido com escopo delegado `access_as_user` | `subject` e `tenantId` |
| `GET /login` (login habilitado) | Público | Página de entrada com botão Microsoft |
| `GET /auth/me` (login habilitado) | Sessão OIDC autenticada | Identidade básica em JSON |
| `GET /csrf` (login habilitado) | Sessão OIDC autenticada | Token CSRF para operações com sessão |
| `POST /logout` (login habilitado) | CSRF válido | Invalida sessão e retorna 204 |
| Outros caminhos/métodos | Negados | Sem acesso |

Sem token ou com token inválido: **401**. Token válido sem o escopo exigido: **403**.
`subject` representa o claim `sub`; não é um endereço de e-mail nem necessariamente o object ID.
O endpoint de saúde indica que a aplicação responde, não testa a disponibilidade do Entra ID.

## Configurar o Entra ID

1. Em **App registrations**, registre a **API**, selecionando contas apenas deste diretório
   (single tenant). Anote **Directory (tenant) ID** e **Application (client) ID**.
2. No manifesto da API, configure `api.requestedAccessTokenVersion` como `2`.
3. Em **Expose an API**, use o Application ID URI `api://<CLIENT_ID_DA_API>` e crie o
   escopo delegado `access_as_user`. Defina quem pode consentir conforme a política do tenant.
4. Registre separadamente o cliente (SPA, aplicativo desktop ou cliente de teste).
   Configure a plataforma e o redirect URI exato do cliente. Em **API permissions**,
   adicione a permissão delegada da sua API: `access_as_user`. Conceda consentimento
   administrativo quando exigido pelo tenant.
5. No cliente, use **Authorization Code com PKCE (S256)**, com os endpoints:
   - Autorização: `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize`
   - Token: `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token`
   - Scope: `api://<CLIENT_ID_DA_API>/access_as_user`
   - Client ID: ID do **cliente**, diferente do ID da API.

Uma biblioteca como MSAL ou um cliente OAuth com suporte a PKCE pode executar esse fluxo.
Envie à API o **access token**, nunca o ID token. Tokens destinados ao Microsoft Graph
não serão aceitos. Para tokens v2, `ENTRA_AUDIENCE` é o UUID do client ID **da API**,
sem o prefixo `api://`.

Este exemplo exige um usuário e um escopo delegado. Tokens de `client_credentials`,
que usam application roles, não autorizam `/api/me`; suporte a esse cenário requer
uma política explícita de app roles em endpoints próprios.

## Executar

Requisitos: JDK 21 e Maven 3.6.3 ou superior.

Para iniciar com as variáveis locais, execute:

```sh
./start.sh
```

O script carrega `.env`, verifica os IDs obrigatórios e inicia o Maven. Se o arquivo
não existir, cria uma cópia de `.env.example` para preenchimento. Informe os UUIDs
completos em `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` e `ENTRA_AUDIENCE`, e o Value em
`ENTRA_CLIENT_SECRET` (entre aspas simples). O script não imprime as credenciais.
Após iniciar, abra **http://localhost:8080/login**. Use `Ctrl+C` para parar.

Alternativamente, exporte as variáveis manualmente:

```sh
cp .env.example .env
# Edite .env com os IDs do seu registro. O arquivo está no .gitignore.
# Para executar SOMENTE a API Bearer, defina ENTRA_LOGIN_ENABLED=false.
set -a
source .env
set +a
mvn spring-boot:run
```

Spring Boot não carrega `.env` automaticamente; o comando acima exporta as variáveis.
Configuração ausente ou IDs fora do formato UUID impedem a inicialização.

```sh
curl -i http://localhost:8080/health
curl -i http://localhost:8080/api/me  # 401 esperado
```

Após obter o access token no cliente, forneça-o em uma variável local `ACCESS_TOKEN`
sem salvar seu valor no repositório ou no histórico do terminal:

```sh
curl -i -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8080/api/me
unset ACCESS_TOKEN
```

O exemplo HTTP destina-se ao desenvolvimento local. No ambiente publicado, exponha a
API por HTTPS. Não registre o header Authorization no proxy ou na aplicação.

## Testar e empacotar

```sh
mvn verify
java -jar target/adapter-entraid-0.0.1-SNAPSHOT.jar
```

Os testes não precisam de tenant, credenciais ou acesso ao Entra ID. Eles geram uma
chave RSA temporária e enviam JWTs assinados pela cadeia real de filtros do Spring Security.
Apenas a origem da chave pública é substituída; os validadores da aplicação são mantidos.
São exercitados acesso autorizado, ausência de token, assinatura não confiável, token
malformado, expiração, validade futura, emissor, audiência, tenant, versão, claims obrigatórios,
escopo, app roles e negação de rotas não cadastradas.

## Decisões e limites

- Validação RS256 com chaves públicas do endpoint JWKS do tenant, cache e atualização
  de chaves pelo Spring Security/Nimbus. Downloads têm timeouts de conexão e leitura de 5 s.
- Emissor exato, audiência, `tid`, versão `2.0`, expiração e `sub` são obrigatórios.
  A validação temporal padrão do Spring tolera 60 s de diferença entre relógios.
- `/api/**` permanece sem sessão, autenticado somente por Bearer no header, com autorização negada por padrão.
  CSRF está desabilitado apenas na cadeia Bearer (`/api/**` e `/health`).
  A cadeia OIDC separada mantém CSRF habilitado e nunca autentica chamadas à API Bearer.
  CORS não foi habilitado; configure origens específicas caso um frontend em outra origem precise acessar.
- A inicialização não exige baixar as chaves. A primeira validação precisa de acesso HTTPS
  a `login.microsoftonline.com`; uma falha de obtenção das chaves não libera acesso.
- JWTs são validados localmente, sem consulta de revogação a cada chamada. A aplicação
  não implementa avaliação contínua de acesso, permissões por objeto nem multitenancy.
- Não há modo mock que desative autenticação em runtime. Chaves de teste existem apenas em `src/test`.
  Os testes OIDC usam servidor local para token/JWKS e executam os validadores oficiais sem substituí-los.
- A integração com um tenant real ainda precisa ser validada no ambiente de destino.

## Referências oficiais

- [Spring Security: OAuth2 Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
- [Microsoft: validação dos claims de access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- [Microsoft: versões e audiência dos access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
