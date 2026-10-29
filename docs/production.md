# Configuração local e produção

## Desenvolvimento local

Execute `./start.sh`. O script carrega `.env`, seleciona `local` e rejeita outro perfil
declarado no ambiente ou no `.env`. O perfil local usa HTTP em `127.0.0.1:8080`,
callback localhost e cookie sem Secure. O arquivo compartilhado
`application-local.properties` contém apenas defaults; credenciais ficam no `.env`
ignorado pelo Git. Não execute esse script na infraestrutura de produção.

## Produção

Sem perfil explícito, o padrão é `prod`. No deploy, declare-o também explicitamente:

```sh
java -jar target/adapter-entraid-0.0.1-SNAPSHOT.jar --spring.profiles.active=prod
```

A configuração atual exige **TLS no próprio Java**, inclusive se houver um proxy
na frente. Configure um certificado válido para o domínio de implantação. O servidor
usa a porta 8443 por padrão (ou `PORT`); a URI registrada no Entra deve corresponder
exatamente à URL pública, incluindo porta quando diferente de 443.

Exemplo de variáveis de configuração, sem credenciais:

```sh
SPRING_PROFILES_ACTIVE=prod
ENTRA_LOGIN_ENABLED=true
ENTRA_TENANT_ID=<UUID-do-tenant>
ENTRA_AUDIENCE=<UUID-da-API>
ENTRA_CLIENT_ID=<UUID-do-aplicativo-web>
ENTRA_REDIRECT_URI=https://portal.seudominio.com/login/oauth2/code/entra
SERVER_SSL_KEY_STORE=file:/run/tls/server.p12
SERVER_SSL_KEY_STORE_TYPE=PKCS12
```

Injete a senha do keystore e o client secret pelo gerenciador da plataforma. Não
coloque os valores em argumentos do Java, Dockerfile, imagem, scripts ou arquivos
versionados. As variáveis acima são um mapa de configuração para o deploy, não um
arquivo para copiar literalmente sem substituir os placeholders.

O Java rejeita no startup:

- perfis `prod` e `local` combinados;
- `server.ssl.enabled=false`;
- cookies sem Secure ou HttpOnly, ou sem SameSite;
- callback HTTP, vazio ou localhost quando o login está habilitado;
- processamento de forwarded headers sem uma integração de proxy revisada.

TLS/certificado ausente ou inválido também impede o servidor de iniciar. As
validações verificam a configuração efetiva, inclusive overrides por variáveis
de ambiente e argumentos. Não são uma barreira contra quem controla o processo:
a infraestrutura deve restringir quem pode alterar perfis e configuração.

## Entrega de segredos

Como o provedor ainda não foi escolhido, não há vault criado nem conexão com um
serviço externo. Foram preparados dois mecanismos suportados pelo Spring Boot:

1. **Injeção pelo ambiente:** o gerenciador entrega `ENTRA_CLIENT_SECRET` e
   `SERVER_SSL_KEY_STORE_PASSWORD` ao processo na inicialização.
2. **Arquivos montados:** o gerenciador/agente monta um diretório de segredos em
   `/run/secrets/`, ou no caminho definido por `SECRETS_DIRECTORY` (com `/` final).
   Cada nome de arquivo é uma propriedade e seu conteúdo é somente o valor:

   | Arquivo | Conteúdo |
   | --- | --- |
   | `entra.login.client-secret` | Value do client secret |
   | `server.ssl.key-store-password` | Senha do keystore |

O import `configtree:` é opcional para permitir a alternativa por ambiente, mas a
aplicação exige um client secret não vazio quando OIDC está habilitado. Não configure
as duas fontes para a mesma propriedade; overrides do ambiente podem prevalecer.
O `.env` não é carregado pelo Java nem pelo comando de produção. O processo não
consegue comprovar que uma variável veio de um vault: essa garantia pertence ao deploy.

Na implantação, configure a identidade da aplicação para ler apenas os segredos
necessários e restrinja as permissões dos volumes. A rotação exige reiniciar/reimplantar
a aplicação; não há recarga automática de credenciais nesta implementação.

Quando a hospedagem for definida, será necessário configurar o vault, a identidade,
o certificado, o domínio e as permissões. Se a plataforma terminar TLS no proxy e
exigir HTTP no backend, a integração deverá ser adaptada com proxies confiáveis e
restrição de rede; não desative as validações para contornar isso.

Referências:
- [Spring Boot 3.5: configuração externa e configtree](https://docs.spring.io/spring-boot/3.5/reference/features/external-config.html)
- [Spring Boot 3.5: TLS e proxy](https://docs.spring.io/spring-boot/3.5/how-to/webserver.html)
