# Página de teste do redirect

HTML e JavaScript puros, sem Node/npm. O Maven inclui `index.html` no Java em
`/demo/index.html`, tanto no desenvolvimento quanto no JAR empacotado.

1. Na raiz do Java, configure `.env` a partir de `.env.example`, usando os valores reais.
2. Use `ENTRA_LOGIN_ENABLED=true` e `SESSION_COOKIE_SECURE=false` para HTTP localhost.
3. Exporte as variáveis e inicie:

```sh
set -a
source .env
set +a
mvn spring-boot:run
```

4. Abra **http://localhost:8080/demo/index.html** e clique em **Entrar com Microsoft**.
5. Após autenticar, a Microsoft retorna ao callback já cadastrado:
   **http://localhost:8080/login/oauth2/code/entra**.
6. O Spring processa o callback e redireciona para a página HTML, que consulta `/auth/me`
   e mostra nome, email, subject, tenant ID e o JSON. Campos ausentes aparecem como “Não informado”.

Não abra o HTML por `file://` nem por um servidor separado: ele usa a sessão do Java
na mesma origem. Nenhum secret ou token OIDC é configurado ou armazenado no frontend.
O callback Azure permanece igual; somente o destino após o login mudou de `/auth/me`
para `/demo/index.html`. A API `/auth/me` continua disponível para consulta direta.

O teste com conta real requer as variáveis e o registro no Entra; a página não simula login.
