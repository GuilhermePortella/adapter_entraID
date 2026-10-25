#!/usr/bin/env bash
# Execução local: ./start.sh
set +x
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ ! -f .env ]]; then
    (umask 077; cp .env.example .env)
    echo 'Arquivo .env criado. Preencha os IDs e o secret e execute novamente.'
    exit 1
fi

chmod 600 .env
set -a
source .env
set +a

export PORT="${PORT:-8080}"
export ENTRA_LOGIN_ENABLED="${ENTRA_LOGIN_ENABLED:-true}"
export ENTRA_REDIRECT_URI="${ENTRA_REDIRECT_URI:-http://localhost:${PORT}/login/oauth2/code/entra}"
export SESSION_COOKIE_SECURE="${SESSION_COOKIE_SECURE:-false}"

required_ids=(ENTRA_TENANT_ID ENTRA_AUDIENCE)
if [[ "$ENTRA_LOGIN_ENABLED" == true ]]; then
    required_ids+=(ENTRA_CLIENT_ID)
    if [[ -z "${ENTRA_CLIENT_SECRET:-}" ]]; then
        echo 'Preencha ENTRA_CLIENT_SECRET no .env com o Value do secret.' >&2
        exit 1
    fi
fi

uuid_pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
for name in "${required_ids[@]}"; do
    value="${!name:-}"
    if [[ ! "$value" =~ $uuid_pattern || "$value" == 00000000-0000-0000-0000-000000000000 || "$value" == 11111111-1111-1111-1111-111111111111 || "$value" == 22222222-2222-2222-2222-222222222222 ]]; then
        echo "Preencha $name no .env com o UUID completo do seu registro Entra ID." >&2
        exit 1
    fi
done

for command in java mvn; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Comando $command não encontrado. Instale JDK 21 e Maven para continuar." >&2
        exit 1
    fi
done

echo "Iniciando aplicação. Após o startup, acesse http://localhost:${PORT}/login"
exec mvn spring-boot:run
