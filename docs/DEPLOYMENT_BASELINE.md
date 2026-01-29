# Deployment baseline

## Opção 1: VM com Docker + Docker Compose

1. Provisionar uma VM (Linux/Windows) com Docker Engine e Compose plugin (versão 3.9 ou superior) e abrir portas 5432, 8000 e 3000.
2. Clonar o repo e fazer checkout na ramificação `main` que será implantada.
3. Criar `.env` a partir de `docs/ENVIRONMENT_VARIABLES.md` e `.env.example`, preenchendo valores de DEV ou PROD (segredos fora do repo).
4. Para dev, rodar:
   ```bash
   docker compose -f compose.yaml up --build -d
   ```
   Para o baseline de deployment (prod-like), executar:
   ```bash
   docker compose -f compose.yaml -f infra/compose.prod.yaml up --build -d
   ```
5. A cada atualização, puxar a última `main` e reexecutar o comando acima para refazer as imagens e serviços.

## Dev vs Prod
- Dev usa volumes/bind mounts e o `NODE_ENV=development` padrão mais permissivo.
- Prod reutiliza o mesmo `compose.yaml` com `infra/compose.prod.yaml`, define `APP_ENV=prod` e remove dependências de builds locais.
- Dev aplica migrações pelo entrypoint; Prod assume que o banco já está preparado ou usa um job externo antes do deploy.
- Logs de Dev são para o terminal local; Prod deve enviar logs para o driver do host ou soluções de observabilidade.

## Runbook mínimo
1. **Provisionar infraestrutura**: VM pronta, Docker instalado, DNS/ports definidos e storage disponível (volume para Postgres). Crie/atualize `.env` e armazene em um local seguro.
2. **Deploy inicial**: clone o repo, `git checkout main`, copie o `.env.example` para `.env` e execute o comando de prod.
3. **Verificação**: execute os health checks abaixo e monitore `docker compose ps` para garantir serviços saudáveis.
4. **Rolling upgrade**: `git pull origin main` e reutilize `docker compose -f compose.yaml -f infra/compose.prod.yaml up --build -d`. Evite alterações locais antes de subir.
5. **Rollback**: `git checkout <tag|commit anterior>`, reexecute o compose de prod e revalide os health checks para confirmar a reversão.

## Health checks automatizáveis
- Backend: `curl -fsS http://localhost:8000/healthz`
- Frontend: `curl -fsS http://localhost:3000/en/`
- Health check status via Compose:
  ```bash
  docker compose -f compose.yaml -f infra/compose.prod.yaml ps --filter health=healthy
  ```

## Wait helper (CI/local)
Use `infra/wait_http.py` to wait for endpoints without fixed sleeps:
```bash
python infra/wait_http.py http://127.0.0.1:8000/healthz http://127.0.0.1:3000/en/
```

## Checklist de segurança
- Armazene JWT_SECRET, DATABASE_URL e POSTGRES_PASSWORD fora do repo em um gestor de segredos ou variáveis de ambiente do host.
- Monte `.env` via `env_file` ou `environment` para evitar expor segredos em históricos de comandos.
- Monitore os arquivos `.env` e limite o acesso ao host ao time mínimo.
