# Rulesets no GitHub

Rulesets sao conjuntos de regras aplicadas a branches ou tags. Eles ajudam a
padronizar o fluxo de trabalho, garantindo que mudancas em `main` passem por
revisoes, validacoes e controles de qualidade antes do merge.

## Por que usar
- Evitar pushes diretos em branches criticos
- Garantir revisoes obrigatorias e status checks verdes
- Proteger historico com regras consistentes

## Criar um ruleset no GitHub (UI)
1. Abra o repo no GitHub.
2. Acesse `Settings` -> `Rules` -> `Rulesets`.
3. Clique em `New branch ruleset`.
4. Defina um nome e o alvo (ex.: `main`).
5. Configure as regras e salve.

## Regras recomendadas para `main`
- Require a pull request before merging
- Require approvals (min. 1 ou 2)
- Require status checks to pass
- Require conversation resolution
- Restrict deletions e force pushes
- Block direct pushes por usuarios nao autorizados
