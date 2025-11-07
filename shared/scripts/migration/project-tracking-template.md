# Migration Project Board Template

## Columns

1. Backlog
2. In Progress
3. Review
4. CI Green
5. Integration Tested
6. Released
7. Done

## Card Template (Service or Shared Repo)

- Name: `[repo] Extract`
- Description:
  - Source Paths: (from extraction-map.yml)
  - Submodules: (list)
  - Owner: (name)
  - Risks: (top 1-2)
  - Blockers: (if any)

## Metrics to Track Weekly

- Mean CI duration per repo
- Submodule drift count
- Open extraction defects
- Time from extraction start → first release

## Exit Criteria

- All repos: CI + Release + Docs + Schema check passing
- Monorepo archived
