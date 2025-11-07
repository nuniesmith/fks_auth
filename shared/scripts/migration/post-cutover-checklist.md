# Post-Cutover Validation Checklist

Run after DNS / CI / deployment points to microrepos.

Automation helper: run `migration/post-cutover-automation.sh` to generate tags, cross-links, submodule drift, and integration compose smoke. Then manually verify the items below.

## Submodules

- [ ] Each service repo: `git submodule status` clean
- [ ] Outdated submodules action passes

## CI

- [ ] All workflows green
- [ ] Cache utilization ≥ expected (compare duration baseline)

## Runtime

- [ ] Full docker-compose (infra) stack starts
- [ ] Health endpoints return 200
- [ ] Version endpoint shows correct shared component tags

## Data & Schemas

- [ ] Schema repo tag recorded in each service deployment artifact
- [ ] No validation errors in logs

## Observability

- [ ] Central log aggregation receiving entries from all services
- [ ] Metrics pipeline (if any) intact

## Security

- [ ] Secrets rotated / re-injected in new pipelines
- [ ] No secrets present in git diffs (scan)

## Cleanup

- [ ] Monorepo archived read-only
- [ ] README updated with mapping
- [ ] Team onboarding docs updated

## Rollback Plan (If Needed)

- [ ] Monorepo branch freeze can be lifted quickly
- [ ] Deployment manifests for monorepo retained for 1 sprint
