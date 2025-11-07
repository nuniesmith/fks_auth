# 🔄 Migration Guide: Integrating Your Repositories

This guide shows you how to integrate your existing FKS, NGINX, and ATS repositories with your new standardized GitHub Actions repository.

## 📋 Prerequisites

1. ✅ Your standardized actions repository is set up: `nuniesmith/actions`
2. ✅ All secrets are configured in the actions repository
3. ✅ Service configurations are complete in `services/` directory

## 🔧 Step 1: Backup Existing Workflows

For each of your service repositories (FKS, NGINX, ATS):

```bash
# Create backup of existing workflows
cd your-service-repo
mkdir -p .github/workflows/backup
mv .github/workflows/*.yml .github/workflows/backup/
```

## 🚀 Step 2: Create New Deployment Workflows

### For FKS Repository

1. Create `.github/workflows/deploy.yml`:

```yaml
# Copy from examples/service-repo-integration/fks_deploy.yml
```

2. Update service-specific settings if needed

### For NGINX Repository

1. Create `.github/workflows/deploy.yml`:

```yaml
# Copy from examples/service-repo-integration/nginx-deploy.yml
```

### For ATS Repository

1. Create `.github/workflows/deploy.yml`:

```yaml
# Copy from examples/service-repo-integration/ats-deploy.yml
```

## 🔑 Step 3: Migrate Secrets

Your secrets should already be set up in the `nuniesmith/actions` repository. Verify these exist:

```bash
# Check your standardized actions repository secrets
# Go to: https://github.com/nuniesmith/actions/settings/secrets/actions
```

**Required secrets:**
- `LINODE_CLI_TOKEN`
- `FKS_ROOT_PASSWORD`, `NGINX_ROOT_PASSWORD`, `ATS_ROOT_PASSWORD`
- `JORDAN_PASSWORD`
- `ACTIONS_USER_PASSWORD`
- `TAILSCALE_AUTH_KEY`
- `TAILSCALE_OAUTH_CLIENT_ID`
- `TAILSCALE_OAUTH_SECRET`
- `JWT_SECRET`
- `NETDATA_CLAIM_TOKEN`
- `NETDATA_CLAIM_ROOM`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `DISCORD_WEBHOOK`

## 🔄 Step 4: Test the Integration

### Test Deployment from Service Repository

1. **Go to your service repository** (e.g., FKS repo)
2. **Navigate to Actions tab**
3. **Run "Deploy FKS Service" workflow**
4. **Choose deployment mode:**
   - `health-check` - Safe test without changes
   - `update-only` - Update existing deployment
   - `full-deploy` - Complete new deployment

### Verify Results

After deployment, check:

```bash
# ✅ Server is running
ssh jordan@fks.7gram.xyz "uptime"

# ✅ Services are active
ssh fks_user@fks.7gram.xyz "docker ps"

# ✅ Monitoring is connected
curl https://fks.7gram.xyz/netdata/api/v1/info

# ✅ Application is responding
curl https://fks.7gram.xyz/api/health
```

## 📊 Step 5: Monitor and Verify

### Check All Services

```bash
# FKS
curl https://fks.7gram.xyz/api/health

# NGINX
curl https://nginx.7gram.xyz/

# ATS
curl https://ats.7gram.xyz/api/health
```

### Verify Netdata Integration

1. Visit: https://app.netdata.cloud
2. Check that all services appear in your space
3. Verify metrics are flowing

## 🔧 Troubleshooting Common Issues

### Issue: Workflow Not Found

**Error:** `The workflow 'nuniesmith/actions/.github/workflows/deploy-service.yml@main' is not found`

**Solution:**
1. Verify the actions repository exists and is public
2. Check the workflow file path is correct
3. Ensure you're using the correct branch (`@main`)

### Issue: Secret Not Available

**Error:** `Secret LINODE_CLI_TOKEN is not available`

**Solution:**
1. Verify secrets are set in the `nuniesmith/actions` repository
2. Check secret names match exactly (case-sensitive)
3. Ensure your service repository has access to call the reusable workflow

### Issue: Service Not Starting

**Error:** Service deploys but doesn't start

**Solution:**
1. Check service configuration in `services/[service-name]/config.yml`
2. Verify Docker Compose files are correct
3. Check user permissions and environment variables

## 🎯 Step 6: Customize for Your Needs

### Add Service-Specific Steps

Each service can have custom post-deployment steps:

```yaml
# In your service repo's deploy.yml
  custom-post-deploy:
    needs: deploy-service
    runs-on: ubuntu-latest
    steps:
      - name: 🎯 Custom Service Setup
        run: |
          # Your service-specific commands
          ssh service_user@service.7gram.xyz "custom-setup-command"
```

### Override Default Settings

```yaml
# In your service repo's deploy.yml
uses: nuniesmith/actions/.github/workflows/deploy-service.yml@main
with:
  service_name: myservice
  server_type: g6-standard-4  # Override default server size
  target_region: us-east      # Override default region
  # ... other overrides
```

## ✅ Verification Checklist

- [ ] All three service repositories have new deployment workflows
- [ ] Workflows successfully call the standardized actions
- [ ] All secrets are properly configured
- [ ] Test deployments work for all services
- [ ] Health checks pass for all services
- [ ] Netdata monitoring is connected
- [ ] Custom post-deployment steps work
- [ ] Old workflow files are backed up

## 🎉 Success!

You now have a standardized deployment process across all your services! 

**Benefits you're now getting:**
- ✅ Consistent deployment process
- ✅ Centralized secret management
- ✅ Standardized user management
- ✅ Unified monitoring setup
- ✅ Easy troubleshooting
- ✅ Reusable infrastructure patterns

**Next steps:**
- Monitor your deployments for a few days
- Gradually retire old deployment methods
- Consider adding more services using the same pattern
