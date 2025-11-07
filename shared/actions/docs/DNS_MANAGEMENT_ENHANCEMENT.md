# 🌐 Enhanced DNS Management for Stage 2 Deployment

## Overview
The Stage 2 post-reboot script now includes comprehensive DNS management that automatically updates multiple Cloudflare DNS records based on the service being deployed.

## Service-Specific DNS Updates

### 🔗 **Nginx Service** 
When deploying nginx, the following **60+ DNS records** are automatically updated:

#### Core Infrastructure
- `nginx.7gram.xyz` - Main nginx service
- `7gram.xyz` - Root domain
- `www.7gram.xyz` - WWW redirect
- `*.7gram.xyz` - Wildcard subdomain
- `admin.7gram.xyz` - Administrative interface

#### Authentication & API
- `auth.7gram.xyz` - Authentication service
- `api.7gram.xyz` - API gateway

#### Media Streaming Services
- `emby.7gram.xyz` - Emby media server
- `jellyfin.7gram.xyz` - Jellyfin media server
- `plex.7gram.xyz` - Plex media server
- `music.7gram.xyz` - Music streaming
- `youtube.7gram.xyz` - YouTube-related services

#### File Management & Productivity
- `nc.7gram.xyz` - Nextcloud
- `calibre.7gram.xyz` - Calibre ebook server
- `calibreweb.7gram.xyz` - Calibre web interface
- `abs.7gram.xyz` - AudioBookShelf
- `audiobooks.7gram.xyz` - Audiobook services
- `ebooks.7gram.xyz` - Ebook management
- `duplicati.7gram.xyz` - Backup solution
- `filebot.7gram.xyz` - File organization

#### Home Management
- `mealie.7gram.xyz` - Recipe management
- `grocy.7gram.xyz` - Household management
- `wiki.7gram.xyz` - Wiki/documentation
- `home.7gram.xyz` - Home Assistant

#### AI & Development
- `ai.7gram.xyz` - AI services
- `chat.7gram.xyz` - Chat interfaces
- `ollama.7gram.xyz` - Ollama AI
- `sd.7gram.xyz` - Stable Diffusion
- `comfy.7gram.xyz` - ComfyUI
- `whisper.7gram.xyz` - Whisper transcription
- `code.7gram.xyz` - Code editing

#### Media Management (*arr Stack)
- `sonarr.7gram.xyz` - TV show management
- `radarr.7gram.xyz` - Movie management
- `lidarr.7gram.xyz` - Music management
- `jackett.7gram.xyz` - Indexer proxy
- `qbt.7gram.xyz` - qBittorrent

#### Infrastructure & Monitoring
- `pihole.7gram.xyz` - Pi-hole DNS
- `dns.7gram.xyz` - DNS management
- `grafana.7gram.xyz` - Grafana monitoring
- `prometheus.7gram.xyz` - Prometheus metrics
- `uptime.7gram.xyz` - Uptime monitoring
- `watchtower.7gram.xyz` - Container updates
- `monitor.7gram.xyz` - General monitoring
- `nodes.7gram.xyz` - Node monitoring

#### Container Management
- `portainer.7gram.xyz` - Main Portainer
- `portainer-freddy.7gram.xyz` - Freddy Portainer
- `portainer-sullivan.7gram.xyz` - Sullivan Portainer

#### Communication
- `mail.7gram.xyz` - Mail service
- `smtp.7gram.xyz` - SMTP server
- `imap.7gram.xyz` - IMAP server

#### Sync Services
- `sync-desktop.7gram.xyz` - Desktop sync
- `sync-freddy.7gram.xyz` - Freddy sync
- `sync-oryx.7gram.xyz` - Oryx sync
- `sync-sullivan.7gram.xyz` - Sullivan sync

#### Utility
- `status.7gram.xyz` - Status page
- `vpn.7gram.xyz` - VPN access
- `remote.7gram.xyz` - Remote access
- `fkstrading.xyz.7gram.xyz` - Legacy FKS trading

### 🔥 **FKS Service**
When deploying FKS, the following **5 DNS records** are updated:
- `fks.7gram.xyz` - Main FKS interface
- `api.7gram.xyz` - API gateway
- `auth.7gram.xyz` - Authentication service
- `trading.7gram.xyz` - Trading interface
- `data.7gram.xyz` - Data services

### 🎮 **ATS Service**
**ATS records are EXCLUDED** from nginx deployment as requested. ATS will handle its own DNS when deployed separately.

### 🔧 **Other Services**
For any other service, only the main service record is updated (e.g., `service-name.7gram.xyz`).

## Technical Implementation

### 🔄 **DNS Update Process**
1. **Service Detection**: Determines service type from `SERVICE_NAME` variable
2. **Record Definition**: Creates array of DNS records based on service
3. **Batch Updates**: Updates all records with rate limiting (1 second between calls)
4. **Success Tracking**: Reports how many records were successfully updated

### 🛡️ **Error Handling**
- Individual record failures don't stop the process
- Detailed error logging for failed updates
- Success/failure summary at the end
- Automatic retry logic for existing vs. new records

### ⚡ **Performance Features**
- **Rate Limiting**: 1-second delay between API calls to respect Cloudflare limits
- **Efficient API Usage**: Checks for existing records before deciding to update or create
- **Low TTL**: Sets 120-second TTL for quick propagation
- **Parallel Safety**: Function-based approach prevents variable conflicts

## Configuration Requirements

### 🔑 **Required GitHub Secrets**
- `CLOUDFLARE_EMAIL` - Your Cloudflare account email
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token with Zone:Edit permissions
- `TAILSCALE_AUTH_KEY` - Tailscale auth key for VPN connection

### 🌐 **Domain Configuration**
- Base domain: `7gram.xyz`
- Zone must be managed in Cloudflare
- API token must have permissions for the zone

## Deployment Flow

### 📋 **Complete Process**
1. **Stage 1**: Server setup, package installation, user creation
2. **Reboot**: Server restarts to apply configurations
3. **Stage 2 Auto-Start**: systemd service triggers post-reboot script
4. **Tailscale Connection**: Connects to VPN and gets IP
5. **DNS Mass Update**: Updates all relevant DNS records
6. **Firewall Config**: Finalizes security settings

### ⏱️ **Timing**
- Stage 2 runs automatically ~30 seconds after reboot
- DNS updates take 1-3 minutes depending on record count
- DNS propagation typically completes within 2-5 minutes

## Exclusions

### ❌ **ATS Records Excluded**
The following ATS-related records are intentionally **NOT** updated by nginx deployment:
- `ats.7gram.xyz` → `100.126.196.23` (ATS Game Server)
- `api.ats.7gram.xyz` → `100.81.66.40` (ATS API)
- `www.ats.7gram.xyz` → `100.81.66.40` (ATS Web)

### 🏠 **Server-Specific Records Excluded**
These records point to specific servers and are **NOT** updated by nginx deployment:
- `freddy.7gram.xyz` → `100.121.199.80` (Home automation server)
- `sullivan.7gram.xyz` → `100.86.22.59` (Main media server)

These will be handled by separate ATS deployment processes or remain pointing to their dedicated servers.

## Benefits

### 🚀 **Automation**
- **Zero Manual DNS Work**: All records updated automatically
- **Service-Aware**: Different record sets for different services
- **Failure Resilient**: Individual record failures don't break deployment

### 🔄 **Scalability**
- **Easy Addition**: New subdomains just need to be added to the array
- **Service Expansion**: New services get their own record definitions
- **Multi-Environment**: Works with any domain by changing configuration

### 📊 **Visibility**
- **Clear Logging**: Shows exactly which records were updated
- **Success Metrics**: Reports update success/failure ratios
- **Error Details**: Provides specific error messages for troubleshooting

This enhancement transforms the deployment from updating a single DNS record to a comprehensive DNS management system that handles all your proxy routing needs automatically! 🎉
