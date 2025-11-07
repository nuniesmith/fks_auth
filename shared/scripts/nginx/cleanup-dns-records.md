# DNS Cleanup Plan for 7gram.xyz

## Records to DELETE (Unused Sullivan Services)
These all point to 100.96.229.27 (Sullivan) but are not managed by any workflow:

```bash
# Delete these A records from Cloudflare:
abs.7gram.xyz
ai.7gram.xyz  
audiobooks.7gram.xyz
calibre.7gram.xyz
calibreweb.7gram.xyz
chat.7gram.xyz
code.7gram.xyz
comfy.7gram.xyz
dns.7gram.xyz
duplicati.7gram.xyz
ebooks.7gram.xyz
emby.7gram.xyz
filebot.7gram.xyz
grafana.7gram.xyz
grocy.7gram.xyz
home.7gram.xyz
imap.7gram.xyz
jackett.7gram.xyz
jellyfin.7gram.xyz
lidarr.7gram.xyz
mail.7gram.xyz
mealie.7gram.xyz
monitor.7gram.xyz
music.7gram.xyz
nc.7gram.xyz
ollama.7gram.xyz
pihole.7gram.xyz
plex.7gram.xyz
portainer.7gram.xyz
prometheus.7gram.xyz
proxy.7gram.xyz
qbt.7gram.xyz
radarr.7gram.xyz
remote.7gram.xyz
sd.7gram.xyz
smtp.7gram.xyz
sonarr.7gram.xyz
status.7gram.xyz
sync-desktop.7gram.xyz
sync-freddy.7gram.xyz
sync-oryx.7gram.xyz
sync-sullivan.7gram.xyz
uptime.7gram.xyz
vpn.7gram.xyz
watchtower.7gram.xyz
whisper.7gram.xyz
wiki.7gram.xyz
youtube.7gram.xyz
```

## Records to KEEP (Currently Managed)

### FKS Services (fkstrading.xyz)
- ✅ Managed by FKS workflow
- ✅ Uses custom domain configuration

### ATS Services (Keep as-is)
```bash
ats.7gram.xyz → 100.82.241.106
api.ats.7gram.xyz → 100.81.66.40  
www.ats.7gram.xyz → 100.81.66.40
game.7gram.xyz → 100.82.241.106
server.7gram.xyz → 100.82.241.106
```

### Nginx/Root Domain (7gram.xyz)
```bash
7gram.xyz → [Nginx Tailscale IP] (managed by nginx workflow)
www.7gram.xyz → [Nginx Tailscale IP] (managed by nginx workflow)  
nginx.7gram.xyz → [Nginx Tailscale IP] (managed by nginx workflow)
```

### Static/Personal Records
```bash
freddy.7gram.xyz → 100.121.199.80 (Home automation)
sullivan.7gram.xyz → 100.86.22.59 (Main media server)
```

## Special Records to Review
```bash
*.7gram.xyz → 100.84.200.116 (Wildcard - may conflict)
admin.7gram.xyz → 100.79.200.41
internal-nginx.7gram.xyz → 100.79.200.41
tailnet.7gram.xyz → 100.79.200.41
ts-nginx.7gram.xyz → 100.79.200.41
portainer-freddy.7gram.xyz → 100.84.200.116
portainer-sullivan.7gram.xyz → 100.84.200.116
fkstrading.xyz.7gram.xyz → 172.105.24.125 (Seems like a mistake)
nodes.7gram.xyz → 172.105.24.125
```

## Action Required:
1. Delete all the unused Sullivan service records
2. Keep ATS records as-is  
3. Ensure nginx workflow manages root domain properly
4. Review and clean up special records
