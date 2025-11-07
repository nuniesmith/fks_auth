#!/bin/bash
# tailscale.sh
# Tailscale Configuration Script for Arch Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log "🔗 Tailscale Configuration for Arch Linux"
log "========================================="

# Check if Tailscale is installed
if ! command -v tailscale &> /dev/null; then
    error "Tailscale is not installed. Installing now..."
    sudo pacman -S --noconfirm tailscale
    sudo systemctl enable tailscaled
    sudo systemctl start tailscaled
fi

# Check daemon status
log "📊 Checking Tailscale daemon status..."
if systemctl is-active --quiet tailscaled; then
    success "Tailscale daemon is running"
else
    log "Starting Tailscale daemon..."
    sudo systemctl start tailscaled
    sleep 3
fi

# Show current status
log "📋 Current Tailscale status:"
tailscale status

echo ""
log "🔑 Tailscale Authentication Required"
echo ""

# Check if already logged in
if tailscale status | grep -q "Logged out"; then
    warning "Tailscale is not authenticated"
    echo ""
    echo "To connect this server to your Tailscale network:"
    echo ""
    echo "1. Get an auth key from: https://login.tailscale.com/admin/settings/keys"
    echo "2. Run one of these commands:"
    echo ""
    echo "   Basic connection:"
    echo "   sudo tailscale up --authkey=\"tskey-auth-YOUR-KEY-HERE\""
    echo ""
    echo "   With route acceptance (recommended):"
    echo "   sudo tailscale up --authkey=\"tskey-auth-YOUR-KEY-HERE\" --accept-routes"
    echo ""
    echo "   As exit node (optional):"
    echo "   sudo tailscale up --authkey=\"tskey-auth-YOUR-KEY-HERE\" --advertise-exit-node"
    echo ""
    
    # Interactive setup option
    echo "3. Or run this script interactively:"
    read -p "Do you have a Tailscale auth key ready? [y/N]: " has_key
    
    if [[ $has_key =~ ^[Yy]$ ]]; then
        echo ""
        read -p "Enter your Tailscale auth key: " auth_key
        
        if [[ $auth_key =~ ^tskey-auth- ]]; then
            echo ""
            echo "Authentication options:"
            echo "1. Basic connection"
            echo "2. Accept routes (recommended for accessing other devices)"
            echo "3. Advertise as exit node (route internet traffic)"
            echo ""
            read -p "Choose option [1-3]: " option
            
            case $option in
                1)
                    log "Connecting with basic settings..."
                    sudo tailscale up --authkey="$auth_key"
                    ;;
                2)
                    log "Connecting with route acceptance..."
                    sudo tailscale up --authkey="$auth_key" --accept-routes
                    ;;
                3)
                    log "Connecting as exit node..."
                    sudo tailscale up --authkey="$auth_key" --advertise-exit-node
                    ;;
                *)
                    warning "Invalid option, using basic connection..."
                    sudo tailscale up --authkey="$auth_key"
                    ;;
            esac
            
            # Wait for connection
            sleep 5
            
            log "📊 Updated Tailscale status:"
            tailscale status
            
            if tailscale status | grep -q "100\."; then
                success "Tailscale connected successfully!"
                TAILSCALE_IP=$(tailscale ip -4)
                echo ""
                echo "🌐 Your Tailscale IP: $TAILSCALE_IP"
                echo "🔗 Access your server at: http://$TAILSCALE_IP/"
                
                # Test web server access
                if curl -s http://localhost/ > /dev/null 2>&1; then
                    echo "✅ Web server is accessible via Tailscale"
                else
                    warning "Web server may not be running. Check NGINX status."
                fi
            else
                error "Tailscale connection failed. Check the auth key and try again."
            fi
        else
            error "Invalid auth key format. Should start with 'tskey-auth-'"
        fi
    else
        echo ""
        warning "Get your auth key from: https://login.tailscale.com/admin/settings/keys"
        echo "Then run this script again or use the manual commands above."
    fi
    
elif tailscale status | grep -q "100\."; then
    success "Tailscale is already connected!"
    TAILSCALE_IP=$(tailscale ip -4)
    echo ""
    echo "🌐 Your Tailscale IP: $TAILSCALE_IP"
    echo "🔗 Access your server at: http://$TAILSCALE_IP/"
    
    # Show network info
    echo ""
    log "📋 Tailscale Network Information:"
    tailscale status
    
else
    warning "Tailscale is in an unknown state. Check manually with 'tailscale status'"
fi

echo ""
log "🛠️ Tailscale Management Commands:"
echo "• Status: tailscale status"
echo "• IP address: tailscale ip -4"
echo "• Logout: sudo tailscale logout"
echo "• Reconnect: sudo tailscale up --authkey=\"YOUR-KEY\""
echo "• File sharing: tailscale file get"
echo "• SSH access: tailscale ssh user@device-name"

echo ""
log "🔥 Firewall Configuration:"
echo "Tailscale traffic should be allowed by default."
echo "If you're using UFW, ensure Tailscale interface is allowed:"
echo "sudo ufw allow in on tailscale0"

# Check if UFW is active and configure it
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    log "🔥 Configuring UFW for Tailscale..."
    sudo ufw allow in on tailscale0
    success "UFW configured for Tailscale"
fi

echo ""
log "📱 Mobile/Desktop Access:"
echo "Install Tailscale on your devices to access this server:"
echo "• iOS/Android: Search 'Tailscale' in app store"
echo "• Windows/Mac/Linux: Download from https://tailscale.com/download"
echo "• Use the same Tailscale account to see this server"

echo ""
success "Tailscale configuration complete! 🎉"

# Final status display
echo ""
log "📊 Final Status Summary:"
if systemctl is-active --quiet tailscaled; then
    echo "✅ Tailscale daemon: Running"
else
    echo "❌ Tailscale daemon: Not running"
fi

if tailscale status | grep -q "100\."; then
    echo "✅ Tailscale network: Connected"
    echo "🌐 Server IP: $(tailscale ip -4 2>/dev/null || echo 'Not available')"
elif tailscale status | grep -q "Logged out"; then
    echo "⚠️  Tailscale network: Authentication required"
else
    echo "❓ Tailscale network: Unknown state"
fi

echo ""
warning "Save this information securely:"
echo "• Your Tailscale admin panel: https://login.tailscale.com/admin"
echo "• This server's Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'Configure authentication first')"