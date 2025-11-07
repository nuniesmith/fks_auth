#!/bin/bash

# Ubuntu Server 24.04 Development Environment Setup Script
# This script sets up Docker, creates users, and configures the system for development

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Starting Ubuntu Server 24.04 development environment setup..."

# Set hostname
print_status "Setting hostname to 'fks'..."
hostnamectl set-hostname fks
echo "127.0.0.1 fks" >> /etc/hosts

# Update and upgrade system
print_status "Updating package lists and upgrading system..."
apt update
apt upgrade -y

# Install essential packages
print_status "Installing essential packages..."
apt install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    tree \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Install Docker Engine
print_status "Installing Docker Engine..."

# Remove any old Docker installations
apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package index
apt update

# Install Docker Engine, CLI, and containerd
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker service
systemctl start docker
systemctl enable docker

# Verify Docker installation
print_status "Verifying Docker installation..."
docker --version
docker compose version

# Create users
print_status "Creating user accounts..."

# Create fks_user
if id "fks_user" &>/dev/null; then
    print_warning "User 'fks_user' already exists, skipping creation"
else
    useradd -m -s /bin/bash fks_user
    print_status "Created user 'fks_user'"
fi

# Create jordan user
if id "jordan" &>/dev/null; then
    print_warning "User 'jordan' already exists, skipping creation"
else
    useradd -m -s /bin/bash jordan
    print_status "Created user 'jordan'"
fi

# Add users to docker group
usermod -aG docker fks_user
usermod -aG docker jordan
print_status "Added users to docker group"

# Add jordan to sudo group for administrative tasks
usermod -aG sudo jordan
print_status "Added jordan to sudo group"

# Set up SSH directory and basic security for users
for user in fks_user jordan; do
    user_home="/home/$user"
    mkdir -p "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    touch "$user_home/.ssh/authorized_keys"
    chmod 600 "$user_home/.ssh/authorized_keys"
    chown -R "$user:$user" "$user_home/.ssh"
    print_status "Set up SSH directory for $user"
done

# Configure SSH for development (optional security improvements)
print_status "Configuring SSH for development..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Basic SSH hardening while keeping it developer-friendly
cat >> /etc/ssh/sshd_config << 'EOF'

# Development-friendly SSH configuration
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
ClientAliveInterval 600
ClientAliveCountMax 2
EOF

# Restart SSH service
systemctl restart sshd

# Install additional development tools
print_status "Installing additional development tools..."
apt install -y \
    build-essential \
    default-jdk \
    sqlite3 \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Install .NET SDK and Runtime
print_status "Installing .NET SDK and Runtime..."
wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
apt update
apt install -y dotnet-sdk-8.0 dotnet-runtime-8.0 aspnetcore-runtime-8.0

# Install Node.js (Latest LTS) via NodeSource
print_status "Installing Node.js (Latest LTS)..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt install -y nodejs

# Install Yarn (alternative package manager)
npm install -g yarn

# Install Rust via rustup for both users
print_status "Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Install Rust for fks_user
sudo -u fks_user bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
sudo -u fks_user bash -c 'source ~/.cargo/env && rustup update'

# Install Rust for jordan
sudo -u jordan bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
sudo -u jordan bash -c 'source ~/.cargo/env && rustup update'

# Install React Native CLI and dependencies
print_status "Installing React Native development tools..."
npm install -g @react-native-community/cli react-native-cli expo-cli

# Install Android development tools for React Native
print_status "Installing Android development dependencies..."
apt install -y openjdk-17-jdk

# Install additional Python tools
print_status "Installing additional Python development tools..."
pip3 install --upgrade pip
pip3 install virtualenv pipenv poetry jupyter notebook pandas numpy matplotlib requests flask django fastapi

# Install additional Node.js development tools
print_status "Installing additional Node.js development tools..."
npm install -g typescript ts-node create-react-app next@latest @angular/cli vue@next nuxt create-expo-app

# Add environment variables for development
print_status "Setting up development environment variables..."
cat >> /etc/environment << 'EOF'
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ANDROID_HOME=/opt/android-sdk
PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools
EOF

# Set up Rust environment for users
print_status "Setting up Rust environment for users..."
for user in fks_user jordan; do
    user_home="/home/$user"
    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$user_home/.bashrc"
    echo 'source ~/.cargo/env' >> "$user_home/.bashrc"
    chown "$user:$user" "$user_home/.bashrc"
done

# Create development directories
print_status "Creating development directories..."
for user in fks_user jordan; do
    user_home="/home/$user"
    mkdir -p "$user_home/projects"
    mkdir -p "$user_home/scripts"
    chown -R "$user:$user" "$user_home/projects" "$user_home/scripts"
done

# Set up firewall (UFW) with basic rules
print_status "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000:8000/tcp  # Common development ports
print_status "Firewall configured with basic rules"

# Create a welcome message
cat > /etc/motd << 'EOF'
===============================================
    FKS Development Server - Ubuntu 24.04
===============================================

🐳 Docker Engine: Installed and running
🐳 Docker Compose: Available as 'docker compose'

👥 Users created:
- fks_user (docker group)
- jordan (docker, sudo groups)

🛠️  Development Stack:
- .NET SDK 8.0 & Runtime
- Node.js (Latest LTS) + npm + yarn
- Python 3 + pip + venv + popular packages
- Rust (rustup) + cargo
- React Native CLI + Expo CLI
- TypeScript, Angular CLI, Vue CLI, Next.js
- Java 17 JDK

🔥 Development ports 3000-8000 are open in firewall.

Happy coding! 🚀
===============================================
EOF

# Final system cleanup
print_status "Cleaning up..."
apt autoremove -y
apt autoclean

# Display final information
print_status "Setup completed successfully!"
echo
echo "=== SETUP SUMMARY ==="
echo "✅ System updated and upgraded"
echo "✅ Docker Engine installed and running"
echo "✅ Docker Compose plugin installed"
echo "✅ Hostname set to 'fks'"
echo "✅ Users created: fks_user, jordan"
echo "✅ SSH configured for development"
echo "✅ Firewall configured"
echo "✅ .NET SDK 8.0 & Runtime installed"
echo "✅ Node.js (Latest LTS) + npm + yarn installed"
echo "✅ Python 3 + development packages installed"
echo "✅ Rust + cargo installed for all users"
echo "✅ React Native CLI + Expo CLI installed"
echo "✅ TypeScript, Angular CLI, Vue CLI, Next.js installed"
echo "✅ Java 17 JDK installed"
echo
echo "=== NEXT STEPS ==="
echo "1. Set passwords for new users:"
echo "   sudo passwd fks_user"
echo "   sudo passwd jordan"
echo
echo "2. Add your SSH public key to authorized_keys:"
echo "   /home/${USER}/.ssh/authorized_keys"
echo "   /home/fks_user/.ssh/authorized_keys"
echo
echo "3. Test installations:"
echo "   su - jordan"
echo "   docker run hello-world"
echo "   node --version"
echo "   python3 --version"
echo "   dotnet --version"
echo "   cargo --version"
echo "   npx react-native --version"
echo
echo "4. Connect from VS Code using SSH:"
echo "   ssh jordan@$(hostname -I | awk '{print $1}')"
echo
echo "5. For React Native development:"
echo "   - Install Android Studio on your local machine"
echo "   - Set up device/emulator forwarding over SSH"
echo "   - Or use Expo for easier development"
echo
print_status "Reboot recommended to ensure all changes take effect"