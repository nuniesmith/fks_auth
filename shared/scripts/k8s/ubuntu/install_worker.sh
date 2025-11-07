#!/bin/bash
# Kubernetes Worker Node Setup Script for Ubuntu 24.04
# This script prepares a worker node to join an existing Kubernetes cluster

# Exit on any error
set -e

# Display execution steps
set -x

# 1. Update the system
echo "[1/5] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
echo "[2/5] Installing dependencies..."
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# 3. Set up containerd as the container runtime
echo "[3/5] Setting up containerd..."
# Load necessary modules
sudo modprobe overlay
sudo modprobe br_netfilter

# Setup required kernel parameters
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Apply sysctl parameters
sudo sysctl --system

# Install containerd
sudo apt install -y containerd

# Configure containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# Update containerd configuration for Kubernetes
sudo sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml

# Restart containerd
sudo systemctl restart containerd
sudo systemctl enable containerd

# 4. Install Kubernetes components
echo "[4/5] Installing Kubernetes components..."
# Add Kubernetes apt repository
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Update apt and install kubelet, kubeadm, and kubectl
sudo apt update
sudo apt install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# 5. Prepare the system for Kubernetes
echo "[5/5] Preparing system for Kubernetes..."
# Disable swap (required for Kubernetes)
sudo swapoff -a
# Comment out swap entries in /etc/fstab
sudo sed -i '/swap/s/^/#/' /etc/fstab

# Completion message
echo "Worker node preparation completed successfully!"
echo "To join this worker to the Kubernetes cluster, run the 'kubeadm join' command"
echo "from your master node. It should look like:"
echo "sudo kubeadm join <master-ip>:6443 --token <token> --discovery-token-ca-cert-hash <hash>"
echo ""
echo "If you need to generate a new join command on the master node, run:"
echo "sudo kubeadm token create --print-join-command"