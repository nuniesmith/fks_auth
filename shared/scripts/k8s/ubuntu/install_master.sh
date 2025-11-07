#!/bin/bash
# Kubernetes Master Node Setup Script for Ubuntu 24.04
# This script will set up a Kubernetes master node on Ubuntu 24.04

# Exit on any error
set -e

# Display execution steps
set -x

# 1. Update the system
echo "[1/7] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
echo "[2/7] Installing dependencies..."
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# 3. Set up containerd as the container runtime
echo "[3/7] Setting up containerd..."
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
echo "[4/7] Installing Kubernetes components..."
# Add Kubernetes apt repository
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Update apt and install kubelet, kubeadm, and kubectl
sudo apt update
sudo apt install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# 5. Initialize the Kubernetes master node
echo "[5/7] Initializing Kubernetes master node..."
# Disable swap (required for Kubernetes)
sudo swapoff -a
# Comment out swap entries in /etc/fstab
sudo sed -i '/swap/s/^/#/' /etc/fstab

# Initialize the master node
sudo kubeadm init --pod-network-cidr=192.168.0.0/16

# Set up kubeconfig for the current user
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# 6. Install Calico network plugin
echo "[6/7] Installing Calico network plugin..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

# 7. Generate join command for worker nodes
echo "[7/7] Generating join command for worker nodes..."
JOIN_COMMAND=$(sudo kubeadm token create --print-join-command)
echo "Use the following command to join worker nodes to the cluster:"
echo $JOIN_COMMAND
echo "Save this command as you will need it to join worker nodes to the cluster."

# Verify the status of the master node
echo "Waiting for node to become ready..."
sleep 60
kubectl get nodes

echo "Kubernetes master node setup completed successfully!"
echo "You can now add worker nodes to your cluster using the join command provided above."