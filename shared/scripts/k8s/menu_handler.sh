#!/usr/bin/env bash
# ============================================================
# Script Name: Kubernetes Menu Handler
# Description: Menu system for Kubernetes management
# ============================================================

# View Kubernetes pod logs
view_k8s_pod_logs() {
    log_info "Checking pods in namespace: $NAMESPACE"
    kubectl get pods -n "$NAMESPACE"
    
    echo -e "${BLUE}Enter the pod name:${NC} "
    read -r pod_name
    
    if [[ -z "$pod_name" ]]; then
        log_error "Pod name cannot be empty."
        return 1
    fi
    
    if ! kubectl get pod "$pod_name" -n "$NAMESPACE" &>/dev/null; then
        log_error "Pod $pod_name not found in namespace $NAMESPACE."
        return 1
    fi
    
    # Check if pod has multiple containers
    local containers
    containers=$(kubectl get pod "$pod_name" -n "$NAMESPACE" -o jsonpath='{.spec.containers[*].name}')
    container_count=$(echo "$containers" | wc -w)
    
    local container=""
    if [[ $container_count -gt 1 ]]; then
        log_info "Pod has multiple containers. Available containers: $containers"
        echo -e "${BLUE}Enter container name (leave blank for first container):${NC} "
        read -r container
    fi
    
    log_info "Found pod: $pod_name. Fetching logs..."
    
    local options=(
        "Current Logs"
        "Previous Logs"
        "Follow Logs"
        "All Containers"
        "Return to Resources Menu"
    )
    
    echo "Log Options for $pod_name:"
    for i in "${!options[@]}"; do
        echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
    done
    
    echo -e "${BLUE}Enter your choice:${NC} "
    read -r log_choice
    
    # Build the container arg
    local container_arg=""
    if [[ -n "$container" ]]; then
        container_arg="-c $container"
    fi
    
    case "$log_choice" in
        0)
            log_info "Displaying current logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" $container_arg || log_error "Failed to fetch current logs."
            ;;
        1)
            log_info "Displaying previous logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" --previous $container_arg || log_error "Failed to fetch previous logs."
            ;;
        2)
            log_info "Following logs for $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" -f $container_arg || log_error "Failed to follow logs."
            ;;
        3)
            log_info "Displaying logs for all containers in $pod_name:"
            kubectl logs "$pod_name" -n "$NAMESPACE" --all-containers=true || log_error "Failed to fetch logs for all containers."
            ;;
        4)
            return
            ;;
        *)
            log_error "Invalid choice. Please select a valid option."
            ;;
    esac
}

# Generate specific resources menu
generate_specific_resources_menu() {
    local options=(
        "ConfigMaps"
        "Secrets"
        "Services"
        "Ingress Resources"
        "Deployments"
        "StatefulSets"
        "DaemonSets"
        "PersistentVolumeClaims"
        "NetworkPolicies"
        "Roles and RoleBindings"
        "ServiceAccounts"
        "Return to Main Menu"
    )
    
    while true; do
        print_header "Generate Specific Resources Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                generate_specific_resources "configmap"
                ;;
            1)
                generate_specific_resources "secret"
                ;;
            2)
                generate_specific_resources "service"
                ;;
            3)
                generate_specific_resources "ingress"
                ;;
            4)
                generate_specific_resources "deployment"
                ;;
            5)
                generate_specific_resources "statefulset"
                ;;
            6)
                generate_specific_resources "daemonset"
                ;;
            7)
                generate_specific_resources "pvc"
                ;;
            8)
                generate_specific_resources "networkpolicy"
                ;;
            9)
                generate_specific_resources "role"
                ;;
            10)
                generate_specific_resources "serviceaccount"
                ;;
            11)
                return
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

view_k8s_resources_menu() {
    local options=(
        "View All Resources"
        "View Pods"
        "View Deployments"
        "View StatefulSets"
        "View Services"
        "View ConfigMaps"
        "View Secrets"
        "View Ingress"
        "View PersistentVolumeClaims"
        "View NetworkPolicies"
        "View Roles and RoleBindings"
        "View ServiceAccounts"
        "View Pod Logs"
        "Return to Main Menu"
    )
    
    while true; do
        print_header "Kubernetes Resources Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                kubectl get all -n "$NAMESPACE"
                ;;
            1)
                kubectl get pods -n "$NAMESPACE"
                ;;
            2)
                kubectl get deployments -n "$NAMESPACE"
                ;;
            3)
                kubectl get statefulsets -n "$NAMESPACE"
                ;;
            4)
                kubectl get services -n "$NAMESPACE"
                ;;
            5)
                kubectl get configmaps -n "$NAMESPACE"
                ;;
            6)
                kubectl get secrets -n "$NAMESPACE"
                ;;
            7)
                kubectl get ingress -n "$NAMESPACE"
                ;;
            8)
                kubectl get pvc -n "$NAMESPACE"
                ;;
            9)
                kubectl get networkpolicies -n "$NAMESPACE"
                ;;
            10)
                kubectl get roles,rolebindings -n "$NAMESPACE"
                ;;
            11)
                kubectl get serviceaccounts -n "$NAMESPACE"
                ;;
            12)
                view_k8s_pod_logs
                ;;
            13)
                return
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

main_menu() {
    local options=(
        "Set up Kubernetes Master Node"
        "Set up Kubernetes Worker Node"
        "Remove Kubernetes Setup"
        "Start Minikube"
        "Stop Minikube"
        "Check Minikube Status"
        "Reset & Apply K8s Resources"
        "Generate Kubernetes Resources"
        "Generate Specific Resources"
        "Convert Docker Compose to K8s"
        "Restart All Deployments"
        "View Kubernetes Resources"
        "Access Kubernetes Dashboard"
        "Change Namespace"
        "Check Directory Structure"
        "Exit"
    )

    while true; do
        print_header "Kubernetes Management Menu"
        
        for i in "${!options[@]}"; do
            echo -e " ${BOLD}[$i]${NC} ${options[$i]}"
        done
        
        echo
        echo -e "${BLUE}Current namespace: ${YELLOW}$NAMESPACE${NC}"
        echo
        echo -e "${BLUE}Enter your choice:${NC} "
        read -r choice
        
        case "$choice" in
            0)
                run_master_script
                ;;
            1)
                run_worker_script
                ;;
            2)
                run_remove_script
                ;;
            3)
                echo -e "${BLUE}Enter driver (default: docker):${NC} "
                read -r driver
                start_minikube "${driver:-docker}"
                ;;
            4)
                stop_minikube
                ;;
            5)
                check_minikube_status
                ;;
            6)
                run_apply_resources_script
                ;;
            7)
                run_resource_generator
                ;;
            8)
                generate_specific_resources_menu
                ;;
            9)
                convert_docker_compose
                ;;
            10)
                restart_k8s_deployments
                ;;
            11)
                view_k8s_resources_menu
                ;;
            12)
                access_k8s_dashboard
                ;;
            13)
                change_namespace
                ;;
            14)
                check_directory_structure
                ;;
            15)
                log_info "Exiting Kubernetes Manager."
                exit 0
                ;;
            *)
                log_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo
        echo -e "${BLUE}Press Enter to continue...${NC}"
        read -r
    done
}

# Function to print a nice header for menus
print_header() {
    local title="$1"
    local width=80
    local line=$(printf '%*s\n' "$width" '' | tr ' ' '=')
    
    echo -e "\n${GREEN}$line${NC}"
    echo -e "${GREEN}$(printf '%*s\n' $(((${#title}+$width)/2)) "$title")${NC}"
    echo -e "${GREEN}$line${NC}\n"
}