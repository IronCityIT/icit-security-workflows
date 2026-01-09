#!/bin/bash
# Iron City IT - Master Deployment Script
# Usage: ./deploy.sh [component]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_COMPOSE_DIR="$SCRIPT_DIR/docker-compose"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║          IRON CITY IT - Security Stack Deployer           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

deploy_defectdojo() {
    echo "Deploying DefectDojo..."
    cd "$DOCKER_COMPOSE_DIR/defectdojo"
    docker-compose up -d
    print_success "DefectDojo deployed at https://defectdojo.ironcityit.com"
    echo "Default credentials: admin / Check docker logs for initial password"
}

deploy_misp() {
    echo "Deploying MISP..."
    cd "$DOCKER_COMPOSE_DIR/misp"
    docker-compose up -d
    print_success "MISP deployed at https://misp.ironcityit.com"
    echo "Default credentials: admin@admin.test / admin (CHANGE IMMEDIATELY)"
}

deploy_webcheck() {
    echo "Deploying web-check..."
    cd "$DOCKER_COMPOSE_DIR/webcheck"
    docker-compose up -d
    print_success "web-check deployed at https://webcheck.ironcityit.com"
}

deploy_threatingestor() {
    echo "Deploying ThreatIngestor..."
    cd "$DOCKER_COMPOSE_DIR/threatingestor"
    docker-compose up -d
    print_success "ThreatIngestor running as background service"
    echo "Check logs: docker-compose logs -f threatingestor"
}

deploy_atomic() {
    echo "Atomic Red Team is client-side only."
    echo ""
    echo "To install on Windows target:"
    echo "  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)"
    echo "  Install-AtomicRedTeam -getAtomics"
    echo ""
    echo "To run a test:"
    echo "  Invoke-AtomicTest T1003.001 -TestNumbers 1"
}

deploy_offensive() {
    print_warning "OFFENSIVE TOOLS DEPLOYMENT"
    echo ""
    echo "These tools require WRITTEN CLIENT AUTHORIZATION before use."
    echo ""
    read -p "Do you have signed authorization for this engagement? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        print_error "Deployment cancelled. Get authorization first."
        exit 1
    fi
    
    read -p "Client name: " client_name
    read -p "Authorization document path: " auth_path
    
    if [ ! -f "$auth_path" ]; then
        print_error "Authorization document not found at $auth_path"
        exit 1
    fi
    
    # Log the deployment
    mkdir -p "$SCRIPT_DIR/engagements/$client_name/logs"
    echo "$(date): Offensive tools deployed for $client_name" >> "$SCRIPT_DIR/engagements/$client_name/logs/deployment.log"
    echo "Authorization: $auth_path" >> "$SCRIPT_DIR/engagements/$client_name/logs/deployment.log"
    
    echo "Deploying Empire and Veil..."
    cd "$DOCKER_COMPOSE_DIR/offensive"
    docker-compose up -d
    
    print_success "Offensive tools deployed"
    echo "Empire: https://localhost:1337 (Starkiller GUI)"
    echo "All activities are being logged to engagements/$client_name/logs/"
}

stop_all() {
    echo "Stopping all services..."
    for dir in "$DOCKER_COMPOSE_DIR"/*/; do
        if [ -f "$dir/docker-compose.yml" ]; then
            cd "$dir"
            docker-compose down 2>/dev/null || true
        fi
    done
    print_success "All services stopped"
}

show_status() {
    echo "Service Status:"
    echo "==============="
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(defectdojo|misp|webcheck|threatingestor|empire|veil)" || echo "No Iron City services running"
}

show_help() {
    echo "Usage: ./deploy.sh [command]"
    echo ""
    echo "Commands:"
    echo "  defectdojo      Deploy DefectDojo vulnerability management"
    echo "  misp            Deploy MISP threat intelligence platform"
    echo "  webcheck        Deploy web-check quick scanner"
    echo "  threatingestor  Deploy ThreatIngestor IOC automation"
    echo "  atomic          Show Atomic Red Team installation instructions"
    echo "  offensive       Deploy Empire/Veil (REQUIRES AUTHORIZATION)"
    echo "  stop            Stop all services"
    echo "  status          Show running services"
    echo "  all             Deploy all non-offensive tools"
    echo ""
}

# Main
print_banner
check_docker

case "$1" in
    defectdojo)
        deploy_defectdojo
        ;;
    misp)
        deploy_misp
        ;;
    webcheck)
        deploy_webcheck
        ;;
    threatingestor)
        deploy_threatingestor
        ;;
    atomic)
        deploy_atomic
        ;;
    offensive)
        deploy_offensive
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    all)
        deploy_defectdojo
        deploy_misp
        deploy_webcheck
        deploy_threatingestor
        ;;
    *)
        show_help
        ;;
esac
