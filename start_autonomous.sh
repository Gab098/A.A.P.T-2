#!/bin/bash

# A.A.P.T. - Avvio Sistema Autonomo
# Script per avviare rapidamente il sistema di pianificazione autonoma

set -e

echo🚀 A.A.P.T. - Avvio Sistema Autonomo"
echo "=================================="

# Colori per output
RED=undefined0330;31
GREEN='\033;32m'
YELLOW='\331;33mBLUE=0330;34
NC='\33[0m' # No Color

# Funzione per stampare messaggi colorati
print_status()[object Object]
    echo -e ${BLUE}[INFO]${NC} $1}

print_success() [object Object]  echo -e ${GREEN}[SUCCESS]${NC} $1}

print_warning() [object Object]   echo -e ${YELLOW}[WARNING]${NC} $1
}

print_error()[object Object]    echo -e ${RED}[ERROR]${NC} $1"
}

# Verifica prerequisiti
check_prerequisites() [object Object]    print_status "Verifica prerequisiti..."
    
    # Verifica Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker non trovato. Installa Docker prima di continuare."
        exit1
    fi
    
    # Verifica Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose non trovato. Installa Docker Compose prima di continuare."
        exit1
    fi
    
    # Verifica modello Phi-3
    MODEL_PATH="./models/Microsoft/phi-3mini-4k-instruct-q43mini-4k-instruct-q4gguf   if [ ! -f "$MODEL_PATH" ]; then
        print_warning Modello Phi-3on trovato in $MODEL_PATH"
        print_status "Assicurati di aver scaricato il modello prima di continuare."
        print_status "Il sistema funzionerà ma senza pianificazione autonoma.else
        print_success "Modello Phi-3vato"
    fi
    
    print_success "Prerequisiti verificati"
}

# Avvia servizi base
start_base_services() [object Object]    print_status "Avvio servizi base..."
    
    docker-compose up -d rabbitmq neo4j
    
    # Attendi che i servizi siano pronti
    print_status "Attendo che i servizi siano pronti..."
    sleep10   
    # Verifica RabbitMQ
    if docker-compose ps rabbitmq | grep -q Upthen
        print_successRabbitMQ avviatoelse
        print_error Errore nellavvio di RabbitMQ"
        exit1
    fi
    
    # Verifica Neo4j
    if docker-compose ps neo4grep -q Upthen
        print_success "Neo4j avviatoelse
        print_error Errore nell'avvio di Neo4j"
        exit 1
    fi
}

# Avvia worker
start_workers() [object Object]    print_status Avvio worker..."
    
    docker-compose up -d nmap_worker nuclei_worker
    
    sleep 5
    
    # Verifica worker
    if docker-compose ps nmap_worker | grep -q Upthen
        print_successNmap worker avviatoelse
        print_warning Errore nell'avvio del nmap worker"
    fi
    
    if docker-compose ps nuclei_worker | grep -q Upthen
        print_successNuclei worker avviatoelse
        print_warning Errore nell'avvio del nuclei worker"
    fi
}

# Avvia UI
start_ui() [object Object]    print_status "Avvio UI..."
    
    docker-compose up -d ui
    
    sleep 5
    
    if docker-compose ps ui | grep -q Upthen
        print_success "UI avviata"
        print_statusDashboard disponibile su: http://localhost:5000else
        print_warning Errore nell'avvio dell'UI"
    fi
}

# Avvia orchestrator V2 (sistema autonomo)
start_autonomous_system() [object Object]    print_status "Avvio sistema autonomo..."
    
    docker-compose --profile autonomous up -d orchestrator_v2
    
    sleep 10
    
    if docker-compose ps orchestrator_v2 | grep -q Upthen
        print_success "Orchestrator V2ato"
        print_statusSistema autonomo attivo su: http://localhost:5151else
        print_warning Errore nell'avvio dellorchestrator V2  fi
}

# Verifica stato sistema
check_system_status() [object Object]    print_status "Verifica stato sistema..."
    
    echo ""
    echo 📊 STATO SISTEMA:"
    echo================="
    
    # Servizi base
    echo "🐰 RabbitMQ: $(docker-compose ps rabbitmq | grep -o Up\|Down|| echo 'Unknown)"    echo "🗄️  Neo4j: $(docker-compose ps neo4 grep -o Up\|Down|| echoUnknown')"
    
    # Worker
    echo "🔍 Nmap Worker: $(docker-compose ps nmap_worker | grep -o Up\|Down|| echo 'Unknown')"
    echo 🎯 Nuclei Worker: $(docker-compose ps nuclei_worker | grep -o Up\|Down|| echoUnknown)"
    
    # UI
    echo 🖥️  UI: $(docker-compose ps ui | grep -o Up\|Down|| echoUnknown')   
    # Orchestrator V2
    echo 🤖 Orchestrator V2: $(docker-compose ps orchestrator_v2 | grep -o Up\|Down|| echoUnknown')"
    
    echo " echo "🌐 Endpoint disponibili:"
    echo   -Dashboard UI: http://localhost:50  echo "  - RabbitMQ Management: http://localhost:15672
    echo   - Neo4j Browser: http://localhost:7474   echo  - Orchestrator V2 Health: http://localhost:5151health"
    echo  - Orchestrator V2 Status: http://localhost:5151tus
}
# Funzione di pulizia
cleanup() [object Object]    print_status "Arresto sistema..."
    docker-compose down
    print_success Sistema arrestato"
}

# Gestione segnali
trap cleanup SIGINT SIGTERM

# Menu principale
show_menu()[object Object]  echo    echo 🎛️  MENU A.A.P.T.:"
    echo=================="
    echo 1) Avvio completo (base + autonomo)"
    echo "2 Avvio base (senza autonomia)"
    echo "3) Solo sistema autonomo echo 4) Verifica stato
    echo 5) Logs sistema"
    echo 6) Test sistema"
    echo "7) Arresto completo"
    echo 8)Esci"
    echo   read -p Scegli un'opzione (1-8choice
}

# Mostra logs
show_logs()[object Object]  echo "
    echo📋 LOGS SISTEMA:"
    echo ================"
    echo 1 Orchestrator V2"
    echo2) Nmap Worker"
    echo3Nuclei Worker"
    echo 4) UI    echo 5) Tutti i logs"
    echo   read -p "Scegli log da visualizzare (1 log_choice
    
    case $log_choice in
    1cker logs orchestrator_v2
       2) docker logs nmap_worker -f ;;
    3docker logs nuclei_worker -f ;;
      4) docker logs aapt_ui -f ;;
       5ocker-compose logs -f ;;
        *) print_error "Opzione non valida;;
    esac
}

# Esegui test
run_tests() [object Object]    print_status "Esecuzione test sistema...  
    if [ -f "./orchestrator/test_autonomous_system.py" ]; then
        cd orchestrator
        python test_autonomous_system.py
        cd ..
    else
        print_warningFile di test non trovato
    fi
}

# Main
main() {
    check_prerequisites
    
    while true; do
        show_menu
        
        case $choice in
            1             print_status "Avvio sistema completo..."
                start_base_services
                start_workers
                start_ui
                start_autonomous_system
                check_system_status
                ;;
            2             print_status "Avvio sistema base..."
                start_base_services
                start_workers
                start_ui
                check_system_status
                ;;
            3             print_status "Avvio solo sistema autonomo..."
                start_autonomous_system
                check_system_status
                ;;
            4             check_system_status
                ;;
            5              show_logs
                ;;
            6               run_tests
                ;;
            7           cleanup
                exit0               ;;
            8             print_status "Uscita..."
                exit0               ;;
            *)
                print_error "Opzione non valida"
                ;;
        esac
        
        echo 
        read -p "Premi ENTER per continuare..."
    done
}

# Esegui main se script chiamato direttamente
if ${BASH_SOURCE[0== "${0}" ]]; then
    main
fi 