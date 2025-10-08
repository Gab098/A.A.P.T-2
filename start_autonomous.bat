@echo off
setlocal enabledelayedexpansion

REM A.A.P.T. - Avvio Sistema Autonomo per Windows
REM Script per avviare rapidamente il sistema di pianificazione autonoma

echo A.A.P.T. - Avvio Sistema Autonomo
echo ==================================

REM Verifica prerequisiti
call :check_prerequisites

:menu
cls

echo.
echo ========== MENU A.A.P.T. ===========
echo 1) Avvio completo (base + autonomo)
echo 2) Avvio base (senza autonomia)
echo 3) Solo sistema autonomo
echo 4) Verifica stato
echo 5) Logs sistema
echo 6) Test sistema
echo 7) Arresto completo
echo 8) Esci
echo =====================================
set /p choice=Scegli un'opzione (1-8): 

if "%choice%"=="1" goto start_complete
if "%choice%"=="2" goto start_base
if "%choice%"=="3" goto start_autonomous
if "%choice%"=="4" goto check_status
if "%choice%"=="5" goto show_logs
if "%choice%"=="6" goto run_tests
if "%choice%"=="7" goto cleanup
if "%choice%"=="8" goto exit_script

echo [ERROR] Opzione non valida
pause
goto menu

:start_complete
echo [INFO] Avvio sistema completo...
call :start_base_services
call :start_workers
call :start_ui
call :start_autonomous_system
call :check_status
pause
goto menu

:start_base
echo [INFO] Avvio sistema base...
call :start_base_services
call :start_workers
call :start_ui
call :check_status
pause
goto menu

:start_autonomous
echo [INFO] Avvio solo sistema autonomo...
call :start_autonomous_system
call :check_status
pause
goto menu

:start_base_services
echo [INFO] Avvio servizi base...
docker-compose up -d rabbitmq neo4j
REM Attendi che i servizi siano pronti
ping 127.0.0.1 -n 10 >nul
echo [SUCCESS] Servizi base avviati
exit /b

:start_workers
echo [INFO] Avvio worker...
docker-compose up -d nmap_worker nuclei_worker
ping 127.0.0.1 -n 6 >nul
echo [SUCCESS] Worker avviati
exit /b

:start_ui
echo [INFO] Avvio UI...
docker-compose up -d ui
ping 127.0.0.1 -n 6 >nul
echo [SUCCESS] UI avviata
echo [INFO] Dashboard disponibile su: http://localhost:5000
exit /b

:start_autonomous_system
echo [INFO] Avvio sistema autonomo...
docker-compose --profile autonomous up -d orchestrator_v2
ping 127.0.0.1 -n 10 >nul
echo [SUCCESS] Orchestrator V2 avviato
echo [INFO] Sistema autonomo attivo su: http://localhost:5151
exit /b

:check_status
echo [INFO] Verifica stato sistema...
echo.
docker-compose ps
echo.
echo Endpoint disponibili:
echo   - Dashboard UI: http://localhost:5000
echo   - RabbitMQ Management: http://localhost:15672
echo   - Neo4j Browser: http://localhost:7474
echo   - Orchestrator V2 Health: http://localhost:5151/health
echo   - Orchestrator V2 Status: http://localhost:5151/status
pause
exit /b

:show_logs
echo.
echo LOGS SISTEMA:
echo 1) Orchestrator V2
echo 2) Nmap Worker
echo 3) Nuclei Worker
echo 4) UI
echo 5) Tutti i logs
echo.
set /p log_choice=Scegli log da visualizzare (1-5): 
if "%log_choice%"=="1" (docker logs orchestrator_v2 -f) else if "%log_choice%"=="2" (docker logs nmap_worker -f) else if "%log_choice%"=="3" (docker logs nuclei_worker -f) else if "%log_choice%"=="4" (docker logs aapt_ui -f) else if "%log_choice%"=="5" (docker-compose logs -f) else (echo [ERROR] Opzione non valida)
pause
goto menu

:run_tests
echo [INFO] Esecuzione test sistema...
if exist orchestrator\test_autonomous_system.py (
    pushd orchestrator
    python test_autonomous_system.py
    popd
) else (
    echo [WARNING] File di test non trovato
)
pause
goto menu

:cleanup
echo [INFO] Arresto sistema...
docker-compose down
echo [SUCCESS] Sistema arrestato
pause
goto menu

:exit_script
echo [INFO] Uscita...
exit /b 0

:check_prerequisites
echo [INFO] Verifica prerequisiti...
REM Verifica Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker non trovato. Installa Docker Desktop prima di continuare.
    pause
    exit /b 1
)
REM Verifica Docker Compose
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose non trovato. Installa Docker Compose prima di continuare.
    pause
    exit /b 1
)
REM Verifica modello Phi-3
if not exist models\Microsoft\phi-3-mini-4k-instruct-q4\phi-3-mini-4k-instruct-q4.gguf (
    echo [WARNING] Modello Phi-3 non trovato
    echo [INFO] Assicurati di aver scaricato il modello prima di continuare.
    echo [INFO] Il sistema funzionerà ma senza pianificazione autonoma.
) else (
    echo [SUCCESS] Modello Phi-3 trovato
)
exit /b 