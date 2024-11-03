@echo off

doskey kubectl=minikube kubectl --

REM Load the image into Kubernetes
minikube image load tic4303-mini-project:latest

REM Deploy the application to Kubernetes
kubectl apply -f k8s/namespace.yaml
kubectl get secret tic4303-mini-project-secret -n tic4303-mini-project-namespace >nul 2>&1
if %errorlevel% equ 0 (
    kubectl delete secret tic4303-mini-project-secret -n tic4303-mini-project-namespace
)
for /f %%i in ('powershell -command "[Convert]::ToBase64String((1..32 | ForEach-Object {Get-Random -Minimum 0 -Maximum 255}))"') do set "SESSION_SECRET=%%i"
kubectl create secret generic tic4303-mini-project-secret ^
    --from-literal=SESSION_SECRET=%SESSION_SECRET% ^
    -n tic4303-mini-project-namespace
kubectl apply -f k8s/

minikube tunnel
