#!/usr/bin/env sh

alias kubectl="minikube kubectl --"

# Load the image into Kubernetes
minikube image load tic4303-mini-project:latest

# Deploy the application to Kubernetes
kubectl apply -f k8s/namespace.yaml
if kubectl get secret tic4303-mini-project-secret -n tic4303-mini-project-namespace >/dev/null 2>&1; then
    kubectl delete secret tic4303-mini-project-secret -n tic4303-mini-project-namespace
fi
kubectl create secret generic tic4303-mini-project-secret \
  --from-literal=NODE_ENV=development \
  --from-literal=SESSION_SECRET=$(openssl rand -base64 32) \
  -n tic4303-mini-project-namespace
kubectl apply -f k8s/

minikube tunnel
