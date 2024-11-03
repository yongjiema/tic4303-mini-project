@echo off

doskey kubectl=minikube kubectl --

kubectl delete -f k8s/
