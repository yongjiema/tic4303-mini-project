# tic4303-mini-project

The mini project for TIC4303.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- [Node.js](https://nodejs.org) installed on your machine or set up a [Dev Container](https://code.visualstudio.com/docs/devcontainers/containers) in Visual Studio Code.

## Run the Web Application

To set up and run the web application locally, follow these steps:

1. **Navigate to the project directory**: `cd tic4303-mini-project`
2. **Install dependencies**: `npm install`
3. **Start the application**: `npm start`

The application should now be running at http://localhost:3000.

## Default Users

- Username: admin, Password: Adm!n$tr0ngP@ssw0rd123, Role: admin
- Username: user1, Password: Us3r#Secure2024!@#, Role: user
- Username: user2, Password: P@ssw0rd!_Ex@mple#456, Role: user

## Building and Running with Docker

1. Build the Docker image: `sh scripts/build-docker-image.sh` or `scripts\build-docker-image.bat`
2. Run the Docker container: `sh scripts/run-docker-image.sh` or `scripts\run-docker-image.bat`

The application should now be running at http://localhost:3000.

## Deploy to Kubernetes

For a Minikube-based Kubernetes deployment:

1. Build the Docker image: `sh scripts/build-docker-image.sh` or `scripts\build-docker-image.bat`
2. Deploy using Minikube: `sh scripts/deploy-using-minikube.sh` or `scripts\deploy-using-minikube.bat`

The application should now be running at http://localhost:3000.


