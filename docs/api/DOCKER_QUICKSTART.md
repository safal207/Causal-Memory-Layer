# 🐳 CML Docker Quickstart

This guide explains how to run the CML Audit API using Docker and Docker Compose. This is the fastest way to get a local instance of CML running for development, testing, or demonstrations.

> **Note:** This setup is intended for local development and demos. It is not configured for production-grade security or scaling.

## 🏁 Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## 🚀 Getting Started

### 1. Build and Start the API
Run the following command in the project root:
```bash
docker compose up --build
```
The API will be available at `http://localhost:8080`.

### 2. Verification
Open a terminal and run:
```bash
# Start the services
docker compose up --build -d

# Check API health
curl http://localhost:8080/health

# Clean up
docker compose down
```
Expected Health Output:
{"status":"ok","version":"0.4.0"}

## 🛠 Common Commands

| Action | Command |
| :--- | :--- |
| **Start (Background)** | `docker compose up -d` |
| **Stop** | `docker compose stop` |
| **Down (Remove Containers)** | `docker compose down` |
| **View Logs** | `docker compose logs -f` |

## 📡 Using the API
Once running, you can use the examples provided in [cURL Examples](./HOSTED_AUDIT_API_CURL_EXAMPLES.md) to interact with the server.
