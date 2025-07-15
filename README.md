# traefik-acme-watcher

A lightweight tool to extract certificates from Traefik's `acme.json` file and watch for changes. Designed for Linux (arm64/amd64) containers where you need to use Traefik-managed certificates with other services.

**THIS PROJECT IS STILL WORK IN PROGRESS!**

## Features

- Extracts certificates from Traefik's `acme.json` file
- Monitors for changes using efficient inotify (Linux-specific)
- Exports certificates in PEM format
- Sends signals to processes when certificates change
- Can act as PID 1 in Docker containers with proper signal handling
- Supports user switching for security
- Minimal dependencies (only `golang.org/x/sys` for inotify)

## Installation

### Building from source

```bash
# Clone the repository
git clone https://github.com/yourusername/traefik-acme-watcher
cd traefik-acme-watcher

# Build using Docker (works on any platform, including macOS)
./docker-build.sh

# Or use the Makefile for Docker-based builds
make docker-build-all

# Build directly on Linux
make build-all
```

## Usage

### Basic certificate extraction

Extract certificates and watch for changes:

```bash
./traefik-acme-watcher \
  --acme-path=/path/to/acme.json \
  --domain=example.com \
  --cert=/output/cert.pem \
  --key=/output/key.pem
```

### With process signaling

Send a signal to a process when certificates change:

```bash
./traefik-acme-watcher \
  --acme-path=/path/to/acme.json \
  --domain=example.com \
  --cert=/output/cert.pem \
  --key=/output/key.pem \
  --pid=1234 \
  --signal=HUP
```

### As PID 1 in Docker

Run and manage a process, restarting it when certificates change:

```bash
./traefik-acme-watcher \
  --acme-path=/acme.json \
  --domain=example.com \
  --cert=/certs/cert.pem \
  --key=/certs/key.pem \
  --exec="nginx -g 'daemon off;'" \
  --user=nginx \
  --signal=HUP
```

### Wait Mode

Wait for a domain to appear in acme.json before starting:

```bash
# With --exec: starts the process only after domain appears
./traefik-acme-watcher \
  --acme-path=/acme.json \
  --domain=new.example.com \
  --cert=/certs/cert.pem \
  --key=/certs/key.pem \
  --exec="nginx -g 'daemon off;'" \
  --wait

# With --pid: sends signal when domain appears
./traefik-acme-watcher \
  --acme-path=/acme.json \
  --domain=new.example.com \
  --cert=/certs/cert.pem \
  --key=/certs/key.pem \
  --pid=1234 \
  --signal=HUP \
  --wait
```

## Command-line Options

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `--acme-path` | Path to Traefik's acme.json file | Yes | - |
| `--domain` | Domain name to extract certificate for | Yes | - |
| `--cert` | Output path for certificate PEM file | Yes | - |
| `--key` | Output path for private key PEM file | Yes | - |
| `--pid` | Process ID to signal on certificate changes | No | - |
| `--exec` | Command to execute and manage | No | - |
| `--user` | User to switch to when using --exec | No | - |
| `--signal` | Signal to send (HUP, TERM, USR1, USR2, etc.) | No | HUP |
| `--wait` | Wait for domain to appear instead of failing at startup | No | false |

Note: `--pid` and `--exec` are mutually exclusive.

## Docker Usage

### Example Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o traefik-acme-watcher

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/traefik-acme-watcher /usr/local/bin/
ENTRYPOINT ["traefik-acme-watcher"]
```

### Docker Compose example

```yaml
services:
  traefik:
    image: traefik:v3.4
    ports:
      - "443:443"
    volumes:
      - acme:/acme
    command:
      - --providers.docker=true
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.le.acme.tlschallenge=true
      - --certificatesresolvers.le.acme.email=admin@example.com
      - --certificatesresolvers.le.acme.storage=/acme/acme.json

  nginx:
    build: .
    volumes:
      - acme:/acme:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    command:
      - /usr/local/bin/traefik-acme-watcher
      - --acme-path=/acme/acme.json
      - --domain=example.com
      - --cert=/etc/nginx/certs/cert.pem
      - --key=/etc/nginx/certs/key.pem
      - --exec=nginx -g 'daemon off;'
      - --wait
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.nginx.rule=Host(`example.com`)"
      - "traefik.http.routers.nginx.entrypoints=websecure"
      - "traefik.http.routers.nginx.tls.certresolver=le"

volumes:
  acme:
```

Where `Dockerfile` would be:
```dockerfile
# Build traefik-acme-watcher
FROM golang:1.24-alpine AS builder
RUN go install -ldflags='-w -s' github.com/felixbuenemann/traefik-acme-watcher@latest

# Final image
FROM nginx:alpine
COPY --from=builder /go/bin/traefik-acme-watcher /usr/local/bin/
RUN mkdir -p /etc/nginx/certs
```

## How it works

1. **Startup**: Reads the `acme.json` file and extracts the certificate for the specified domain
   - If domain is not found and `--wait` is specified, continues to monitoring phase
   - Otherwise fails with an error
2. **Monitoring**: Uses Linux inotify to watch for changes to the `acme.json` file
3. **Change detection**: When the file changes, re-reads it and compares the certificate
4. **Update**: If the certificate changed (or appeared for the first time in wait mode), writes new PEM files and signals the configured process
5. **Process management**: 
   - With `--pid`: Sends the configured signal to the process
   - With `--exec`: Manages the child process, forwarding signals and restarting as needed
   - In wait mode with `--exec`: Starts the child process only after the domain appears

## Process Management Behavior

When using `--exec`, traefik-acme-watcher acts as a process supervisor:

- **Signal forwarding**: All signals (except SIGCHLD) are forwarded to the child process
- **Restart logic**:
  - If the process exits cleanly after receiving a signal from the watcher: **restarts**
  - If the process exits cleanly on its own: **does not restart**
  - If the process exits with an error: **does not restart**
- **Graceful shutdown**: On SIGTERM/SIGINT, gives the child process 5 seconds to exit before forcing termination

## Security Considerations

- The `acme.json` file contains private keys and should have restrictive permissions (600)
- When using `--user`, the process switches to the specified user after startup
- Certificate files are written atomically to prevent partial reads
- Private keys are written with 0600 permissions, certificates with 0644

## Building for Multiple Architectures

The included Makefile supports building for both arm64 and amd64:

```bash
# Build for arm64
make build-arm64

# Build for amd64
make build-amd64

# Build for both
make build-all
```

## Requirements

- Linux (arm64 or amd64)
- Go 1.21 or later (for building)
- Access to Traefik's `acme.json` file

## License

MIT License - see LICENSE file for details