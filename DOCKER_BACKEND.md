# Make Some Noise - Backend

A high-performance Go-based API server that generates synthetic security events and metrics for SIEM/SOAR content development and testing. This container powers the Make Some Noise event generation engine.

## Overview

The backend API provides RESTful endpoints for generating realistic security events across 27+ event types. It supports multiple delivery methods including Syslog (UDP/TCP), Splunk HTTP Event Collector (HEC), and file output. Perfect for:

- SIEM content development and testing
- SOAR automation testing
- Security monitoring validation
- Splunk Enterprise Security (ES) testing
- Splunk IT Service Intelligence (ITSI) metric generation
- Cribl Stream integration testing

## Quick Start

### Using Docker Compose

```bash
docker-compose up -d
# API runs at http://localhost:8080
```

### Standalone Docker

```bash
docker run -d \
  --name makesomenoise-backend \
  -p 8080:8080 \
  thelawsofchaos/makesomenoise-backend:latest
```

## Environment Variables

- `PORT`: API port (default: `8080`)
- `LOG_LEVEL`: Logging verbosity (default: `info`)

## API Endpoints

The backend provides comprehensive REST API endpoints for event generation:

- **Configuration Management**: Save and retrieve event generation configurations
- **Event Generation**: Generate individual events or batch events
- **Event Delivery**: Send events to configured destinations (Syslog, Splunk HEC, files)
- **Continuous Generation**: Run background event generation with configurable rates
- **Status Monitoring**: Check API health and current generation status

For detailed API documentation, visit the [GitHub repository](https://github.com/TheLawsOfChaos/make-some-noise/).

## Features

- **27+ Event Types**: Comprehensive coverage including:
  - Windows Security Events (4624, 4625, 4688, 4720, etc.)
  - Windows Sysmon (Process Create, Network Connection, Registry Events, DNS)
  - Cisco ASA logs
  - Palo Alto Networks firewall events
  - Fortinet FortiGate logs
  - AWS CloudTrail events
  - Azure AD logs
  - Microsoft 365 events
  - CrowdStrike Falcon EDR
  - Elastic Defend events
  - DNS queries
  - Web server access logs
  - VPN access logs
  - File activity logs
  - SSH access logs

- **Multiple Delivery Methods**:
  - Syslog UDP
  - Syslog TCP
  - Splunk HTTP Event Collector (HEC)
  - File output

- **Per-Source Routing**: Route different event types to different destinations
- **Real-time Event Preview**: Generate and preview events before delivery
- **Continuous Noise Generation**: Background event generation with configurable rates
- **ITSI Metrics Support**: Generate Splunk-compatible metrics
- **Template System**: Use built-in templates or create custom ones
- **High Performance**: Efficient event generation suitable for high-volume testing

## Supported Event Types

### Windows
- Security Events (Authentication, Account Management, Process Creation, Privilege Use)
- Sysmon (Process Activity, Network Connection, File Activity, Registry Changes, DNS)

### Network
- Cisco ASA (Connections, Access Control)
- Palo Alto Networks (Traffic, Threat)
- Fortinet FortiGate (Traffic, Security)

### Cloud
- AWS CloudTrail
- Azure AD
- Microsoft 365

### Endpoint Detection & Response (EDR)
- CrowdStrike Falcon
- Elastic Defend

### Other
- DNS queries
- Web server access logs (Apache, Nginx)
- VPN access logs
- File activity
- SSH access logs

## Architecture

- **Language**: Go 1.20+
- **HTTP Server**: Gin framework
- **Event Generation**: Modular generator system
- **Delivery**: Pluggable delivery adapters
- **Performance**: Optimized for high-throughput event generation

## Requirements

- Container runtime (Docker, Podman, etc.)
- Network connectivity to destination systems (Syslog servers, Splunk, etc.)
- 256MB+ RAM (recommended 512MB+ for high-volume generation)

## Deployment Options

### Docker Compose (Recommended)

Included in the main repository for full-stack deployment with frontend and backend together.

### Kubernetes

Can be deployed as a Kubernetes service with configurable replicas for load balancing.

### Docker Swarm

Compatible with Docker Swarm for orchestrated deployments.

## Performance Considerations

- **Event Generation Rate**: Configurable from single events to thousands per second
- **Memory Usage**: Scales with event buffer size and generation rate
- **CPU**: Single-threaded event generation; scale horizontally with multiple containers
- **Network**: UDP for Syslog provides lower overhead; TCP for reliability

## Troubleshooting

### API Not Responding
1. Check container is running: `docker ps | grep makesomenoise-backend`
2. Verify port 8080 is not in use: `netstat -tulpn | grep :8080`
3. Check logs: `docker logs makesomenoise-backend`

### Events Not Being Delivered
1. Verify destination connectivity from container
2. Check destination address and port configuration
3. Confirm authentication/token if required (e.g., Splunk HEC)
4. Review API response for error messages

### Performance Issues
1. Check system resource availability (CPU, memory)
2. Reduce event generation rate
3. Scale horizontally with multiple containers
4. Optimize destination network bandwidth

## Documentation

For more information about the Make Some Noise project:
- [GitHub Repository](https://github.com/TheLawsOfChaos/make-some-noise/)
- [Main Project README](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/README.md)
- [Frontend Container](https://hub.docker.com/r/thelawsofchaos/makesomenoise-frontend)

## License

This project is licensed under the same license as the main Make Some Noise repository. See [LICENSE](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/LICENSE) for details.

## Support

For issues, feature requests, or contributions, visit the [GitHub repository](https://github.com/TheLawsOfChaos/make-some-noise/).
