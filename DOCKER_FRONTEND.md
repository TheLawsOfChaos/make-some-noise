# Make Some Noise - Frontend

A modern React-based web interface for the Make Some Noise SIEM event generator. This container provides a user-friendly dashboard for configuring, previewing, and managing synthetic security event generation.

## Overview

The frontend is a responsive web application built with React and Vite, designed to work seamlessly with the Make Some Noise backend API. It allows users to:

- Configure event generation parameters
- Select from 27+ supported event types
- Preview generated events in real-time
- Manage multiple event sources and destinations
- Monitor continuous noise generation
- Support for multiple delivery methods (Syslog, Splunk HEC, File output)

## Quick Start

### Using Docker Compose

```bash
docker-compose up -d
# Access at http://localhost:3000
```

### Standalone Docker

```bash
docker run -d \
  --name makesomenoise-frontend \
  -p 3000:3000 \
  --network host \
  thelawsofchaos/makesomenoise-frontend:latest
```

## Configuration

The frontend connects to the backend API. By default, it expects the backend to be available at `http://localhost:8080`. When using Docker Compose, this is automatically configured through the compose file.

### Environment Variables

- `VITE_API_URL`: Backend API URL (optional, defaults to `http://localhost:8080`)

## Features

- **Real-time Event Preview**: See generated events before sending them
- **Template Management**: Use built-in templates or create custom ones
- **Per-Source Routing**: Route different event types to different destinations
- **Multiple Delivery Methods**: Syslog (UDP/TCP), Splunk HEC, or file output
- **Event Type Support**: Windows Security Events, Sysmon, Cisco ASA, AWS CloudTrail, Azure AD, DNS, Web Servers, EDR, and more
- **ITSI Metrics**: Generate Splunk-compatible metrics for service monitoring
- **Responsive Design**: Works on desktop and mobile devices

## Supported Event Types

- **Windows**: Security Events, Sysmon
- **Network**: Cisco ASA, Palo Alto Networks, Fortinet FortiGate
- **Cloud**: AWS CloudTrail, Azure AD, Microsoft 365
- **EDR**: CrowdStrike Falcon, Elastic Defend
- **Other**: DNS queries, Web server logs, VPN access, File activity, SSH access, and more

## Requirements

- Backend container running on `localhost:8080` (or configured URL)
- Modern web browser with JavaScript enabled
- Network connectivity to backend API

## Deployment Options

### Docker Compose (Recommended)

Included in the main repository for full-stack deployment with backend and frontend together.

### Kubernetes

Can be deployed as part of a Kubernetes manifest alongside the backend service.

### Docker Swarm

Compatible with Docker Swarm for orchestrated deployments.

## Architecture

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **HTTP Client**: Axios
- **Routing**: React Router v6
- **Icons**: Heroicons

## Troubleshooting

### Connection Issues
If the frontend cannot reach the backend API:
1. Verify the backend container is running
2. Check the API endpoint configuration
3. Ensure network connectivity between containers
4. Review browser console for CORS errors

### Performance
- Clear browser cache if experiencing slow loading
- Check network tab in developer tools for slow requests
- Verify backend performance

## Documentation

For more information about the Make Some Noise project:
- [GitHub Repository](https://github.com/TheLawsOfChaos/make-some-noise/)
- [Main Project README](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/README.md)
- [Backend Container](https://hub.docker.com/r/thelawsofchaos/makesomenoise-backend)

## License

This project is licensed under the same license as the main Make Some Noise repository. See [LICENSE](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/LICENSE) for details.

## Support

For issues, feature requests, or contributions, visit the [GitHub repository](https://github.com/TheLawsOfChaos/make-some-noise/).
