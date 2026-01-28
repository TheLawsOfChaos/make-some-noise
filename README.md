# Make Some Noise

<p align="center">
  <img src="branding/makesomenoise-dark.png" width="96" alt="Make Some Noise logo" />
</p>

<p align="center">
  <a href="https://github.com/TheLawsOfChaos/make-some-noise/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/TheLawsOfChaos/make-some-noise/docker-publish.yml?branch=main" alt="Build" />
  </a>
  <a href="https://github.com/TheLawsOfChaos/make-some-noise/releases">
    <img src="https://img.shields.io/github/v/release/TheLawsOfChaos/make-some-noise" alt="Release" />
  </a>
  <a href="https://github.com/TheLawsOfChaos/make-some-noise/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/TheLawsOfChaos/make-some-noise" alt="License" />
  </a>
</p>

A web application for generating synthetic security events and metrics to feed Splunk Enterprise Security, Splunk ITSI, and Cribl for SIEM/SOAR content development and testing.

## Features

- **27 Event Types**: Comprehensive coverage of security logs, cloud events, EDR, identity, network, and infrastructure metrics
- **Multiple Delivery Methods**: Send events via Syslog (UDP/TCP), Splunk HEC, or write to files
- **Per-Source Routing**: Route different event types to different destinations
- **Real-time Preview**: Preview generated events before sending
- **Continuous Noise Generation**: Run background event generation with configurable rates
- **ITSI Metrics Support**: Generate Splunk-compatible metrics for service monitoring
- **Template System**: Use built-in templates or create custom ones
- **Docker Deployment**: Easy deployment with Docker Compose

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone or navigate to the project directory
cd make-some-noise

# Build and start the containers
docker-compose up -d

# Access the web interface
open http://localhost:3000
```

### Manual Development Setup

**Backend (Go):**
```bash
cd backend
go mod download
go run main.go
# API runs on http://localhost:8080
```

**Frontend (React):**
```bash
cd frontend
npm install
npm run dev
# UI runs on http://localhost:3000
```

## Supported Event Types

### Windows Security Events
- Event ID 4624 - Successful Logon
- Event ID 4625 - Failed Logon
- Event ID 4688 - Process Creation
- Event ID 4672 - Special Privileges Assigned
- Event ID 4720 - User Account Created
- Event ID 4726 - User Account Deleted
- Event ID 4728 - Member Added to Global Group
- Event ID 4732 - Member Added to Local Group

### Windows Sysmon
- Event ID 1 - Process Create
- Event ID 3 - Network Connection
- Event ID 7 - Image Loaded
- Event ID 8 - CreateRemoteThread
- Event ID 10 - Process Access
- Event ID 11 - File Create
- Event ID 12/13 - Registry Events
- Event ID 22 - DNS Query

### Cisco ASA
- 302013/302014 - Connection Built/Teardown
- 302015/302016 - Outbound Connection
- 106001/106006/106015/106023 - ACL Deny Events
- 113039 - VPN Session
- 111008 - User Command

### Cisco Firepower
- Intrusion Events
- Connection Events
- File Events
- Malware Events

### Suricata IDS
- Alert Events (EVE JSON)
- Flow Events
- DNS Events
- HTTP Events
- TLS Events
- File Info Events

### Linux Auditbeat (ECS Format)
- Process Events
- File Integrity Events
- User Login Events
- Socket Events
- Package Events

### Microsoft Active Directory
- Event ID 4720 - User Account Created
- Event ID 4722 - User Account Enabled
- Event ID 4723 - Password Change Attempt
- Event ID 4724 - Password Reset
- Event ID 4725 - User Account Disabled
- Event ID 4726 - User Account Deleted
- Event ID 4728/4729 - Member Added/Removed from Global Group
- Event ID 4732/4733 - Member Added/Removed from Local Group
- Event ID 4740 - User Account Locked
- Event ID 4767 - User Account Unlocked

### AWS CloudTrail
- ConsoleLogin - AWS Console sign-in events
- AssumeRole - IAM role assumption via STS
- CreateUser/DeleteUser - IAM user management
- PutBucketPolicy - S3 bucket policy changes
- AuthorizeSecurityGroupIngress - Security group modifications
- RunInstances/StopInstances - EC2 lifecycle events
- CreateAccessKey - IAM access key creation
- GetSecretValue - Secrets Manager access

### AWS GuardDuty
- UnauthorizedAccess:EC2/SSHBruteForce
- Recon:EC2/PortProbeUnprotectedPort
- CryptoCurrency:EC2/BitcoinTool
- UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
- Trojan:EC2/BlackholeTraffic
- Backdoor:EC2/C2Activity

### AWS VPC Flow Logs
- ACCEPT - Allowed traffic
- REJECT - Denied traffic

### Azure Activity Logs
- VM Create/Delete operations
- Role assignments
- NSG rule changes
- Storage key regeneration
- Key Vault secret access

### Okta System Logs
- user.session.start - Session initiation
- user.authentication.sso - SSO authentication
- user.mfa.factor.activate - MFA enrollment
- user.account.lock - Account lockout
- policy.lifecycle.update - Policy changes
- application.lifecycle.create - App provisioning

### Azure AD Sign-in Logs
- Interactive sign-in success/failure
- MFA challenge events
- Conditional access blocks
- Risky sign-in detection
- Service principal authentication

### CrowdStrike Falcon
- DetectionSummaryEvent - Threat detections
- ProcessRollup2 - Process telemetry
- NetworkConnectIP4 - Network connections
- DnsRequest - DNS queries
- FileWritten - File activity

### Microsoft Defender for Endpoint
- AlertEvidence - Security alerts
- DeviceEvents - Device activity
- DeviceProcessEvents - Process execution
- DeviceNetworkEvents - Network activity
- DeviceFileEvents - File operations

### Palo Alto Firewall
- TRAFFIC - Allow/deny traffic logs
- THREAT - Virus and spyware detection
- URL - URL filtering logs
- SYSTEM - System events
- CONFIG - Configuration changes

### VMware vCenter
- VmCreatedEvent - VM creation
- VmPoweredOnEvent/VmPoweredOffEvent - Power state changes
- VmMigratedEvent - vMotion events
- AlarmStatusChangedEvent - Alarm triggers
- UserLoginSessionEvent - Admin logins

### Zeek (Bro) Network Logs
- conn.log - Connection records
- dns.log - DNS queries
- http.log - HTTP requests
- ssl.log - TLS/SSL connections
- files.log - File analysis
- notice.log - Alerts and notices

### DNS Query Logs
- QUERY - DNS requests
- RESPONSE - DNS responses
- NXDOMAIN - Non-existent domain
- BLOCKED - Filtered queries

### Apache/Nginx Access Logs
- 200/201/204 - Success responses
- 301/302/304 - Redirects
- 400/401/403/404 - Client errors
- 500/502/503/504 - Server errors

### AWS ALB Access Logs
- HTTP/HTTPS requests
- Target errors
- ELB errors
- Slow responses
- WebSocket connections

### Office 365 Audit Logs
- FileAccessed/FileModified/FileDeleted - SharePoint/OneDrive
- UserLoggedIn - Authentication events
- MailItemsAccessed - Exchange activity
- TeamCreated - Teams administration

### Kubernetes Audit Logs
- Pod create/delete operations
- Secret access events
- Container exec commands
- ConfigMap updates
- RBAC changes

## ITSI Metrics (Splunk HEC Format)

### System Infrastructure Metrics
- **CPU**: Per-core utilization, user/system/idle/iowait breakdown
- **Memory**: Used/free/cached/buffers, swap usage
- **Disk Space**: Per-mount usage, inodes, percent full
- **Disk I/O**: Read/write IOPS, throughput, latency, queue length
- **Network**: Bytes/packets in/out, TCP states, errors, drops
- **Load**: 1/5/15 minute averages, process counts, context switches
- **Temperature**: CPU/GPU/chassis temps, fan RPMs

### Application Performance Metrics
- **Response Time**: Latency percentiles (p50/p75/p90/p95/p99) by endpoint
- **Request Rate**: RPS by endpoint and HTTP method
- **Error Rate**: Error counts by status code and type
- **Queue**: Message queue depth, consumer lag, processing rates
- **Threads**: Thread pool utilization and states
- **Connections**: Connection pool usage by target type
- **JVM**: Heap, GC, memory pools, class loading (for Java apps)

### Database Metrics
- **Query Performance**: Latency, throughput, slow query counts
- **Connections**: Active/idle/waiting by state and user
- **Buffer Pool**: Cache hit ratio, page reads/writes
- **Transactions**: TPS, commits, rollbacks, WAL metrics
- **Replication**: Lag seconds/bytes, replica states
- **Locks**: Lock waits, deadlocks, blocking sessions
- **Tablespace**: Table/index sizes, row counts, dead tuples

### Web/API Metrics
- **HTTP Status**: Response code distribution (2xx/3xx/4xx/5xx)
- **Latency**: Request latency percentiles by endpoint
- **Throughput**: Requests/sec, active connections
- **Bandwidth**: Bytes in/out, content type breakdown
- **SSL/TLS**: Handshake time, version/cipher distribution, cert expiry
- **Upstream**: Backend health, response times per server
- **Cache**: Hit ratio, cache status distribution by zone

## Delivery Methods

### Syslog (UDP/TCP)
- RFC 3164 (BSD) format
- RFC 5424 format
- Configurable facility and severity

### Splunk HEC
- HTTP Event Collector support
- Batched event sending
- SSL/TLS support
- Token authentication
- Metrics format support for ITSI

### File Output
- Write to local files
- Automatic file rotation
- Configurable max size
- Per-source file routing

## API Endpoints

```
GET  /api/health                    # Health check
GET  /api/event-types               # List all event types
GET  /api/event-types/:type/schema  # Get schema for event type
POST /api/generate                  # Generate events
POST /api/generate/preview          # Preview single event
GET  /api/destinations              # List destinations
POST /api/destinations              # Create destination
PUT  /api/destinations/:id          # Update destination
DELETE /api/destinations/:id        # Delete destination
POST /api/destinations/:id/test     # Test destination connection
GET  /api/templates                 # List templates
POST /api/templates                 # Create template
GET  /api/event-sources             # List event sources for noise generation
POST /api/noise/start               # Start continuous event generation
POST /api/noise/stop                # Stop event generation
GET  /api/noise/status              # Get generation status
PUT  /api/noise/config              # Update generation config
GET  /api/noise/stats               # Get generation statistics
```

## Configuration

### Environment Variables

**Backend:**
- `PORT` - API port (default: 8080)

### Destination Configuration

**Syslog:**
```json
{
  "type": "syslog_udp",
  "config": {
    "host": "192.168.1.100",
    "port": 514,
    "facility": 1,
    "severity": 6,
    "format": "rfc3164"
  }
}
```

**Splunk HEC:**
```json
{
  "type": "hec",
  "config": {
    "url": "https://splunk:8088/services/collector/event",
    "token": "your-hec-token",
    "index": "main",
    "sourcetype": "siem:events",
    "verify_ssl": false
  }
}
```

**File:**
```json
{
  "type": "file",
  "config": {
    "file_path": "/tmp/output/events.log",
    "max_size_mb": 100,
    "rotate_keep": 5
  }
}
```

## Docker Volumes

The application uses a volume mount for file output:

```yaml
volumes:
  - ./output:/tmp/output
```

Files written to `/tmp/output/` inside the container will appear in the `./output/` directory on the host.

## Use Cases

- **SIEM Content Development**: Generate realistic events to test detection rules and correlation searches
- **Splunk ES Testing**: Validate Enterprise Security content packs and notable events
- **ITSI Service Monitoring**: Create metrics to test KPIs, glass tables, and service health scores
- **Training and Demos**: Generate sample data for security training environments
- **Load Testing**: Stress test log ingestion pipelines with high-volume event generation
- **Parser Development**: Test Splunk props/transforms or Cribl pipelines with known event formats

## License

MIT License
