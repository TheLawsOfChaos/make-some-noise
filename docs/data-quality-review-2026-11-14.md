# make-some-noise data quality review (2026-11-14)

Review of the events the make-some-noise backend 1.1.0 generates, as seen through a real
Splunk 10.6.1 stack with the vendor add-ons installed. Six subject matter reviews (firewall,
Windows, cloud, identity and endpoint, network sensors, Linux and infrastructure) plus the
flow test are consolidated here. The source files are listed in the appendix.

## 1. Summary

What was tested:

- All 27 sources of the 1.1.0 backend, 5 events per second for 60 seconds each, over HEC into
  a two-box Splunk 10.6.1 stack (search head and indexer, phoenix tenant mn1).
- 8075 events sent, 0 send errors, 0 drops, 0 skipped sources. Every source landed in the
  mapped index with the mapped sourcetype.
- Add-ons on the search head: Splunk Add-on for AWS 8.1.2, Microsoft Cloud Services 6.1.3,
  Microsoft Azure (TA-MS-AAD) 4.2.0, Microsoft Office 365 6.0.2, Microsoft Windows 10.0.1,
  Sysmon 5.0.0, Sysmon for Linux, Microsoft Security 3.0.0, Cisco ASA 6.0.0, Cisco Security
  Cloud 3.6.6, Palo Alto Networks 4.0.0, Okta Identity Cloud 5.1.0, CrowdStrike Falcon Event
  Streams 3.7.2, CCX Suricata 1.0.1, TA for Zeek 1.0.11, Apache Web Server 2.1.0, Unix and
  Linux (Splunk_TA_nix).
- Each source was then judged by a reviewer for realism (does it look like what the product
  emits) and parsing (does the add-on produce the fields and CIM tags a detection needs).

Verdicts: 0 GOOD, 14 PARTIAL, 13 BAD.

| verdict | sources |
|---|---|
| PARTIAL (14) | cisco_asa, windows_sysmon, aws_cloudtrail, aws_guardduty, aws_vpcflow, azure_activity, azure_ad_signin, o365_audit, kubernetes_audit, okta, zeek, suricata, webserver, vmware_vcenter |
| BAD (13) | cisco_firepower, paloalto, windows_security, microsoft_ad, microsoft_defender, aws_alb, crowdstrike, dns_query, linux_auditbeat, metrics_system, metrics_application, metrics_database, metrics_webapi |

No source reached GOOD. The flow test alone would have rated 17 sourcetypes as extracting
correctly; the reviewers' stricter bar (field values an analyst would believe, event mix,
coherent identities) pulled every one of those down to PARTIAL. The delivery path itself is
sound: the defects are in the generators, with a handful on the Splunk side.

The fixes that matter most, across the board:

1. **Windows XML quoting** (windows_security, microsoft_ad, windows_sysmon). Go's
   `xml.Marshal` writes `<Data Name="x">`; the Windows and Sysmon add-ons match only
   `Name='x'`. No EventData field (TargetUserName, LogonType, IpAddress, MemberName, user,
   src) is extracted on 598 of 598 Security events. One shared helper that swaps the quotes
   and self-closes empty elements fixes all three sources.
2. **PAN-OS CSV layout** (paloalto). The column order is invented from column 3 on and
   addresses are packed as `ip///port`; every field lands in the wrong column and `URL` is
   not a PAN-OS log type. The three templates must be rewritten in the documented order.
3. **ALB line** (aws_alb). The elb and client fields are joined by `/` and the line stops at
   field 21 of the 25 the add-on's single regex needs; 0 of 299 events extract anything.
4. **FTD syslog shape** (cisco_firepower). The generator emits flat custom JSON that no FTD
   ever wrote; it has to become `%FTD-n-43000n: Key: value, ...` syslog so `rec_type` and
   the CIM fields are set.
5. **Metrics array wrapper** (metrics_*). Each event is a JSON array of HEC metric objects
   sent as one `event` string; a metrics index rejects it. The sender (`delivery/hec.go`)
   must post the elements as metric points. Unwrapped, the content works (57 metric names,
   mstats searches run).
6. **CrowdStrike split**. Five of six templates put FDR sensor event names inside the Event
   Streams envelope, which neither add-on recognises. Keep the stream source for
   DetectionSummaryEvent and its siblings and add a `crowdstrike_fdr` source with the flat
   `event_simpleName` shape.
7. **Fixed identity pools instead of a new tenant, account, host or user per event**. Every
   cloud and endpoint generator draws a fresh AWS account id, Azure tenant, O365
   OrganizationId, CrowdStrike cid and aid, host id or suffixed user name per event. 300
   events give 300 accounts, so no baseline, rare-user or correlation detection can be
   exercised. Package-level pools (3 AWS accounts, 1 tenant, 10 to 20 named users with stable
   ids, a small host table) fix this once for every generator.

Also worth fixing early, because they are one-token changes: VPC flow `log_status` (`-` to
`OK`), Sysmon EID 10 GUID field names, GuardDuty type name `Backdoor:EC2/C&CActivity.B!DNS`,
CloudTrail ConsoleLogin `eventType`, O365 `SourceFileExtension`, Okta severity.

## 2. Method

### Stack

One phoenix tenant (mn1): Splunk Enterprise 10.6.1 on two EC2 boxes, a search head with the
add-ons and an indexer with HEC. Noise indexes: noise_windows, noise_endpoint, noise_identity,
noise_cloud, noise_network, noise_linux, noise_app (events) and noise_metrics (metrics). The
backend ran as the published image `thelawsofchaos/makesomenoise-backend:1.1.0` in a
rootless container on the operator host; only the backend was used, driven through its REST
API by a small sender script (send.py). Searches ran through the search head's REST endpoint.

### Add-ons and versions

Add-ons already in the phoenix store were used as found; four were staged from Splunkbase for
this test (newest release marked compatible with Splunk 10.6): Palo Alto Networks 4.0.0
(7523), Okta Identity Cloud 5.1.0 (6553), CrowdStrike Falcon Event Streams 3.7.2 (5082), CCX
Add-on for Suricata 1.0.1 (6994). Decisions behind them:

- Palo Alto 7523 over the archived Palo Alto Networks Add-on 2757.
- Okta 6553 (`OktaIM2:log`); the generator's default `okta:im` belongs to the archived add-on
  2806.
- CrowdStrike Event Streams over FDR because the generator wraps every event as
  `{"metadata": ..., "event": ...}`, the streaming shape.
- No Splunkbase add-on parses Kubernetes audit JSON, Auditbeat ECS JSON, vSphere API event
  JSON or the generator's DNS query JSON; those four sources (and the four metrics sources)
  were sent with `msn:*` sourcetypes and parse as plain JSON.

### How sourcetype, index and source were set

The backend sets index and source per HEC destination and sourcetype per template, with a
destination-level sourcetype override. The sender created one destination per source from
`sourcetypes.json` (the reconciled map, not the generator defaults: for 14 of 27 sources the
generator's default sourcetype has no stanza in any staged add-on). Two refinements:

- **Per-template routing** for paloalto (`pan:traffic` for traffic_*, `pan:threat` for
  threat_* and url_*) and zeek (`bro:conn:json`, `bro:dns:json`, `bro:http:json`,
  `bro:ssl:json`, `bro:files:json`, `bro:notice:json`): one HEC destination per sourcetype,
  with `template_ids` on the run's `enabled_sources` entries. The backend supports this
  without a code change.
- **Windows source names**: the three XML sources were sent as sourcetype `XmlWinEventLog`
  with HEC source `XmlWinEventLog:Security` (windows_security, microsoft_ad) and
  `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (windows_sysmon), because the Sysmon
  add-on's props key on that source.

Event time is the HEC receive time (the backend does not pass the event's own timestamp), so
TIME_PREFIX and LINE_BREAKER settings in the add-ons did not matter; index-time transforms and
search-time extractions did. Host is `siem-event-generator` for every source except the three
Windows ones, which set the Computer name.

### What the verdicts mean

- **GOOD**: realistic and parsed. The event looks like what the product emits and the add-on
  produces its fields and CIM tags.
- **PARTIAL**: lands and mostly parses, but a realistic analyst would notice something wrong
  (impossible field combinations, random severities, wrong event mix, invented values).
- **BAD**: not what the product emits, or the add-on cannot parse it.

Each reviewer read the generator code (`backend/generators/<source>.go`), 20 raw sample
events per source, the installed add-on's props and transforms, the vendor documentation
for the real format, and ran searches against the stack. Fix recommendations name the file
and function.

### Limits

- Splunk_SA_CIM is not on the search head, so no datamodel searches were possible. Tag
  checks (`tag=network tag=communicate` and so on) stood in for datamodel membership; a tag
  only means the eventtype matched, not that the fields are populated.
- Add-ons are installed on the search head only; nothing index-time from the add-ons ran on
  the indexer. Search-time extraction is what every verdict is based on.
- One Splunk version (10.6.1) and one add-on version each.
- The 20-event samples are a random template mix, so a source with ten or eleven templates
  may not show every template; the Splunk searches cover all 299 or so events per source.
- The reviewers did not change the repo, the stack or the add-ons; "proof" results in the
  Windows section were produced by re-parsing stored events at search time.

## 3. Results table

| source | sourcetype sent | add-on | verdict | reason |
|---|---|---|---|---|
| cisco_asa | cisco:asa | Cisco ASA 6.0.0 | PARTIAL | 6 of 8 ids are real Cisco text and parse; 106001 and 106006 are invented text and extract nothing; 302013 emits UDP; event mix wrong |
| cisco_firepower | cisco:ftd:syslog | Cisco Security Cloud 3.6.6 | BAD | flat custom JSON; FTD never emits it; no rec_type, src, dest or CIM |
| paloalto | pan:traffic, pan:threat | Palo Alto Networks 4.0.0 | BAD | CSV layout invented from column 3; every field in the wrong column; URL is not a PAN log type |
| windows_security | XmlWinEventLog (source XmlWinEventLog:Security) | Microsoft Windows 10.0.1 | BAD | System block parses, EventData never does: user, src, LogonType 0 of 598 (double-quoted Name=) |
| microsoft_ad | XmlWinEventLog (source XmlWinEventLog:Security) | Microsoft Windows 10.0.1 | BAD | same cause; plus wrong group SIDs, 4740 Subject, domain mixing |
| windows_sysmon | XmlWinEventLog (source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) | Sysmon 5.0.0 with Windows 10.0.1 | PARTIAL | fields extract (by accident of a stanza collision) and tags are right; EID 10 GUID names, EID 22 QueryType and textual QueryStatus, hashes, versions, RuleName |
| microsoft_defender | m365:defender:incident:advanced_hunting | Microsoft Security 3.0.0 | BAD | action=unknown and user empty on 299 of 299 (no $table); ActionType values that do not exist; Alerts-API fields in AlertEvidence |
| crowdstrike | CrowdStrike:Event:Streams:JSON | CrowdStrike Event Streams 3.7.2 | BAD | 250 of 299 events are FDR sensor names in a stream envelope; the detection template lacks action, numeric severity, process ids |
| okta | OktaIM2:log | Okta Identity Cloud 5.1.0 | PARTIAL | real envelope, all tags fire; user empty on a third (no User target), random severity, ipChain and geo inconsistent, 14 percent lockouts |
| aws_cloudtrail | aws:cloudtrail | AWS 8.1.2 | PARTIAL | parses and tags; ConsoleLogin eventType wrong, thin userIdentity, wrong id shapes, 300 accounts in 300 events |
| aws_guardduty | aws:cloudwatch:guardduty | AWS 8.1.2 | PARTIAL | parses and tags; severity random per finding, C2 type name wrong, port and portName mismatch |
| aws_vpcflow | aws:cloudwatchlogs:vpcflow | AWS 8.1.2 | PARTIAL | every field extracts; log_status "-" never happens, protocol and port independent, REJECT flows carry MBs |
| aws_alb | aws:elb:accesslogs | AWS 8.1.2 | BAD | 0 of 299 extract: elb and client joined by "/", line stops at field 21 of 25 |
| azure_activity | azure:monitor:activity | Microsoft Cloud Services 6.1.3 | PARTIAL | operationName extracts; user, vendor_account, change_type empty or wrong (short claim keys, no tenantId, mixed case) |
| azure_ad_signin | azure:aad:signin | Microsoft Azure 4.2.0 | PARTIAL | authentication fields all present; riskDetail holds riskEventTypes, impossible device and geo combos, SP sign-in shape wrong |
| o365_audit | o365:management:activity | Microsoft Office 365 6.0.2 | PARTIAL | parses and tags; RecordType a string, SourceFileExtension bug, UserLoggedIn Actor types wrong, MailItemsAccessed thin |
| kubernetes_audit | msn:kubernetes:audit | none | PARTIAL | valid audit.k8s.io/v1 JSON; URIs lack object names, RBAC URIs wrong, level and bodies inconsistent, no EKS identity |
| zeek | bro:*:json | TA for Zeek 1.0.11 | PARTIAL | Zeek-shaped JSON, raw keys extract; the TA adds nothing (export=none, no src/dest aliases for bro:*:json); conn, ssl, files, notice values contradict each other |
| suricata | suricata | CCX Suricata 1.0.1 | PARTIAL | EVE shape right and CIM mapped; wrong sids, random severity, port and app_proto mismatches, mixed DNS schema, TLS formats |
| dns_query | msn:dns:query | none | BAD | no resolver emits this schema; nothing maps to Network_Resolution; retarget to MSAD:NT6:DNS or isc:bind:query |
| webserver | apache:access:combined | Apache Web Server 2.1.0 | PARTIAL | combined line correct and fully extracted; byte counts and method, path, status, UA pairings implausible; tag=web missing is a TA gap |
| linux_auditbeat | msn:linux:auditbeat | none | BAD | ECS envelope right, vocabulary and module blocks invented; a detection written for real Auditbeat matches nothing |
| vmware_vcenter | msn:vmware:vcenter | none | PARTIAL | matches the vSphere Event object; messages contradict the structured fields; no logout, failed login, reconfigure or snapshot |
| metrics_system | msn:metrics:system | none | BAD | one JSON array per HEC event, rejected by a metrics index; content GOOD when unwrapped |
| metrics_application | msn:metrics:application | none | BAD | same wrapper defect; prod hostnames with development environment, host duplicated as a dimension |
| metrics_database | msn:metrics:database | none | BAD | same wrapper defect; Postgres WAL metrics for mysql, mariadb, oracle, mssql |
| metrics_webapi | msn:metrics:webapi | none | BAD | same wrapper defect; fractional request counts, prod hostnames in staging |

## 4. Per-source findings

Generator files are under `backend/generators/` in the make-some-noise repo. Splunk evidence
is quoted from searches on the mn1 search head over the real run (earliest -6h); search
syntax is in the appendix.

### 4.1 Firewalls (sme-firewall.md)

#### cisco_asa: PARTIAL

What parses: the syslog header (`<166>` facility local4, severity 6, `Mmm dd hh:mm:ss host
%ASA-6-302013:`) matches the add-on's TIME_PREFIX and anchored regexes. 106023, 111008,
113039, 302013, 302014, 302015 extract src, dest, ports, rule, session_id, duration, bytes,
user and command as expected; tags network, session, vpn fire. Facility and severity digits
per id match Cisco. Connection ids, durations, byte counts, AnyConnect group names and
`[0x0, 0x0]` codes are plausible.

Evidence: `| stats count(src) count(dest) count(src_port) ... by message_id` gives 0 for
106001 (46 events) and 106006 (47 events); every other id is fully populated.

Defects (cisco_asa.go):

1. **106001 text is invented**. Cisco: `%ASA-2-106001: Inbound TCP connection denied from
   IP/port to IP/port flags tcp_flags on interface name`; only a deny exists and the source
   carries a port (Cisco ASA Syslog Messages 101001 to 199021,
   https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-101001-to-199021.html).
   `generate106001` writes `... connection permitted from x.x.x.x/any to ...`; the regex
   needs `\d{1,5}` after the source IP, so nothing extracts. Fix: `denied`, a real source
   port, `fields["action"] = "Deny"`.
2. **106006 is UDP only and carries a source port**. Cisco: `%ASA-2-106006: Deny inbound UDP
   from addr/port to addr/port on interface name`. `generate106006` writes `Deny inbound TCP
   from x.x.x.x to y.y.y.y/88`, so the 106006_106007 regex fails. Fix: UDP, `src/port`, dst
   port from a UDP set (53, 123, 161, 500, 1900, 5060, 4500).
3. **302013 is TCP only**; UDP builds are 302015 (Syslog Messages 302003 to 342008,
   https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html).
   `generate302013` picks TCP or UDP and wrote UDP 19 of 31 times. Also `Built inbound ...
   for outside:... to outside:...` appears; pick the "to" interface from {inside, dmz}.
4. **302014 teardown reason** `Idle Timeout` is not in Cisco's list (Conn-timeout, FIN
   Timeout, SYN Timeout, TCP FINs, TCP Reset-I, TCP Reset-O, Flow closed by inspection, Deny
   Terminate, Xlate Clear, ...). A `SYN Timeout` teardown is a half-open flow: duration
   0:00:30 and bytes 0, not 0:12:28 and 480654.
5. **106023 with icmp carries ports**. For icmp the ASA writes `src outside:a.b.c.d dst
   inside:e.f.g.h (type 8, code 0)` with no ports. The regex tolerates either, but an analyst
   sees icmp "ports". `access-group "INSIDE_IN"` on `src outside` traffic is inconsistent; use
   OUTSIDE_IN or GLOBAL_DENY.
6. **111008 commands**: six of the eight entries in `generate111008` are show commands, which
   never produce 111008. Replace with config-mode commands (`configure terminal`, `write
   memory`, `access-list ... permit`, `username ... privilege 15`, `no logging host`, `clear
   xlate`, `reload`). Real ASAs pair this with 111010 and 605005.
7. **Event mix**: equal weights give 111008 10 percent and 113039 14 percent. Production:
   302013/302014/302015/302016 85 to 95 percent, 106023 most of the rest, 106001/106006 a
   fraction of a percent, 113039 and 111008 a handful per day. Suggested weights 302013:30,
   302014:30, 302015:15, 302016:10, 106023:10, 106001:2, 106006:2, 113039:1, 111008:1.

Minor: usernames `sys_37uB`, `app_QLju` look synthetic; a `jdoe`-style pool reads better. The
outbound 302015 ordering (lower-security side first) is correct; the TA labelling the
external side `src` is a known TA limitation, not a generator bug.

#### cisco_firepower: BAD

What lands: only the raw JSON keys (event_type, dst_ip, action, policy, ...) through the
add-on's generic JSON kv transform. src, dest, src_ip, dest_ip, rec_type, signature,
transport, vendor_action are 0 on all 598 events across connection, file, intrusion and
malware. `src_ip` is 0 because the TA's `FIELDALIAS-syslog_src_ip = SrcIP AS src_ip`
overrides the JSON key. The network/communicate tags come from a catch-all eventtype on the
sourcetype, so a malware event is tagged as network traffic with no src or dest.

What FTD emits: security events 430001 (intrusion), 430002 (connection start), 430003
(connection end), 430004 (file), 430005 (file malware), as comma-separated `Key: value` pairs
after `%FTD-n-43000n:` (Cisco Secure Firewall Threat Defense Syslog Messages, Security Event
Syslog Messages,
https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html;
third-party samples at https://docs.sekoia.com/integration/categories/network_security/cisco_asa/).
Since 6.3 empty fields are omitted. The add-on's `EXTRACT-extract_rec_type =
(?:%FTD|%FMC)-\d+\-(?P<rec_type>\d{6}):` is the only way `rec_type` (and so the five
eventtypes and all CIM aliases) gets set; `syslog_auto_kv` reads the pairs in any order. Any
severity digit is accepted.

Example of the expected shape (430001):

```
<161>Nov 14 09:13:58 ftd-hq-01 %FTD-1-430001: EventPriority: High, DeviceUUID: <uuid>, InstanceID: 1, FirstPacketSecond: 2026-11-14T09:13:58Z, ConnectionID: 12345, SrcIP: 203.0.113.50, DstIP: 10.1.1.5, SrcPort: 44123, DstPort: 445, Protocol: tcp, IngressInterface: outside, EgressInterface: inside, IngressZone: outside-zone, EgressZone: inside-zone, ACPolicy: Corp-ACP, AccessControlRuleName: Allow-SMB, Priority: 1, GID: 1, SID: 41978, Revision: 5, Message: "OS-WINDOWS Microsoft Windows SMB remote code execution attempt", Classification: Attempted Administrator Privilege Gain, User: No Authentication Required, Client: NetBIOS-ssn (SMB) client, ApplicationProtocol: NetBIOS-ssn (SMB), IntrusionPolicy: Balanced Security and Connectivity, InlineResult: Dropped, InlineResultReason: Intrusion rule set to drop, NAPPolicy: Balanced Security and Connectivity, NumIOC: 0
```

Defect and fix (cisco_firepower.go, all four `generate*` functions): they `json.Marshal` a
flat map with invented snake_case keys. Smallest change: keep the field maps, replace the
marshal with an `fmt.Sprintf` of `<PRI>Mmm dd hh:mm:ss host %FTD-n-43000n: Key: value, ...`
(reuse the header builder from cisco_asa.go) with Cisco's CamelCase keys, sourcetype
`cisco:ftd:syslog`:

- intrusion: 430001 with EventPriority, DeviceUUID, InstanceID, FirstPacketSecond,
  ConnectionID, SrcIP, DstIP, SrcPort, DstPort, Protocol (lowercase), interfaces and zones,
  ACPolicy, AccessControlRuleName, Priority 1 to 3, GID, SID, Revision, Message (quoted Snort
  text), Classification (the long Snort text), IntrusionPolicy, InlineResult (Dropped, Would
  have dropped, Partially dropped, or omitted), NAPPolicy, NumIOC.
- connection: 430002 at start (InitiatorPackets 1, ResponderBytes 0) and 430003 at end
  (ConnectionDuration, byte counts, URL/URLCategory/URLReputation for web, DNSQuery for dns,
  SSL* for TLS, AccessControlRuleReason when blocked). AccessControlRuleAction values: Allow,
  Trust, Block, Block with reset, Interactive Block, Interactive Block with reset, Fastpath.
- file: 430004; malware: 430005 (plus SHA_Disposition: Malware, ThreatName, ThreatScore,
  EventPriority; the `retrospective` flag becomes a Retrospective FileAction).

Realism to fix at the same time: interface names `ethernet1/8` are PAN-OS (FTD logs nameif
and zones); intrusion events with ICMP and ports; `action Allowed` beside `blocked: true`;
7-digit rule ids (Snort SIDs are 1 to about 70000, custom from 1000000); priority 4 (Snort is
1 to 3); `application: SSH` with a url, `web_application: Amazon` and `client: Safari` on one
event; `file_type: DOCX` on a `.dll`; `sensor_id` 8 random letters instead of a UUID;
nanosecond timestamps where FTD writes `FirstPacketSecond: 2026-11-14T09:13:58Z`.

Event mix: connection events are more than 99 percent of a real FTD feed. Suggested
430002:45, 430003:45, 430001:6, 430004:3, 430005:1. FTD also emits the ASA-style LINA
messages (%FTD-6-302013, %FTD-4-106023, %FTD-6-113039, 722051); Splunk_TA_cisco-asa has a
`[cisco:ftd]` stanza for those, and a realistic feed is both.

#### paloalto: BAD (pan:traffic and pan:threat)

What lands: pan:traffic shows `src_ip` holding a 16-letter string, `dest_ip` holding
`ip///port`, `src_port dns`, `src_zone vpn-access`, `dest_zone 820355`, `rule vsys1`, `app
ethernet1/1`, `action unknown`, `session_id allow`. pan:threat is shifted the same way:
threat_name 0, url 0, action 0 on all 211. Tags network/communicate, ids/attack and web are
present only because the eventtypes key on sourcetype, so every CIM row would carry garbage.

Real PAN-OS field order (PAN-OS 11.0 syslog field descriptions, Traffic Log Fields,
https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields,
and Threat Log Fields,
https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields):
`FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type, FUTURE_USE, Generated
Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP, Rule Name,
Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone,
Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count,
Source Port, Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol,
Action, ...` (traffic continues with Bytes, Bytes Sent, Bytes Received, Packets, Start Time,
Elapsed Time, Category, ..., Session End Reason, ..., Device Name; threat continues with
URL/Filename, Threat ID, Category, Severity, Direction, ...). Subtype values for threat:
data, file, flood, packet, scan, spyware, url, ml-virus, virus, vulnerability, wildfire,
wildfire-virus. There is no URL log type: URL filtering is THREAT subtype `url` with Threat
ID `(9999)`. The add-on's `extract_traffic` and `extract_threat` are `DELIMS = ","` with
exactly that field list; `extract_threat_core_fields` additionally requires category at
column 34, severity at 35, direction at 36; the `pan_traffic`/`pan_threat` routing regexes
need TYPE at column 4.

Defects (paloalto.go `generateTraffic`, `generateThreat`, `generateURL`):

- An extra `0` at column 3 pushes TYPE to column 5; after column 8 nothing lines up (no
  generated time, no NAT columns, rule before user and app, session id before ports, no
  flags, bytes before action). Not one shift: the Sprintf templates have to be rewritten.
- `%s/%s/%s/%d` with two empty strings packs the address as `ip///port` into one column.
- The action (`allow`/`deny`) is written in the subtype column; traffic subtypes are `start`,
  `end`, `drop`, `deny`. A denied session is subtype `deny`, action `deny`, 1 packet, about 60
  bytes, elapsed 0, session end reason `policy-deny`; the generator gives denies 299 packets
  and 376 KB.
- `generateURL` writes type `URL` and sourcetype `pan:url` (no stanza anywhere).
- `ssh` on port 3389 and `smtp` on 1433; zone pairs `vpn` to `vpn` and `dmz` to `dmz` with a
  rule named `vpn-access`; the `fields` map calls `randomApplication()` and `randomRule()`
  again, so API consumers see a different app and rule than the raw line; the threat `fields`
  has no ports; sequence numbers should be monotonic per device.

Fix: rewrite the three templates in the PAN-OS order through at least Device Name (column 53
traffic, 60 threat) and pad the rest with empty columns (real 10.2/11 lines have 117 to 130
columns, mostly empty). Split src and dst into ip and port columns. Serial as 12 digits
(`007200001056`), device name in Device Name (the TA's `dvc`). Lowercase subtype. Traffic
allow as subtype `end`; traffic deny as above; url block as THREAT subtype `url`, action
`block-url`, URL in field 32, Threat ID `(9999)`, category (phishing, malware, ...),
severity informational, direction client-to-server; virus as action `reset-both` or `alert`,
URL/Filename the file name, Threat ID `Virus/Win32.WGeneric.abcdef(123456)` (the TA splits
name and id), severity medium or high, direction server-to-client for a download, app and
dest port that agree; spyware as `Suspicious DNS Query (generic:evil.example.com)(4201234)`
or `Cobalt Strike Beacon Command and Control Traffic(86445)`, action `sinkhole`, `alert` or
`reset-both`, internal source to external destination (the generator has C2 backwards).

Event mix: traffic 95 percent or more, url a few percent, threat well under 1 percent.
Suggested traffic_allow:60, traffic_deny:15, url_allow:15, url_block:5, threat_spyware:3,
threat_virus:1.

### 4.2 Windows and endpoint (sme-windows.md, sme-identity-endpoint.md)

Reference for all three XML sources: the Splunk universal forwarder with `renderXml=true`
writes single-quoted attributes and self-closing empty elements
(`<Data Name='SubjectUserSid'>S-1-5-18</Data>`, `<Correlation/>`, `<Security/>`; Splunk
Research sample https://research.splunk.com/sources/4d2078ab-36f5-447e-b7e4-474890b8040b/).
The add-ons are written for that rendering: Splunk_TA_windows `[eventdata_xml_data] REGEX =
<(?:\w+)\sName='([^>]*)'\/?>([^<]*)(?:<\/\1>)?`, Splunk_TA_microsoft_sysmon `[sysmon-data]
REGEX = <Data Name='(.*?)'>(.*?)</Data>`, `[sysmon-created]`, `[sysmon-sid]` and `TIME_PREFIX
= <Data Name='UtcTime'>`. Microsoft's event pages show the Event Viewer rendering (double
quotes, `<Correlation />`), which is what the generator copied and which the forwarder never
sends.

#### windows_security: BAD

What parses: EventCode (4624 47, 4625 63, 4672 57, 4688 67, 4720 95), Computer, Channel,
Keywords; eventtypes windows_logon_success, windows_logon_failure, windows_process_new,
windows_account_created and tags authentication, process, account, change fire. Nothing
from EventData: TargetUserName, LogonType, IpAddress, MemberName, user, Logon_Type are 0 on
every EventCode of the 598 Security events. `EventData_Xml` is captured with `<Data
Name="SubjectUserName">` inside, so the kv regex simply does not match.

**Defect S1 (blocking): Data Name uses double quotes and empty elements are not
self-closing.** windows_security.go, microsoft_ad.go and windows_sysmon.go each call
`xml.Marshal(event)`; Go always writes double-quoted attributes and never self-closes. Fix,
one shared helper for all three builders (generators/generator.go): marshal, then replace
every `"` with `'` (Go escapes literal quotes inside text as `&#34;` and `&#39;`, so only
the structural quotes are touched) and collapse `<x ...></x>` to `<x .../>` with one regexp.
Replace `rawEvent, err := xml.Marshal(event)` with `winEventXML(event)` at the five call
sites in windows_security.go, the eleven in microsoft_ad.go and the seven in
windows_sysmon.go. Add a one-line test that the output contains `Name='TargetUserName'` and
`<Correlation/>` and no `"`.

Proof on the installed add-on (search-time only, nothing sent): the stored events re-parsed
with `rex mode=sed "s/\"/'/g" | extract reload=true` extract TargetUserName, LogonType,
IpAddress and Logon_Type on 19 of 19 4624 and 11 of 11 4625, MemberName and MemberSid on
every 4728 and 4732, TargetUserName, SubjectUserName and TargetSid on 40 of 40 4720. After
the fix the `[source::XmlWinEventLog:Security]` stanza yields Logon_Type, src (4624 from
IpAddress, 4625 from WorkstationName), user (4720 to 4767 from TargetUserName, 4728/4732 from
the member), action and status from the EventCode plus Error_Code lookup, process_name and
parent_process for 4688.

**Defect S2: Version is 2 for every template.** Real: 4624 and 4688 version 2, 4625, 4672 and
4720 version 0 (learn.microsoft.com event pages). `buildEvent` sets 2 for all; pass the
version per template.

**Defect S3: 4625 Status, SubStatus and FailureReason do not agree.** The triplet is coupled:
bad password 0xC000006D / 0xC000006A / %%2313; unknown user 0xC000006D / 0xC0000064 /
%%2313; locked out 0xC0000234 / 0x0 / %%2307; disabled 0xC0000072 / 0x0 / %%2310; expired
0xC000006E / 0xC0000071 / %%2309; logon type not granted 0xC000015B / 0x0 / %%2308. `generate4625`
draws Status and FailureReason from separate lists and SubStatus is always `0x0`. The TA's
action lookup reads Status, and analysts separate spraying from enumeration on SubStatus.
Fix: one slice of {Status, SubStatus, FailureReason} and pick one entry.

**Defect S4: logon type, logon process and network fields do not match.** Interactive, unlock
and cached logons (2, 7, 11) are `User32`/`Negotiate` with IpAddress `127.0.0.1` or `-`;
network (3) is `NtLmSsp`/`NTLM` (KeyLength 128) or `Kerberos`/`Kerberos` (KeyLength 0); RDP
(10) is `User32`/`Negotiate` with the client IP; the Subject of a network or service logon is
`S-1-5-18` / `HOST$` / 0x3e7; LogonGuid has braces. `generate4624` always writes NtLmSsp with
an IP and random port; `generate4625` uses `RandomInt(2, 11)` (6 is not a logon type) with a
public IP for every type; Kerberos, the majority in a domain, never appears. Fix: choose the
logon type first and set the rest from a per-type table; add a Kerberos variant for type 3;
brace the GUID; drop 6, 8, 9 from 4625.

**Defect S5: 4688 command line, parent and token.** CommandLine must start with
NewProcessName; TokenElevationType %%1938 normal, %%1937 run as administrator, %%1936 SYSTEM;
Target equals the creator unless the logon differs. Generator: `CommandLine: g.RandomPath()`
is a different executable (taskhostw.exe with notepad.exe), TokenElevationType always
%%1936, ParentProcessName always cmd.exe, Subject and Target unrelated. Fix: derive
CommandLine from NewProcessName plus args, pair TokenElevationType with MandatoryLabel
(S-1-16-8192, -12288, -16384), vary the parent (explorer.exe, svchost.exe, services.exe,
powershell.exe, cmd.exe), copy Subject to Target.

**Defect S6 (minor):** SystemTime has 9 fractional digits (Windows writes 7); EventData order
follows Go map order (real events have a fixed order per EventID; use an ordered slice, which
also makes golden tests deterministic); Computer, SubjectDomainName and TargetDomainName are
drawn independently (derive the domain once per event); 4720 PasswordLastSet should be
`<never>`, DisplayName `<value not set>`, UserAccountControl a newline-and-tab list.

**Defect S7:** five templates cover logon and process creation only (see section 7).

#### microsoft_ad: BAD

Same blocking cause (S1 applies through `buildADEvent`). The System block is right for these
events (Version 0, Level 0, Task 13824 and 13826, Keywords 0x8020000000000000, the Security
Auditing provider GUID, a DC name) and the EventData sets for 4720, 4722, 4723, 4724, 4725,
4726, 4728, 4729, 4732 and 4767 match the Microsoft schema. Once the quotes are fixed the TA
sets user, dest, change_type and the account-management tags.

**Defect A1: group SIDs and group-to-event mapping.** Domain Users is S-1-5-21-<domain>-513,
Domain Admins -512, Enterprise Admins -519 (universal, logged as 4756/4757, not 4728/4729);
builtin groups are S-1-5-32-xxx and only appear in 4732/4733 (Administrators 544, Remote
Desktop Users 555, Backup Operators 551, Server Operators 549). `RandomGroupName()` feeds
4728/4729 with builtin and universal groups, `TargetSid` is a random S-1-5-21 for every group,
MemberName uses `RandomOU()` with its own random domain. Fix: a `groups` table {name, rid or
sid, scope}; 4728/4729 global scope, 4732/4733 builtin with S-1-5-32-<rid>, add 4756/4757;
build the member SID from the same domain prefix as the DC.

**Defect A2: 4740 Subject and caller computer.** Real: SubjectUserSid S-1-5-18,
SubjectUserName `DC01$`, SubjectLogonId 0x3e7, TargetDomainName is the caller computer name.
`generate4740`: no SubjectUserSid, SubjectUserName an FQDN without `$`, SubjectLogonId 0x0,
TargetDomainName the domain. Fix accordingly, TargetDomainName from `g.RandomHostname()`.

**Defect A3 (minor):** Computer `PDC.CORP.local` while the subject domain is NORTHWIND;
derive both from one domain. 4720 DisplayName is random words. Versions (0) are right.

#### windows_sysmon: PARTIAL

What parses on mn1: Image, CommandLine, Hashes, SHA256, user, process_guid, parent_process,
action on all 44 EID 1; src_ip, dest_ip, dest_port on all 50 EID 3; TargetFilename and
file_path on all 48 EID 11; QueryName, query, answer on all 46 EID 22; TargetImage and
GrantedAccess on all 48 EID 10; ImageLoaded and Hashes on all 35 EID 7; CIM tags right
(process/report on 1/7/8/10, endpoint/filesystem on 11, network/communicate on 3,
dns/network/resolution on 22). The System block is correct (Sysmon provider GUID, Level 4,
Task = EventID, Keywords 0x8000000000000000).

Why it parses although the quotes are wrong: the search head has two `sysmon-data` transforms
stanzas, Splunk_TA_microsoft_sysmon (`<Data Name='(.*?)'>`) and Splunk_TA_sysmon-for-linux
(`<Data Name="(.*?)">`, because Sysmon for Linux writes double quotes). Same-named stanzas
merge across apps and the Linux copy wins, so Windows Sysmon events run the Linux regex. That
is an accident of having both add-ons on one head, not something the generator should rely
on. `[sysmon-created]` (TimeCreated) and `[sysmon-sid]` (SecurityID) still miss. With fix S1
the events match both add-ons as written; the proof searches show single-quoted Sysmon events
still extract.

**Defect M1: EID 10 GUID field names.** Sysmon writes `SourceProcessGUID` and
`TargetProcessGUID` (ultimatewindowssecurity.com event 90010), and the add-on takes
process_guid and parent_process_guid for EventCode 10 from exactly those names. `generateEvent10`
uses `SourceProcessGuid`/`TargetProcessGuid`; process_guid is 0 of 48 on EID 10 while 37 of 37
on EID 8. Fix: rename the two keys in generateEvent10.

**Defect M2: EID 22 has a QueryType field and textual QueryStatus.** Real fields: RuleName,
UtcTime, ProcessGuid, ProcessId, QueryName, QueryStatus, QueryResults, Image, User; no
QueryType. QueryStatus is the Windows DNS status number (0, 9003 NXDOMAIN, 9501, 1460, 9701);
the add-on aliases it to reply_code_id, so "SUCCESS" lands in a numeric CIM field. Fix: delete
QueryType; QueryStatus from {0, 0, 0, 9003, 9501}; empty QueryResults on 9003.

**Defect M3: hashes, versions, Security UserID, RuleName.** Hashes are `SHA256=` only; nearly
every deployed config yields `SHA1=...,MD5=...,SHA256=...,IMPHASH=...` and the add-on has
regexes for all four. Version is 5 for every event (schema 4.90: EID 1 v5, 3 v5, 7 v3, 8 v2,
10 v3, 11 v2, 22 v5, 12/13 v2). `<Security UserID='S-1-5-18'/>` is always present on Sysmon
events; the generator leaves UserID empty. RuleName is `-` on all 308; real configs name
rules (`technique_id=T1003,technique_name=Credential Dumping`), and the TA builds `rule`
from it. CallTrace is one frame; real values have several `|`-separated frames.

**Defect M4: EID 3 plausibility.** Initiated random, SourceHostname a random other host,
protocol random against port (udp to 22, 25, 3306, 3389, 445). Real: SourceHostname is the
reporting host, outbound to a public IP is Initiated true, udp goes with 53/123/137/389/500/
1900 and tcp with 22/25/80/443/445/3389/636/3306. Fix: one (protocol, port) table.

**Defect M5 (minor): EID 1 content.** CommandLine equals Image with no arguments;
`C:\Windows\System32\powershell.exe` is not a real path; Description always "Windows
Process"; ParentImage always services.exe; IntegrityLevel random (Low for winlogon.exe);
RandomPath puts csrss.exe, svchost.exe, lsass.exe under `C:\Users\...\Documents` in about 40
percent of events, which is a masquerading signal on every other event. Fix: a table of
{image, description, original file name, typical parent, integrity, example args}.

**Defect M6:** GetEventType lists 12 and 13 but no registry template exists.

#### microsoft_defender: BAD

What parses: ActionType, DeviceName, FileName, SHA1, SHA256, Timestamp and the eventtype
ms_security_advanced_hunting. But every CIM eval in the add-on's
`[m365:defender:incident:advanced_hunting]` stanza is keyed on the `$table` column (`EVAL-action
= case('$table'=="DeviceProcessEvents" ..., 1==1, "unknown")`, `EVAL-user`, `FIELDALIAS-signature
= $table AS signature`, file_* and registry_* evals). The rows lack it, so action is "unknown"
and user is null on 299 of 299; signature and severity 0; tags empty. `process` comes out as
FolderPath plus ProcessCommandLine (`C:\Users\...\AppData\Local\C:\Users\...\dwm.exe
-encodedcommand`) and process_name (services.exe) disagrees with process_exec (taskhostw.exe).

This sourcetype is "Results from the Defender Advanced Hunting alert action"
(https://splunk.github.io/splunk-add-on-for-microsoft-365-defender/Sourcetypes); `$table` is
the column Advanced Hunting adds on `union` or `search` queries. The shape the product itself
streams is the Event Hub record `{"time": ..., "tenantId": ..., "category":
"AdvancedHunting-DeviceProcessEvents", "properties": {<row>}}` decorated with MachineGroup
(https://learn.microsoft.com/en-us/defender-endpoint/api/raw-data-export-event-hub), parsed
by the add-on's `[ms:defender:eventhub]` stanza (every eval keyed on `category` and
`properties.<Column>`).

**Defect D1 (blocking): no table identity.** Smallest fix: `"$table": "<Table>"` per row in
microsoft_defender.go (buildBaseEvent takes a table name: AlertEvidence, DeviceProcessEvents,
DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents). Right fix: emit the
Event Hub record and map the source to `ms:defender:eventhub`.

**Defect D2: templates do not match the Advanced Hunting tables.**

- alert (AlertEvidence): Status, Classification, InvestigationId and InvestigationState are
  Alerts-API fields (ms:defender:atp:alerts), not AlertEvidence; "Critical" is not an AH
  severity. Real columns: Timestamp, AlertId, Title, Categories, AttackTechniques,
  ServiceSource, DetectionSource, EntityType, EvidenceRole, EvidenceDirection, FileName,
  FolderPath, SHA1, SHA256, FileSize, ThreatFamily, RemoteIP, RemoteUrl, AccountName,
  AccountDomain, AccountSid, AccountObjectId, AccountUpn, DeviceId, DeviceName, LocalIP,
  Severity (Informational, Low, Medium, High)
  (https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table).
  Emit a paired AlertInfo row so AlertId joins work.
- malware_detection: ActionType Quarantine/Remove/Clean/Block with Severity "Severe" does not
  exist. Real AV detections are DeviceEvents rows with `ActionType: "AntivirusDetection"` and
  the threat details in an `AdditionalFields` JSON string (ThreatName, WasRemediated,
  WasExecutingWhileDetected, Count); remediation is a separate AntivirusDetectionActionType
  or AntivirusReport row
  (https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table).
- network_connection: ActionType "NetworkConnection" is not a value; real values are
  ConnectionSuccess, ConnectionFailed, ConnectionRequest, InboundConnectionAccepted,
  ListeningConnectionCreated, ConnectionFound (the eventhub stanza keys on exactly these).
  RemotePort must be an int. Add RemoteIPType, InitiatingProcessAccountDomain,
  InitiatingProcessSHA1, InitiatingProcessParentFileName.
- logon_event: the table is DeviceLogonEvents (ActionType LogonSuccess/LogonFailed/
  LogonAttempted, LogonType Interactive/Network/RemoteInteractive/Batch/Service, Protocol
  NTLM/Kerberos/Negotiate, FailureReason, IsLocalAdmin, LogonId, RemoteDeviceName, RemoteIP,
  RemoteIPType; https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table).
  Add a LogonFailed variant with FailureReason.
- process_creation: FolderPath and FileName disagree (FileName services.exe, FolderPath
  `...\powershell.exe`); FolderPath is the full image path, FileName its last segment,
  ProcessCommandLine starts with the file name, the Initiating* trio describes the parent.
  Add ProcessIntegrityLevel, ProcessTokenElevation, InitiatingProcessParentFileName,
  AccountUpn, InitiatingProcessAccountName/Domain/Sid.
- file_creation: ActionType FileCreated is right; add InitiatingProcessAccountSid,
  FileOriginUrl for browser drops; SHA1 is the populated hash in real rows.

**Defect D3: device and base fields.** DeviceId is a 40-character hex string (not a UUID),
DeviceName a lowercase FQDN, Timestamp 7 fractional digits, ReportId a long. MachineGroup,
PublicIP, OSPlatform and OSBuild are DeviceInfo columns and do not appear on
DeviceProcessEvents, DeviceLogonEvents or AlertEvidence rows; LocalIP exists only on
DeviceNetworkEvents, DeviceEvents and AlertEvidence. `buildBaseEvent` emits all of them on
every row. Fix: `g.RandomHex(40)`, lowercase FQDN, move the DeviceInfo columns into a
DeviceInfo template, keep MachineGroup only in the eventhub wrapper.

#### crowdstrike: BAD

Verdict BAD as shipped (PARTIAL for the detection template alone). Evidence:
`stats count by metadata.eventType` gives DetectionSummaryEvent 49, DnsRequest 49,
FileWritten 51, NetworkConnectIP4 66, ProcessRollup2 40, UserLogon 44. Only
DetectionSummaryEvent gets an eventtype (crowdstrike_detection_summary_event; tags alert,
attack, malware, process, report); the other five get none. On the detection events action
is 0 of 49, process_id 0, signature_id 0; dest, user, severity, file_hash, id, description 49.
TIME_PREFIX on eventCreationTime works.

The add-on's eventtypes.conf enumerates every metadata.eventType it knows:
APIActivityAuditEvent, AuthActivityAuditEvent, UserActivityAuditEvent,
AutomatedLeadSummaryEvent, CSPMIOAStreamingEvent, CSPMSearchStreamingEvent,
CloudSecurityIOMEvent, CustomerIOCEvent, DataProtectionDetectionSummaryEvent,
DetectionSummaryEvent, EppDetectionSummaryEvent, FirewallMatchEvent, IdentityProtectionEvent,
IdpDetectionSummaryEvent, IncidentSummaryEvent, MobileDetectionSummaryEvent,
ReconNotificationSummaryEvent, RemoteResponseSession*Event, ScheduledReportNotificationEvent,
XdrDetectionSummaryEvent. ProcessRollup2, NetworkConnectIP4, DnsRequest, FileWritten and
UserLogon are not stream events.

**Defect A: five FDR sensor events in a stream envelope** (templates process, network, dns,
file_write, auth_activity). FDR delivers flat JSON, every value a string, no envelope, keyed
on `event_simpleName` plus a versioned `name` (`ProcessRollup2V19`, `NetworkConnectIP4V12`,
`DnsRequestV4`); common fields `aid`, `cid`, `aip`, `timestamp` (epoch ms string),
`ContextTimeStamp` (epoch seconds with decimals), `ContextProcessId` (joins to the
ProcessRollup2 `TargetProcessId`), `event_platform`, `ConfigBuild`, `ConfigStateHash`,
`Entitlements`, `id` (samples at
https://docs.sekoia.com/integration/categories/endpoint/crowdstrike_falcon_telemetry/ and
https://docs.panther.com/data-onboarding/supported-logs/crowdstrike/falcon-data-replicator).
Per event: ProcessRollup2 `ImageFileName` is a full device path
(`\Device\HarddiskVolume1\Windows\System32\svchost.exe`) with TargetProcessId, RawProcessId,
ParentProcessId, ParentBaseFileName, CommandLine, SHA256HashData, MD5HashData, UserSid,
AuthenticationId, ProcessStartTime, IntegrityLevel, TokenType, SessionId; NetworkConnectIP4
has numeric `Protocol` ("6", "17"), string ports, ConnectionFlags, RemoteAddressString, no
ImageFileName; DnsRequest has numeric `RequestType` ("1", "28"), QueryStatus,
FirstIP4Record, IP4Records, DnsRequestCount, no ImageFileName; FileWritten does not exist
(the family is NewExecutableWritten, PeFileWritten, OoxmlFileWritten, PdfFileWritten,
ZipFileWritten, NewScriptWritten with TargetFileName as a full device path, no
TargetDirectoryName); UserLogon has UserName, UserSid, LogonDomain, LogonServer, LogonType
("2", "3", "10"), AuthenticationPackage, AuthenticationId, UserPrincipal, RemoteAddressIP4,
LogonTime, UserIsAdmin, PasswordLastSet (no invented LogonTypeName). The generator's
ComputerName, LocalIP, MAC and RFC3339 timestamp are not sensor event fields.

Fix: remove the five templates from crowdstrike.go and create crowdstrike_fdr.go (source
`crowdstrike_fdr`, sourcetype `crowdstrike:events:sensor`, Splunk Add-on for CrowdStrike FDR,
Splunkbase 5579, not yet staged) emitting the flat shape above with all values strings, a
stable `aid` per host and one `cid` per run. If the split is not wanted, the minimum is to
delete the five templates.

**Defect B: DetectionSummaryEvent fields** (generateDetection; product sample at
https://docs.sekoia.com/integration/categories/endpoint/crowdstrike_falcon/, field schema at
https://docs.panther.com/data-onboarding/supported-logs/crowdstrike/event-streams):

1. `action` empty: the TA computes it from `event.PatternDispositionValue`,
   `event.PatternDispositionFlags.*` or `event.PatternDispositionDescription`; none is
   emitted. Add PatternDispositionValue (0 "Detection, process would have been blocked if
   related prevention policy setting was enabled." or 2048 "Prevention, process was blocked
   from execution.") and the PatternDispositionFlags object (Indicator, Detect, InddetMask,
   SensorOnly, Rooting, KillProcess, KillSubProcess, QuarantineMachine, QuarantineFile,
   PolicyDisabled, KillParent, OperationBlocked, ProcessBlocked, RegistryOperationBlocked,
   CriticalProcessDisabled, BootupSafeguardEnabled, FsOperationBlocked,
   HandleOperationDowngraded, KillActionFailed, BlockingUnsupportedOrDisabled,
   SuspendProcess, SuspendParent). ESCU's crowdstrike_stream detections filter on these.
2. `Severity` is the string "High"; real is an integer 1 to 5 with SeverityName the label
   (the TA aliases Severity to severity_id).
3. FilePath is the directory with the device prefix (`\Device\HarddiskVolume2\Windows`),
   FileName the basename, CommandLine the full command, ParentImageFileName a full device
   path. Generator emits an unrelated full path in FilePath (FileName csrss.exe, FilePath
   `C:\Windows\System32\dwm.exe`), no CommandLine, no ParentCommandLine. Derive all three
   from one tuple; add ParentCommandLine, MD5String, SHA1String.
4. process_id and parent_process_id empty: add ProcessId and ParentProcessId (int64),
   ProcessStartTime (epoch seconds), ProcessEndTime 0.
5. Field names that do not exist on this event: `MAC` (real MACAddress), `aid` (real
   SensorId), `cid` (customer id is metadata.customerIDString), `timestamp`, `TacticId`,
   `TechniqueId` (ids live on EppDetectionSummaryEvent.MitreAttack). Add SensorId,
   MachineDomain, FalconHostLink, Objective.
6. `DetectId` is a uuid; real is `ldt:<aid>:<pid>`, newer events add `CompositeId`.
7. customerIDString, cid and aid are fresh random hex per event. One cid per generator
   instance; a host table of (ComputerName, aid, LocalIP, MACAddress, MachineDomain) reused
   across events, or no two events can be correlated.
8. DetectName, Tactic, Technique and DetectDescription are drawn independently ("Malicious
   PowerShell Execution" with "Credential Access" and "Remote Desktop Protocol"). One table
   of coherent rows with the product's description style.
9. `metadata.offset` is random; real is a monotonic counter per stream.
10. Mix: a real stream is mostly UserActivityAuditEvent and AuthActivityAuditEvent with
    detections a small minority; today 16 percent detections and 84 percent impossible events.

### 4.3 Cloud (sme-cloud.md)

Cross-source defects, fix once for every cloud generator:

1. **Identity space is unbounded.** Every event picks a fresh account id (CloudTrail,
   GuardDuty, VPC flow), tenant and subscription (Azure), OrganizationId (O365), userId (Entra)
   and a suffixed user name. Fix: package-level pools (3 AWS account ids, 1 Azure tenant with
   2 subscriptions, 1 O365 OrganizationId, 10 to 20 named users with stable ids). Functions:
   aws_cloudtrail.go randomAccountID/randomIAMUser, aws_guardduty.go randomAccountID,
   aws_vpcflow.go randomAccountID, azure_activity.go randomSubscriptionID/randomTenantID,
   azure_ad_signin.go randomTenantID/randomUser, o365_audit.go randomTenantID/randomUser.
2. **Identifier shapes.** generator.go has RandomHex but the AWS generators use RandomString
   (mixed case) for ids that are lowercase hex (i-, ami-, sg-, eni-, ALB id, target group id,
   detector id, trace id) or uppercase (AKIA/ASIA + 16 of [A-Z0-9], AIDA/AROA + 17). ESCU
   matches `AKIA[0-9A-Z]{16}` and `i-[0-9a-f]{17}`; none of the generated ids match.

#### aws_cloudtrail: PARTIAL

What parses: 10 eventNames, userIdentity.type, src on 299, user on 175, action and status on
260; tags authentication/multifactor on ConsoleLogin, account/change/management on
CreateUser, DeleteUser, CreateAccessKey, assume_role on AssumeRole, change/instance on
RunInstances and StopInstances. PutBucketPolicy gets no tag (the TA has no eventtype for
it). The record shape matches the reference
(https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).

Defects (aws_cloudtrail.go):

1. ConsoleLogin carries `"eventType": "AwsApiCall"`; real sign-ins are `AwsConsoleSignIn`
   and awsRegion us-east-1. Fix in generateConsoleLogin.
2. eventVersion "1.08" without the fields that version implies: eventCategory (since 1.07)
   and tlsDetails (since 1.08) are absent on all 299. Add `"eventCategory": "Management"`
   and tlsDetails {tlsVersion, cipherSuite, clientProvidedHostHeader} in buildBaseEvent; for
   console user agents set sessionCredentialFromConsole and omit tlsDetails; bump to 1.11.
3. userIdentity is incomplete: IAMUser identities always carry userName and accessKeyId
   (only 93 of 299 have userName); AssumedRole identities carry sessionContext.attributes and
   sessionContext.sessionIssuer (the TA's EVAL-userName falls back to it and gets nothing).
   Fix: iamUserIdentity() and assumedRoleIdentity() helpers used by every template.
4. AssumeRole lacks `resources` and `responseElements.credentials.expiration` is RFC3339
   where CloudTrail writes "Nov 14, 2026, 6:53:47 AM".
5. AuthorizeSecurityGroupIngress fromPort/toPort are strings; CloudTrail logs numbers.
   PutBucketPolicy should carry additionalEventData and resources for realism.
6. Mix: all ten templates are write calls by IAM users from random public IPs. Real
   CloudTrail is 90 percent read-only, has errorCode events (AccessDenied,
   Client.UnauthorizedOperation, NoSuchEntity), AWSService identities, Root, federated
   sessions. Without AccessDenied no "excessive failed API calls" detection fires; without
   StopLogging/DeleteTrail no logging tamper detection fires.

#### aws_guardduty: PARTIAL

What parses: 6 types, severity (CIM low/medium/high), tags attack/ids on EC2 types and alert
on ConsoleLoginSuccess.B; raw type in raw_gd_type. The JSON matches the GetFindings Finding
shape; all six types exist and none is retired.

Defects (aws_guardduty.go):

1. Severity is random per finding (randomSeverity picks 2.0/4.5/7.0/8.5 for every type).
   Real findings have a fixed default per type
   (https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html):
   SSHBruteForce Low (2), PortProbeUnprotectedPort Low (2), BitcoinTool.B!DNS High (8),
   BlackholeTraffic Medium (5), C&CActivity.B!DNS High (8), ConsoleLoginSuccess.B Medium (5);
   range 1.0 to 10.0 (https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html).
   Fix: buildBaseFinding takes a severity; drop `severityLabel` (not a finding field).
2. Type name: the real C2 type is `Backdoor:EC2/C&CActivity.B!DNS`; generator emits
   `Backdoor:EC2/C2Activity.B!DNS`. The TA's lookup and ESCU match on the real string.
3. PortProbe port and portName are independent (27017 with SSH) and port is a string. Use
   pairs {3389 RDP, 22 SSH, 3306 MYSQL, 5432 POSTGRESQL, 27017 MONGODB} as ints.
4. Thin resource and action blocks: instanceDetails lacks availabilityZone, imageId,
   instanceState, launchTime, platform, networkInterfaces, tags; networkConnectionAction
   lacks localIpDetails.ipAddressV4, so the TA's EVAL-dest for SSHBruteForce falls through to
   the attacker IP and dest equals src. ConsoleLoginSuccess.B title and description are
   invented (real: "Multiple successful console logins from different geographic locations
   were observed for IAM user X").
5. detectorId and the detector arn segment are 32 lowercase hex (RandomHex, not
   RandomString).
6. Aggregation: GuardDuty updates an existing finding (same id, count +1, updatedAt moves)
   rather than issuing a new id per occurrence. Keep a per-type cache and re-emit with
   count+1 most of the time.

#### aws_vpcflow: PARTIAL (close to GOOD)

What parses: action, vpcflow_action, protocol, protocol_code, src_ip, dest_port, bytes,
transport, interface_id on all 299; tags cloud/communicate/network. The line matches the
version 2 default format (https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html).

Defects (aws_vpcflow.go generateFlow):

1. log_status: allowed values are OK, NODATA, SKIPDATA; the raw line ends in a literal `-`
   while `fields` says OK. One token: replace `-` with `OK`.
2. interface id `eni-` + 17 lowercase hex (randomENI should use g.RandomHex(17)).
3. Protocol and port are independent (17 to 22/80/443/3389/3306, 6 to 123). Pick (dstport,
   protocol) pairs; add protocol 1 with ports 0 0 for ICMP.
4. REJECT volume: rejected flows are a few packets at 40 to 60 bytes; the sample has REJECT
   with 775 packets and 998200 bytes.
5. Flow pairs: a real connection yields two records per window (one per direction); emitting
   both makes bidirectional and bytes_in/out detections work.
6. Occasional NODATA records, which real feeds contain.

#### aws_alb: BAD

What parses: nothing. RequestType, ELB, elb_status_code, ClientPort, src_ip, http_method are
0 of 299. Real entry
(https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html):

```
http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "-" "-" 0 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-" TID_1234abcd5678ef90 "-" "-" "-"
```

Two things break the TA: (a) field 3 (elb) and field 4 (client:port) are joined by `/`
(`app/web-alb-x/KmQh.../215.62.233.88:6403`), so the regex consumes one token and everything
shifts; (b) the line ends at matched_rule_priority, and the TA's single REPORT regex
`aws_elb_accesslogs_extract_all_fields` requires request_creation_time, actions_executed,
redirect_url and error_reason (fields 22 to 25).

Fix (aws_alb.go generateALBLog, the rawEvent Sprintf):

1. `"%s %s %s/%s:%d %s ..."` becomes `"%s %s %s %s:%d %s ..."` (a space between elb and
   client).
2. Append request_creation_time (timestamp minus the processing times,
   `2006-01-02T15:04:05.000000Z`), actions_executed ("forward"), redirect_url "-",
   error_reason "-", target:port_list, target_status_code_list, classification "-",
   classification_reason "-", conn_trace_id `TID_` + 16 hex.
3. Status consistency: no target dispatched (elb 503) means target:port "-", times -1,
   target_status_code "-"; a target that answered 500 yields elb 500; 502 means target_status
   "-".
4. ssl_cipher and ssl_protocol depend on the listener ("-" "-" for http and ws).
5. Request line scheme is the listener scheme and the host carries the port
   (`"GET https://host:443/ HTTP/1.1"`); ws/wss use http/https in the request line.
6. Ids: ALB id and target group id 16 lowercase hex, trace id `Root=1-<8 hex>-<24 hex>`.
   Drop "ELB-HealthChecker/2.0" from client user agents (health checks never appear in the
   access log). For https set domain_name and chosen_cert_arn.

#### azure_activity: PARTIAL

What parses: 6 operationNames; user 0 of 299; vendor_account 0; change_type "resources" for
virtualMachines/write and delete; action empty for KeyVault secrets/read, securityRules/write,
regenerateKey/action; tag change on roleAssignments and VM ops. Real Event Hub record schema:
https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema.

Defects (azure_activity.go buildBaseEvent unless noted):

1. identity.claims uses invented short keys (name, oid, tid). The TA's EVAL-user reads
   `identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` and user_type
   reads `identity.authorization.evidence.principalType`. Emit the JWT claim keys (name, upn,
   objectidentifier, tenantid, appid, puid, ipaddr, aud, iss, iat, nbf, exp) and
   identity.authorization.evidence {role, roleAssignmentScope, roleAssignmentId,
   roleDefinitionId, principalId, principalType}.
2. Case: the exported log upper-cases operationName and resourceId
   (`MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE`); the TA's EVAL-change_type, EVAL-image_id and
   EVAL-object compare against the upper-case strings, so VM write/delete classify as
   "resources". strings.ToUpper both (keep identity.authorization.action mixed case).
3. Missing top-level tenantId (the TA aliases it to vendor_account).
4. Values: level "Information" (not "Informational"); resultType Start | Success | Failure |
   Accept (not "Succeeded"); resultSignature "Succeeded.Created", "Started.",
   "Failed.Forbidden".
5. Every Administrative write produces a Start record and a final record with the same
   correlationId; only the final one is emitted.
6. generateKeyVaultSecretGet is not an activity log event (data plane; it lands in Key Vault
   diagnostic logs as AuditEvent SecretGet). Replace with a control-plane op.
7. properties.entity is not a real property; the log carries statusCode, serviceRequestId,
   eventCategory and sometimes a requestbody string.
8. Tenant and subscription random per event; "ServicePrincipal-Deploy" as a name claim (SPs
   have appid and no name claim).

#### azure_ad_signin: PARTIAL

What parses: action success 207, failure 92; errorCodes 0, 50053, 50055, 50057, 50074,
50126, 53003; user, src, reason, authentication_method on all; tag authentication on all.
The record matches the Graph signIn resource
(https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0).

Defects (azure_ad_signin.go):

1. riskDetail holds riskEventTypes values (unfamiliarFeatures, anonymizedIPAddress,
   impossibleTravel, maliciousIPAddress). riskDetail is an enum (none,
   adminGeneratedTemporaryPassword, ..., hidden); detections belong in `riskEventTypes_v2`
   and "impossibleTravel" does not exist (unlikelyTravel). Fix in generateRiskySignin.
2. Impossible device and geo combinations from independent picks: iOS with DESKTOP-xxx,
   Azure AD Joined, Edge 120, "Other clients"; coordinates as strings and wrong for the city.
   Use device profile tuples and per-city coordinates as numbers.
3. authenticationMethod values "PhoneAppNotification" and "PhoneAppOTP" are legacy; sign-in
   logs show "Mobile app notification", "Mobile app verification code", "Text message",
   "Windows Hello for Business", "FIDO2 security key", "Previously satisfied". Add
   authenticationStepRequirement and authenticationStepResultDetail.
4. status.failureReason strings are paraphrases; use the real ones (50126 "Error validating
   credentials due to invalid username or password.", 50053 "Account is locked because user
   tried to sign in too many times with an incorrect user ID or password.", 50057 "User
   account is disabled...", 50055 "The password is expired.", 50074 "Strong Authentication is
   required.", 53003 "Access has been blocked by Conditional Access policies...").
5. Service principal sign-ins are a different log: servicePrincipalId, servicePrincipalName,
   appId, resourceDisplayName, no deviceDetail or user fields, `signInEventTypes:
   ["servicePrincipal"]`. With userPrincipalName "" the TA's user is empty.
6. appId is a fresh uuid per event for well-known first-party apps and resourceId equals
   appId. Use the fixed ids (Azure Portal c44b4083-3bb0-49c1-b47d-974e53cbdf3c, Teams
   1fec8e78-bce4-4aaf-ab1b-5451cc387264, OfficeHome 4765445b-32c6-49b0-83e6-1d93765276ca,
   Microsoft Graph 00000003-0000-0000-c000-000000000000, SharePoint Online
   00000003-0000-0ff1-ce00-000000000000, Exchange Online 00000002-0000-0ff1-ce00-000000000000)
   and the resource the app called.
7. tenantId random per event; UPNs mix three domains in one feed; UPN not lower-cased (Graph:
   always lowercase); fabrikam.com users should be guests.
8. Missing fields detections use: userType, authenticationProtocol, tokenIssuerType,
   uniqueTokenIdentifier, homeTenantId, resourceTenantId, incomingTokenType, signInEventTypes,
   networkLocationDetails, mfaDetail, autonomousSystemNumber, processingTimeInMilliseconds
   (the TA's EVAL-duration uses it).

#### o365_audit: PARTIAL

What parses: SharePoint FileAccessed/FileDeleted/FileModified tags access/cloud/data with all
CIM fields; UserLoggedIn authentication; TeamCreated change; MailItemsAccessed user/src/dest
only (action, object, record_type empty: the TA's lookups have no entry for RecordType 50, a
TA gap). Schema:
https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema.

Defects (o365_audit.go):

1. RecordType is a string ("6"); the schema says Edm.Int32. Any `RecordType=6` numeric
   comparison in content fails. buildBaseEvent should take an int.
2. SourceFileExtension bug: `filename[len(filename)-5:]` gives "b.csv", "A.pdf", ".docx";
   real is "docx". FileModified and FileDeleted lack SourceFileExtension and
   SourceRelativeUrl entirely (file_path 0 of 82), and all three lack Site, WebId, ListId,
   ListItemUniqueId, CorrelationId, ApplicationDisplayName. One sharePointFileFields helper
   for all three; drop ModifiedProperties from FileModified.
3. OneDrive paths are `https://contoso-my.sharepoint.com/personal/john_smith_contoso_com/...`
   with Workload OneDrive, not `personal/john_smith` under the main tenant.
4. MailItemsAccessed lacks the Exchange mailbox audit base fields: ClientIPAddress,
   ClientInfoString, LogonType 0, ExternalAccess, MailboxGuid, OrganizationName,
   OriginatingServer, AppId/ClientAppId, OperationCount, OperationProperties
   [{MailAccessType, Bind|Sync}, {IsThrottled, False}]. FolderItems do not carry Subject for
   this operation; Sync records carry Folders[].Path only.
5. UserLoggedIn: real Actor is [{ID: upn, Type: 5}, {ID: puid, Type: 3}] with ActorContextId,
   ActorIpAddress (the TA's EVAL-src prefers it), Target [{ID: appId, Type: 0}],
   AzureActiveDirectoryEventType 1, ExtendedProperties (ResultStatusDetail, UserAgent,
   UserAuthenticationMethod, RequestType), DeviceProperties, UserKey a PUID, no "Application"
   field. Add a UserLoginFailed twin with LogonError; today the feed has no failed logins.
6. TeamCreated: schema has TeamName, TeamGuid, Members [{UPN, Role int, DisplayName}],
   ItemName; "TeamType" and "Settings" are invented, Role "Owner" should be 1.
7. OrganizationId random per event (the TA uses it as dest, tenant_id, vendor_account);
   UserId mixes three domains; UserKey is a uuid (SharePoint uses
   `i:0h.f|membership|<puid>@live.com`, Exchange and AAD a PUID).

#### kubernetes_audit: PARTIAL

What parses: verb, level, objectRef.resource, responseStatus.code, user.username, userAgent
auto-extract. The JSON is a valid audit.k8s.io/v1 Event
(https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/). ESCU's kube_audit
macro expects source=kubernetes (a mapping choice). EKS reference:
https://docs.aws.amazon.com/eks/latest/best-practices/auditing-and-logging.html.

Defects (kubernetes_audit.go):

1. Level versus bodies: level is random; pod_create and configmap_update always attach
   requestObject (even at Metadata) and nothing carries responseObject at RequestResponse.
   Under the EKS policy secrets and configmaps are Metadata (the generator forces
   secret_access to RequestResponse; EKS never logs secret bodies). Fix: level per resource,
   requestObject only above Metadata, responseObject only at RequestResponse.
2. requestURI never carries the object name (`/api/v1/namespaces/<ns>/secrets/<name>` for
   get, delete, update; `?fieldManager=kubectl-create&fieldValidation=Strict` on create).
3. RBAC URIs and scope: group APIs are `/apis/<group>/<version>/...`, clusterroles and
   clusterrolebindings are cluster scoped (no namespace), objectRef is {apiGroup, apiVersion
   "v1", resource, name} (the generator puts the full group/version in apiVersion).
4. pods/exec: resource "pods" with subresource "exec"; URI
   `/api/v1/namespaces/<ns>/pods/<pod>/exec?command=...&container=main&stdin=true&stdout=true&tty=true`;
   responseStatus.code 101. Create returns 201, not 200 (the EKS query keys on 201).
5. user and userAgent are a full cross product (admin@company.com with kube-scheduler,
   system:kube-scheduler with argocd and kubectl). Fix: randomUser returns (username, groups,
   userAgent, allowed verbs) tuples; system components get narrow templates.
6. EKS identity: IAM principals appear as the mapped username with `uid:
   "aws-iam-authenticator:<account>:<AROA...>"` and `extra: {accessKeyId, arn, canonicalArn,
   principalId, sessionName}`; service accounts carry the SA uid and, on 1.30+,
   authentication.kubernetes.io/pod-name and pod-uid.
7. annotations: authorization.k8s.io/reason is "" on every allow; RBAC writes `RBAC: allowed
   by ClusterRoleBinding "cluster-admin" of ClusterRole "cluster-admin" to Group
   "system:masters"`. There is no forbid at all; real feeds have decision "forbid" with a 403
   Failure responseStatus and 401 for system:anonymous.
8. Timestamps use nanoseconds; the API server writes microseconds.
9. Pod spec is minimal; add securityContext.privileged, hostPID/hostNetwork, hostPath
   volumes, serviceAccountName, labels, public `:latest` images.

### 4.4 Identity (sme-identity-endpoint.md)

#### okta: PARTIAL

What parses: 5 eventTypes (user.session.start 111, user.authentication.sso 53,
user.account.reset_password 56, user.mfa.factor.activate 44, user.account.lock 44); src,
app, reason, result, src_user, signature, user_agent, dest on all; user on 208 of 308;
change_type and object_category on 144; event_type_description from the TA's lookup on all;
TIME_PREFIX on published gives lag 0; tags account, authentication, change. All five
eventType names exist in okta2_system_log.csv. References: Okta System Log OpenAPI spec
(https://github.com/okta/okta-management-openapi-spec), Go SDK log models
(https://github.com/okta/okta-sdk-golang), event type catalog
(https://developer.okta.com/docs/reference/api/event-types/).

Defects (okta.go):

1. `user` empty on user.mfa.factor.activate and user.account.reset_password: the TA takes the
   target entry with `"type":"User"` for these eventTypes; the generator emits `"target":[]`
   and `[{"type":"Factor"}]`. Real Okta always lists the acted-on user as a target
   `{"id":"00u...","type":"User","alternateId":"login@domain","displayName":"..."}`. Fix: a
   userTarget(actor) helper placed first in both templates.
2. severity is random INFO/WARN/ERROR in buildBaseEvent, so successful SSO carries ERROR
   (TA maps it to high). Real: INFO for successes, WARN for failures and lockouts, ERROR only
   for system errors. Set INFO; generateAuthFailure and generateAccountLock already override.
3. request.ipChain[0].ip is a second random IP unrelated to client.ipAddress; the chain ends
   in the client IP with geographicalContext, `"version":"V4"`, `"source":null`.
4. geolocation lat/lon are strings and wrong for the city; state does not match city. One
   (city, state, postalCode, lat, lon) table, lat and lon as float64.
5. securityContext asOrg, isp, domain drawn independently, asNumber random, isProxy missing.
   One table of coherent tuples plus `"isProxy": false`.
6. debugContext is `{}` except lock, which carries invented keys (lockoutReason,
   failedAttempts). Real events always carry debugData.requestId, requestUri, url; sign-ins
   add threatSuspected, dtHash, deviceFingerprint.
7. legacyEventType copies eventType; real values are core.user_auth.login_success,
   core.user_auth.login_failed, core.user_auth.account_locked, app.auth.sso,
   core.user.factor.activate, core.user.config.password_update.
8. published uses RFC3339Nano; Okta publishes milliseconds (cosmetic; the TA parsed it).
9. authenticationContext lacks authenticationProvider, credentialProvider, credentialType,
   issuer, interface (null when not applicable; OKTA_AUTHENTICATION_PROVIDER and PASSWORD for
   a password login).
10. outcome.reason: INVALID_CREDENTIALS and LOCKED_OUT are real; MFA_ENROLL_REQUIRED and
    PASSWORD_EXPIRED are not seen on user.session.start; VERIFICATION_ERROR and
    GENERAL_NONSUCCESS are.
11. displayMessage: lock is "Max sign in attempts exceeded"; MFA activation never embeds the
    factor in the message (it goes in the target and debugData.factor).
12. Ids: app ids are 19 characters (Okta ids are 20); factor ids start with `mfa` (real:
    `opf`, `sms`, `ufs`, `fwf`). Cosmetic.
13. user.authentication.sso target lacks the AppUser entry. Cosmetic.
14. Mix: equal weights give 14 percent lockouts and 18 percent password resets; a real org is
    over 90 percent session.start, sso and token grants. GetEventType lists
    policy.lifecycle.update and application.lifecycle.create but no template emits them
    (stale metadata).

### 4.5 Network sensors (sme-network.md)

#### zeek: PARTIAL

What parses: the raw JSON keys auto-extract (id.orig_h, id.resp_p, uid, conn_state, query,
method, status_code). Nothing from the TA for Zeek applies outside its app context: src,
dest, src_ip, dest_port, bytes are 0 on every bro:*:json sourcetype except notice (src 52
from the raw key). Two layers, both Splunk-side (section 5): Splunk_TA_zeek 1.0.11 ships
`[] export = none`, and even inside the app the `bro:<log>:json` stanzas carry no src/dest
aliases (those live in the `zeek:<log>` stanzas and read Corelight's flattened `id_orig_h`,
which neither Zeek nor the generator emits). Searched inside the app context, transport,
bytes, action (from the conn_state lookup), reply_code, http_method, ssl_subject, file_name,
eventtypes and CIM tags all appear; src and dest stay empty for every log but notice.
Recommendation: keep the generator on Zeek's native dotted keys and the bro:*:json
sourcetypes; fix the export and add aliases on the head.

Defects (zeek.go; references docs.zeek.org conn.html, ssl.html, files.html, Files::Info):

1. `ts` is an integer; Zeek writes epoch seconds with microseconds (`1591367999.305988`).
   `float64(timestamp.UnixMicro())/1e6` in every template.
2. `"-"` and `""` placeholders: Zeek's JSON writer omits unset fields. The generator writes
   `"service":"-"`, `"referrer":"-"`, `"origin":"-"`, `"info_code":"-"` (a count; a string is
   a type error), `"fuid":"-"`, `"file_mime_type":"-"`, `"sub":""`. Omit the key instead.
3. http `id.resp_p` is a string ("80"); ports are numbers everywhere else (generateHTTP).
4. conn.log fields are drawn independently: 8 of 8 sample conn events are
   self-contradictory (S0 "no reply" with 116 response packets and 867 KB; TCP history letters
   on a UDP flow; orig_ip_bytes smaller than orig_bytes; service http on port 3306; REJ with
   686 KB back). Pick one profile and derive the rest: tcp SF `ShADadFf` with bytes both
   sides; S0 `S` with no reply bytes, no service, no duration; REJ `Sr`; RSTO `ShADadR`; udp
   SF `Dd`; orig_ip_bytes = orig_bytes + orig_pkts * 40; service from id.resp_p (80 http, 443
   ssl, 22 ssh, 25 smtp, 53 dns, 3389 rdp, 445 smb, 88 krb_tcp). Add `ip_proto` (Zeek 7.1+).
5. dns.log: `qtype` must be numeric and `qtype_name` the mnemonic; `answers` is always one
   IPv4 even for TXT/MX/NS/CNAME; rcode is always 0 (add NXDOMAIN 3 without answers, SERVFAIL 2).
6. http.log: `status_msg` always "OK" (map it per status); request_body_len 222 to 9151 on
   GET and HEAD (0 unless POST/PUT); response_body_len 39816 on HEAD and 301; truncated user
   agents (reuse webserver.go's); add orig_fuids and orig_mime_types for POST.
7. ssl.log: cipher and version independent (TLS_AES_* and TLS_CHACHA20_* only with TLSv13;
   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 only with TLSv12); resumed and TLSv13 sessions carry
   no certificate fields; subject CN does not match server_name; add next_protocol "h2".
8. files.log: `analyzers` is one random entry while hashes are always written; default policy
   gives `["MD5","SHA1","SHA256"]` plus PE for x-dosexec and EXTRACT when extraction is on;
   sha1 is missing; mime_type and filename contradict (script.js as application/pdf);
   seen_bytes less than total_bytes with missing_bytes 0 is impossible; duration whole seconds
   (real: fractions). The generator writes the pre-6.0 shape (tx_hosts, rx_hosts, conn_uids),
   which is the one this TA aliases; keep it but know it is a Zeek 5 shape.
9. notice.log: `HTTP::Malicious_User_Agent` and `DNS::Tunneling` do not exist in Zeek
   (neither is in the TA's bro_note_alert_type.csv). Replace with Scan::Address_Scan,
   SSH::Password_Guessing, SSL::Certificate_Expired, DNS::External_Name, FTP::Bruteforcing,
   HTTP::SQL_Injection_Attacker, Signatures::Sensitive_Signature,
   TeamCymruMalwareHashRegistry::Match, Software::Vulnerable_Version,
   CaptureLoss::Too_Much_Loss. src, dst, p must equal id.orig_h, id.resp_h, id.resp_p;
   `actions` always includes Notice::ACTION_LOG; messages should be the formatted real ones
   ("1.2.3.4 scanned at least 15 unique ports of host 10.0.0.5 in 0m1s"); peer_descr "bro"
   is pre-3.0.
10. Key order: json.Marshal sorts keys, so every event starts with "AA"/"actions"/"analyzers"
    instead of ts, uid, id.orig_h. Cosmetic; a struct with json tags fixes it.
11. Fine: uid/fuid format, local_orig/local_resp, trans_depth, qclass, validation_status,
    curve names. RandomIPv4External can return 169.254.x.x and 100.64.0.0/10 (net.IP.IsPrivate
    does not cover them); minor.

#### suricata: PARTIAL

What parses: the CCX add-on maps src, dest, action, signature, severity_id, severity, bytes,
vendor_product on alerts; query and answer on dns; filename on fileinfo; bytes, duration,
tcp_flag on flow; http_method, url, bytes on http; ssl_server_name_indication on tls.
Eventtypes and tags: ids/attack/network on alerts, dns/resolution, web, tls/certificate,
network/session. `timestamp`, flow_id, in_iface, tx_id and the 5-tuple match the EVE format
(https://docs.suricata.io/en/suricata-7.0.0/output/eve/eve-json-format.html).

Defects (suricata.go):

1. Signature ids do not match their messages (RandomSuricataSignature; checked against ET
   Open suricata-7.0.3, https://rules.emergingthreats.net/open/suricata-7.0.3/rules/): sid
   2019876 is "ET SCAN SSH BruteForce Tool with fake PUTTY version" (the generator's "ET SCAN
   Potential SSH Scan" is 2001219); 2008578 is "ET SCAN Sipvicious Scan" (the Nmap NSE rule is
   2009359); 2016149 is a STUN rule; 2027757 is not in emerging-coinminer.rules. 2100498 and
   2013028 are right. Copy sid, msg, classtype and priority as a unit from the ruleset.
2. `alert.severity` is random 1 to 3; it is the classtype priority, fixed per signature
   (policy-violation 1, trojan-activity 1, attempted-recon 2, bad-unknown 2,
   protocol-command-decode 3). Splunk shows every category spread over all three.
3. Direction, port and app_proto are unrelated to the signature (curl User-Agent Outbound
   from an external source to internal 445 over http; CoinMiner over UDP to 80 with smtp).
   Give each signature a direction, proto and app_proto; app-layer alerts carry tx_id and the
   matching http/tls/dns sub-object; ET rules carry alert.metadata.
4. flow events carry a `tcp` object on UDP flows; tcp_flags hex contradicts the booleans
   (build the hex from FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10); byte counts are
   impossible (4.7 KB per packet; make bytes = pkts * 60..1500).
5. dns events mix three schemas: `"type":"query"` with response-only fields and v1 rdata/ttl
   beside v2 flags/qr. In Suricata 6/7 a query is `{"type":"query","id":..,"rrname":..,
   "rrtype":"A","tx_id":0}` and an answer carries version 2, flags, rcode and an `answers`
   array; NXDOMAIN carries no rdata. Trade-off: the CCX TA aliases `dns.rdata AS answer` (v1
   shape); with v2 a local alias `answers{}.rdata AS answer` is needed on the head.
6. tls: version must be "TLS 1.2" / "TLS 1.3" (the generator also emits "TLSv1.2");
   fingerprint is a colon-separated lowercase SHA1; TLS 1.3 sessions carry no subject,
   issuerdn, serial, fingerprint, notbefore, notafter; issuerdn pairs are invented ("CN=DigiCert
   SHA2, O=GlobalSign"; real "C=US, O=Let's Encrypt, CN=R3"); SNI and subject are random
   strings; ja3 should be the MD5 of a real ja3 string (a fixed table of pairs is the simple
   correct option).
7. fileinfo: src_port is RandomCommonPort regardless of app_proto (ftp with 389, smb with 80);
   magic contradicts filename (setup.exe as PNG image data). HTTP fileinfo carries the http
   sub-object, SMTP an email object; file_id only when stored.
8. http: hostnames and urls are random strings; `redirect` always present and empty;
   http_refer always equals the host.
9. `host` is a random server name per event; in EVE it is the sensor name (one or two values
   per site). The TA maps it to dvc.

#### dns_query: BAD

It lands and spath works (query_name, client_ip, answers{}.data, flags.recursion_desired),
but query, src and eventtype are empty: no resolver or DNS security product writes this
schema, nothing maps it to Network_Resolution, and the values contradict each other.

Realism defects (dns_query.go buildBaseEvent and the six templates): flags.authoritative is
random (AA is set only by authoritative servers); protocol DoH/DoT random per event, including
to a Pi-hole on a private address; dns_server mixes hostnames and IPs (a resolver logs itself
once, in host); blocked queries answer REFUSED (RPZ, Pi-hole and Umbrella block with NXDOMAIN
or a sinkhole A record); entropy is a string and entropy, anomaly_score, query_length are
detection output, not resolver output; query_suspicious domains carry a threat_intel block no
resolver has. transaction_id, client_port, response_time_ms, query_class are fine.

What real resolver logs look like, and the sourcetype to target:

- Windows DNS Server debug log: `11/14/2026 5:54:26 AM 0A1C PACKET 000001E3C8F7A2B0 UDP Rcv
  <client> 4a3b Q [0001 D NOERROR] A (3)www(6)google(3)com(0)` and the `Snd ... R Q [8081 DR
  NOERROR]` response. Splunk_TA_windows 10.0.1 (already installed) parses it as
  `MSAD:NT6:DNS` (src_ip, xid, direction, protocol, questiontype, questionname, response,
  flags; EVAL-query; eventtype nt6-dns-events tagged network/resolution/dns). The analytical
  ETW channel (events 256 to 261) is the modern form, tagged as `msdns:analytical`.
- BIND 9 query log: `14-Nov-2026 05:54:26.934 queries: info: client @0x7f3c4c0a1b60
  <client>#60136 (www.google.com): query: www.google.com IN A +E(0)K (<server>)`, RPZ hits in
  category rpz. Splunk Add-on for ISC BIND (2876) parses it as `isc:bind:query`.
- Infoblox NIOS syslog (`infoblox:dns`, add-on 2934), Unbound (no supported TA), dnsmasq /
  Pi-hole (community TAs only), Cisco Umbrella DNS CSV (`cisco:umbrella:dns`, Cisco Cloud
  Security add-on) for the block and threat fields.

Recommendation: rewrite the six templates as Windows DNS debug log lines with sourcetype
`MSAD:NT6:DNS` (one Rcv line per query, one Snd line per response; blocked is Snd with
NXDOMAIN from the policy zone), since the parsing TA is already on the stack and the
generator already covers Windows. Second choice: BIND query log as `isc:bind:query`. Keep the
tunneling and DGA stories as long TXT and A names; detections work on the query, not on a
pre-computed entropy field.

#### webserver: PARTIAL

What parses: client, src, status, http_method, uri_path, url, http_referrer, http_user_agent,
request_bytes, action, status_type, timestamp, http_version on all 299; `bytes` empty by
design (`%b` lands in request_bytes, a TA naming quirk); user null because `%u` is always
"-"; no eventtype and no tag. The line matches the combined LogFormat
(https://httpd.apache.org/docs/2.4/logs.html). `tag=web` is missing because the TA's
eventtype leaves out apache:access:combined (section 5).

Realism defects (webserver.go generateAccess):

- `%b` is RandomInt(100, 100000) for every request: HEAD never has a body (`-`), 204 and 304
  are `-`, 301/302 bodies are a few hundred bytes, 404 pages under 1 KB, a static object has
  one size. Sample: `"HEAD /config.php HTTP/1.1" 500 90065`.
- Method, path, status and user agent are independent: `DELETE /static/js/app.js` from
  python-requests, `DELETE /about` 403 from Googlebot, `POST /.env` 500, `OPTIONS /contact`
  200. Bots and browsers send GET; DELETE/PUT only on /api/ paths; scanner paths come with
  scanner agents and answer 404/403 with no Referer. A (path, allowed methods, size, typical
  status) table fixes most of it.
- `%u` is always "-" while /admin, /dashboard and /api/v1/users return 200.
- Every event is a new random external client; real logs show the same client fetching a
  page and then its assets, and query strings (which also exercise uri_query).

### 4.6 Linux and infrastructure (sme-linux-infra.md)

#### linux_auditbeat: BAD

It lands and the ECS skeleton is right (@timestamp, ecs.version, agent.type auditbeat,
event.{kind,category,type,action,outcome,module,dataset}, host.*), but the values are not
what Auditbeat 8.11 emits for any of its five datasets. Evidence: `stats count by
event.module event.dataset event.action event.outcome` shows auditd executed/fork/exec each
with success and failure, login logged-in/logged-out/session-opened/session-closed each with
success and failure; `event.outcome success` beside `auditd.result fail` 5 times; `logged-in
success` with `system.auth.ssh.event Invalid` 4 times. References: Auditbeat auditd example
and field list
(https://raw.githubusercontent.com/elastic/beats/main/auditbeat/module/auditd/_meta/data.json,
https://www.elastic.co/guide/en/beats/auditbeat/8.11/exported-fields-auditd.html), action
vocabulary
(https://raw.githubusercontent.com/elastic/go-libaudit/main/aucoalesce/normalizations.yaml),
system login/package/socket datasets
(https://www.elastic.co/guide/en/beats/auditbeat/8.11/auditbeat-dataset-system-login.html),
file_integrity example
(https://raw.githubusercontent.com/elastic/beats/main/auditbeat/module/file_integrity/_meta/data.json).

Defects (linux_auditbeat.go):

1. generateProcess: real execve groups normalise to `event.action: executed`, category
   process, type start, with auditd.message_type syscall, auditd.result, auditd.summary
   {actor, object, how}, auditd.data {syscall execve, a0.., exit, tty, arch}; outcome derived
   from result. Generator picks action from executed/fork/exec (fork and exec are not
   Auditbeat actions), type from start/end/info, outcome and result separately; no
   message_type, summary or data; process.hash.sha256 and process.start are never produced
   by the auditd module; every process runs `<exe> --config /etc/config.yaml`; process.ppid
   never equals process.parent.pid.
2. generateUserLogin: real actions are only user_login (type start plus
   authentication_success or authentication_failure), user_logout (type end, no outcome),
   boot, shutdown; event.origin /var/log/wtmp|btmp; the message "Login by user vagrant (UID:
   1000) on pts/2 (PID: 14962) from <ip> (IP: <ip>)"; user.{name,id,terminal},
   source.ip, process.pid, related. It never emits system.auth.ssh.* (Filebeat's auth
   fileset), source.geo.* (an ingest pipeline) or process.name. Generator emits
   logged-in/logged-out/session-opened/session-closed with outcome and type drawn
   separately, a system.auth.ssh block drawn separately again, and a geo block where city and
   country are independent (New York in BR, Mumbai in US). Better for a SOC: emit the auditd
   module's USER_LOGIN, USER_AUTH, USER_CMD records (event.action logged-in, authenticated,
   ran-command; auditd.data op, acct, terminal, addr, hostname, cmd; summary.how
   /usr/sbin/sshd or /usr/bin/sudo; network.direction inbound; source.ip), which is what
   ssh brute force and sudo detections key on.
3. generateSocket: the 8.x dataset emits one `network_flow` per flow with event.start/end/
   duration, source/destination/client/server {ip, port, packets, bytes}, network
   {community_id, direction, type, transport}, flow {final, complete},
   system.audit.socket.*, process.*. Generator emits `socket_opened` with no counters and
   process and port unrelated (sshd egress udp to 22). Couple process to port and direction;
   udp only for dns and ntp.
4. generatePackage: real actions use underscores (package_installed, package_removed,
   package_updated, kind event; existing_package is the only kind state) with message
   "Package nginx (1.18.0-6ubuntu14) installed" and system.audit.package.*. Generator uses
   dashes, kind state always, type drawn separately.
5. generateFile: actions are right; event.type drawn separately (deleted with creation); a
   deleted file has no hash, size, mode or inode; file.owner root with uid 43018; default
   hash_types is sha1 only.
6. Cross-template: RandomLinuxUser and user.id are independent (root with uid 17778); host.id
   is a new GUID per event for the same hostname.

Target sourcetype: no add-on parses Auditbeat ECS JSON, so msn:* is right for this shape.
For the Splunk-native path the Unix and Linux TA (installed) parses raw auditd text as
`linux_audit` (TIME_PREFIX `audit\(`, REPORT-command, LOOKUP-action on op, EVALs on type
USER_AUTH / ADD_USER / USER_CMD and res). Recommended: add a `linux_auditd` generator writing
raw records, one per line:

```
type=SYSCALL msg=audit(1794700000.123:1066789): arch=c000003e syscall=59 success=yes exit=0 a0=... ppid=816 pid=28721 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=58 comm="wget" exe="/usr/bin/wget" subj=unconfined key="exec"
type=EXECVE msg=audit(1794700000.123:1066789): argc=3 a0="wget" a1="-q" a2="https://example.com/x"
type=USER_AUTH msg=audit(1794700000.456:1066790): pid=2913 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_unix acct="ec2-user" exe="/usr/sbin/sshd" hostname=<client> addr=<client> terminal=ssh res=failed'
type=USER_LOGIN msg=audit(1794700000.789:1066791): pid=2913 uid=0 auid=1000 ses=58 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=<client> addr=<client> terminal=/dev/pts/0 res=success'
type=USER_CMD msg=audit(1794700001.000:1066792): pid=3001 uid=1000 auid=1000 ses=58 msg='cwd="/home/ubuntu" cmd=617074206C697374 exe="/usr/bin/sudo" terminal=pts/0 res=success'
```

mapped to sourcetype `linux_audit`, index noise_linux. That is the smallest change that gives
CIM action, user, src, command and status from the installed add-on. Keep the ECS generator
for Elastic-shaped data, with its vocabulary fixed.

#### vmware_vcenter: PARTIAL

The objects follow the vSphere API vim.event.Event layout (key, chainId, createdTime,
userName, datacenter, computeResource, host, vm, fullFormattedMessage plus the subclass
fields: ipAddress, userAgent, locale, sessionId for UserLoginSessionEvent; alarm, entity,
from, to for AlarmStatusChangedEvent; sourceHost, sourceDatastore for VmMigratedEvent;
https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.event.UserLoginSessionEvent.html
and siblings), and the field names are the ones Splunk's own vCenter login search uses on
vmware_inframon:events
(https://lantern.splunk.com/Observability_Use_Cases/Monitor_Business/Monitoring_VMware_virtualization_infrastructure/vCenter_console_logins).
Splunk auto-extracts eventType and userName.

Defects (vmware_vcenter.go):

1. fullFormattedMessage contradicts the structured fields: generateVMCreated and
   generateVMPoweredOn/Off call randomHostName() a second time for the message ("vm-db-523 on
   esxi-15 is powered on" beside host.name esxi-19); generateVMMigrated writes "from esxi-05
   to esxi-11" while host.name is esxi-20. Real vCenter builds the message from the same
   arguments ("{vm.name} on {host.name} in {datacenter.name} is powered on"; "Migration of
   virtual machine {vm.name} from {sourceHost.name}, {sourceDatastore.name} to {host.name},
   {ds.name} completed"). Fix in buildBaseEvent and generateVMMigrated; add ds and
   sourceDatacenter.
2. generateAlarmTriggered: entity.name differs from host.name; `source` is missing; userName
   is a human account although alarm status changes are system generated (empty userName);
   message should read "Alarm 'Host CPU usage' on esxi-11.vsphere.local changed from Green to
   Red"; `from` should vary.
3. generateUserLogin: the message is "User {userName}@{ipAddress} logged in as {userAgent}"
   (Sekoia sample https://docs.sekoia.com/integration/categories/endpoint/vmware_vcenter/,
   Broadcom KB https://knowledge.broadcom.com/external/article/426979); userAgent values are
   `VMware vim-java 1.0` (H5 client), `PowerCLI/12.7.0.20091289`, `govc/0.30.0`, `pyvmomi
   Python/3.9.5 (...)`, never "VMware vSphere Client/7.0.3"; AD accounts show as
   `CORP\admin`. No failed logins (BadUsernameSessionEvent, NoAccessUserEvent) and no
   UserLogoutSessionEvent.
4. key and chainId are independent; for a standalone event chainId equals key.
5. createdTime has second precision; vCenter emits microseconds. Cosmetic.
6. svc-backup creates and vMotions VMs in every datacenter; user-initiated VmMigratedEvent is
   a manual vMotion, DRS moves are DrsVmMigratedEvent with an empty userName.

Target sourcetype: keep the JSON. A local props.conf with `KV_MODE = json` under
`vmware_inframon:events` would make Splunk-side content match. If a text form is wanted, the
one-line vpxd event format (`Event [key] [1-1] [time] [vim.event.VmPoweredOnEvent] [info]
[CORP\admin] [] [chainId] [message]`) is simple to emit as a syslog template.

### 4.7 Metrics (sme-linux-infra.md)

#### metrics_system, metrics_application, metrics_database, metrics_webapi: BAD as delivered

Each generated event's RawEvent is a JSON array of 13 to 42 HEC metric objects
(`{"time":...,"event":"metric","source":...,"host":...,"fields":{"metric_name":"disk.total",
"_value":...,"environment":...,"host":...,"mount":"/",...}}`). The sender (`delivery/hec.go`
Send) wraps the whole array as the `event` string of one `/services/collector/event` call, so
a metrics index rejects it ("metric event is not properly structured") and in an event index
it lands as one 6 to 39 KB array event that needs spath (average raw length 6464 to 16625
bytes; spath finds 56 to 99 metric names per source). Each element on its own is the
documented single-measurement form
(https://help.splunk.com/en/splunk-enterprise/get-data-in/metrics/10.0/get-metrics-data-in/get-metrics-in-from-other-sources),
proved by posting the 20-line metrics_system sample unwrapped: 574 points accepted, `mcatalog`
lists 57 metric names with dims core, cpu, datacenter, device, environment, extracted_host,
fan, gpu, interface, mount, purpose, region, sensor, and `mstats avg(cpu.percent)` works.

**Defect 1 (all four): the array wrapper.** Fix in the backend (section 6), not in the
templates. Better for volume, in the generators: emit the multiple-measurement form, one
object per dimension set with `"metric_name:cpu.user": 23, "metric_name:cpu.system": 9` in
fields; the 42-point disk_space array becomes 6 objects. Change buildMetricEvent in each of
the four files to take a `map[string]float64`.

**Defect 2 (all four): host is both HEC metadata and a dimension.** buildMetricEvent copies
dimensions["host"] into fields and into the top-level host; Splunk keeps the metadata host
and renames the dimension to extracted_host. Delete host from fields.

**Defect 3 (all four): hostname and environment disagree.** randomHost() always returns
`<prefix>-NN.prod.internal` while randomEnvironment() returns production, staging or
development independently. Pick the environment first and build the host from it.

Per-source content:

- metrics_system (GOOD content): names, units and dims are what an SAI or ITSI dashboard
  expects. Nits: disk.inodes.used is fractional (round it); in generateCPU the per-core
  values, cpu.percent.total and the user/system/idle/iowait split are independent and can
  exceed 100; derive the split from the core average.
- metrics_application (PARTIAL content): app.response_time.* carry no unit in the name while
  every other latency metric uses `_ms`; app.errors.count emits one point per endpoint x
  status_code x error_type (36 of 40 points) and dwarfs the rest. JVM and thread-pool metrics
  are good.
- metrics_database (PARTIAL content): generateTransactions always emits db.wal.* although
  engine may be mysql, mariadb, oracle or mssql (generateBufferPool already branches on
  engine; do the same: binlog/innodb for mysql, redo for oracle, log flushes for mssql).
  db.replication.is_replica, is_streaming and db.replica.state are booleans or enums carried
  as metrics; they belong in dimensions.
- metrics_webapi (PARTIAL content): cache.hits and cache.misses are fractional
  (requests * ratio; round them); cache.requests.by_status repeats the same five numbers
  already emitted as separate metrics; ssl.certificate.is_valid and upstream.server.health
  are booleans as metrics. The nginx-style http.connections.*, http.responses.*,
  ssl.handshake.*, upstream.server.* sets are realistic.

## 5. Splunk-side fixes (not generator defects)

| area | finding | fix |
|---|---|---|
| Zeek | Splunk_TA_zeek 1.0.11 ships `metadata/default.meta` with `[] export = none`, so its props, lookups and eventtypes are invisible outside the app context (CCX Suricata and Apache export system, which is why their fields appear). | `local.meta` with `[] export = system` for Splunk_TA_zeek in the tenant app staging. |
| Zeek | Even in-app, the `bro:<log>:json` stanzas carry no src/dest/src_port/dest_port aliases; those live only in the `zeek:<log>` stanzas and read Corelight's flattened `id_orig_h`. | Local props.conf: `[bro:conn:json] FIELDALIAS-src_dest = id.orig_h ASNEW src id.orig_h ASNEW src_ip id.orig_p ASNEW src_port id.resp_h ASNEW dest id.resp_h ASNEW dest_ip id.resp_p ASNEW dest_port`, same for bro:dns:json, bro:http:json, bro:ssl:json. |
| Apache | Splunk_TA_apache 2.1.0's eventtype `access_log_event` is `sourcetype=apache:access OR apache:access:kv OR apache:access:json`, so apache:access:combined gets no tag=web. | Local eventtypes.conf adding `OR sourcetype=apache:access:combined`. |
| Sysmon | Two `sysmon-data` transforms stanzas (Splunk_TA_microsoft_sysmon single-quoted, Splunk_TA_sysmon-for-linux double-quoted) merge by app precedence; the Linux copy wins on this head and is the only reason the double-quoted Windows Sysmon events extract today. | Do not depend on it; fix the generator (S1). If both add-ons stay on one head, know that the Windows Sysmon REPORT runs the Linux regex. |
| Defender | The add-on's `m365:defender:incident:advanced_hunting` stanza keys every CIM eval on `$table`; the streaming shape the product emits is the Event Hub record parsed by `ms:defender:eventhub`. | Map the source to `ms:defender:eventhub` once the generator emits the `{time, tenantId, category, properties}` record; or keep the alert-action sourcetype with `$table` rows. |
| O365 | MailItemsAccessed gets no action, object or record_type: the TA's lookups have no entry for RecordType 50. | TA gap; a local lookup row if needed. |
| CloudTrail | PutBucketPolicy has no eventtype in the AWS TA, so no CIM tag. | TA gap; local eventtype if the change model needs it. |
| Suricata | If the generator moves to the EVE v2 dns shape, the CCX alias `dns.rdata AS answer` goes empty. | Local alias `answers{}.rdata AS answer` on the head. |
| Cisco ASA | Both Splunk_TA_cisco-asa 6.0.0 and Cisco Security Cloud define `[cisco:asa]`; settings merge by app precedence. `ta-cisco-asa.tgz` has no version digits in its name, so the store sync cannot match it. | Keep one, or accept the merge; rename the archive. |
| vCenter | No add-on parses the API event JSON. | Local `[vmware_inframon:events] KV_MODE = json` so Splunk-side content built for that sourcetype matches. |
| Kubernetes | ESCU 6.6.0's `kube_audit` macro is `source="kubernetes"`. | Set HEC source=kubernetes for kubernetes_audit if ESCU detections should see it. |
| CIM | Splunk_SA_CIM is not on the search head; no datamodel checks were possible. | Add `splunk-common-information-model` to the tenant apps before the next review. |
| Store | The phoenix store is older than the register (AWS TA 8.1.2 vs 8.3.1, Microsoft Security 3.0.0 vs 4.0.0). | Sync before the next cycle; the map is based on the archives actually in the store. |

## 6. Sender and backend fixes

**hec.go metrics unwrapping (the one backend code change this review needs).** In
`backend/delivery/hec.go` Send: when `event.RawEvent` starts with `[` and the template is
marked as metrics, `json.Unmarshal` the array and append one `hecEvent` per element with
`Event: "metric"`, `Fields: elem["fields"]`, `Time: elem["time"]`, `Host: elem["host"]`, and
source, sourcetype and index from the destination. `hecEvent` already has `Event interface{}`
and `Fields map[string]interface{}`, so no struct change. Post those batches to the
destination URL with the trailing `/event` stripped (`/services/collector` accepts both event
and metric payloads). The HEC destination for the four metrics sources can then point at
noise_metrics and the sender's `metrics_index` workaround goes away. The README's note that
metrics are delivered as the body of an ordinary event describes the current behaviour and
should be updated with it.

**Destination per template already works.** `EnabledEventSource.destination_id` overrides the
run's global destination per source, `template_ids` narrows an entry to a set of templates,
and the backend accepts several entries for the same event type (`noise/generator.go`
buildWeightedPool). The sender used that to give paloalto and zeek one destination per
sourcetype (weight = number of templates so every template keeps the same share). No code
change needed; worth documenting in the README as the way to feed per-template sourcetypes.

**Generator default sourcetypes.** For 14 of 27 sources the generator's default has no stanza
in any add-on (aws:guardduty, azure:activity, cisco:firepower:syslog, crowdstrike:falcon:json,
ms:defender:endpoint, okta:im, pan:url, kube:apiserver:audit, vmware:vcenter, auditbeat,
dns:query, metrics). Change the defaults to the mapped values (aws:cloudwatch:guardduty,
azure:monitor:activity, cisco:ftd:syslog, CrowdStrike:Event:Streams:JSON,
m365:defender:incident:advanced_hunting or ms:defender:eventhub, OktaIM2:log, pan:threat for
url templates) so a bare destination without a sourcetype override parses. Windows sources
should default to sourcetype `XmlWinEventLog` and expect the channel in source.

**Host handling.** Only windows_security, windows_sysmon and microsoft_ad set a host; the
other 24 sources arrive as `host=siem-event-generator` and there is no destination override.
Several add-ons derive dvc or host from the event (Suricata `host`, PAN Device Name, ASA
hostname, FTD hostname, Okta none), but a SOC groups by host for everything. Generators that
know a device or sensor name (cisco_asa, cisco_firepower, paloalto, suricata, zeek, webserver,
vmware_vcenter, linux_auditbeat host.name, crowdstrike ComputerName, the metrics host) should
set `event.Host`, and the HEC destination should accept a `host` override like it does
source. This also ties into the identity pools in section 1 (a small host table per source).

**Source name per destination.** The HEC source defaults to `make-some-noise:<source>`; the
Windows sources need `XmlWinEventLog:<channel>` and Kubernetes may need `kubernetes`. Let a
template carry a source (as it does a sourcetype) so the Windows channel does not have to be
configured on the destination.

**Counters and the stop race.** Stop cancels the loop without waiting for the in-flight
generateAndSend, so each run loses at most one event (generated 300, sent 299). "sent" means
queued in the HEC buffer, not acknowledged: a failed timed flush is only logged and the final
flush on Close is tried once with its error ignored, so a HEC outage at the end of a source
can lose a batch without showing in the counters. Count Splunk against `sent`, and consider
surfacing flush failures in `/noise/status`. Noise runs never update a destination's
`events_sent`; only `/api/generate` does.

**Event time.** The backend does not pass the generated timestamp to HEC, so `_time` is the
receive time for every source and the add-ons' TIME_PREFIX settings never run. Fine for a
live feed; for replaying a day of history a `time` field on the HEC event (from the
generator's timestamp) would be needed.

## 7. Suggested additional datasets

### 7.1 New event types inside existing sources

From the reviewers' "what to add" lists, condensed. All parse with the add-ons already
installed unless noted.

- **cisco_asa**: 302016 (UDP teardown), 302020/302021 (ICMP); 106100 (the ACL log line a SOC
  alerts on, with hit-cnt), 106015, 106016, 106017; 305011/305012 xlate build/teardown;
  authentication 605005/605004, 113004/113005/113012/113015, 109025; change 111010, 111009,
  502101/502102/502103, 111005; VPN lifecycle 722022/722023, 722051, 722033/722034, 113019,
  716001/716002, 713172/713120; threat detection 733100/733101, 419002/419003,
  400013/400032; 302013 variants with identity `(domain\user)` and NAT-translated addresses.
- **cisco_firepower** (after the syslog rewrite): 430003 Security Intelligence blocks
  (SecIntMatchingIP, IPReputationSICategory, URLSICategory, DNSSICategory), DNS fields
  (DNSQuery, DNSRecordType, DNSResponseType, DNS_Sinkhole), SSL decryption fields,
  AccessControlRuleReason, URLCategory/URLReputation, HTTPResponse, UserAgent,
  ReferencedHost, VLAN_ID, identity users; 430001 with ImpactFlag and IOC fields; the LINA
  messages via `%FTD-` (302013 to 302016, 106023, 113039, 722051, 605005); 430002 and 430003
  as one session with the same ConnectionID; optionally eStreamer JSON
  (cisco:sfw:estreamer).
- **paloalto**: THREAT vulnerability (the most common threat subtype), wildfire, file, data,
  scan/flood; SYSTEM logs (`pan:system`: commit, ha, general, ntp, dhcp, vpn, auth failures,
  content update); CONFIG logs (`pan:config`); GLOBALPROTECT (`pan:globalprotect`:
  gateway-connected, gateway-logout, portal-auth); USERID and DECRYPTION logs; TRAFFIC start
  subtype; session_end_reason variety; optional syslog header for syslog destinations.
- **windows_security**: 4634/4647 logoff; 4768, 4769, 4771, 4776 Kerberos and NTLM (the bulk
  of a DC's log; Kerberoasting on 4769 TicketEncryptionType 0x17, AS-REP roasting on 4768
  PreAuthType 0, spraying on 4771 Status 0x18 and 4776 0xC000006A); 4648 explicit
  credentials; 5140/5145 share access (ADMIN$, C$, IPC$); 7045 new service (System channel)
  and 4697; 4698/4702 scheduled tasks; 1102 log cleared, 4719 audit policy changed, 4616 time
  changed; 4663/4656/4660 object access, 4657 registry value; 5156/5157 filtering platform;
  4673/4674, 4704/4705; 4104 PowerShell script block (Microsoft-Windows-PowerShell/Operational)
  and 4103; 4624 logon types 4, 5, type 3 Kerberos, type 10 with ElevatedToken.
- **microsoft_ad**: 4756/4757 universal group; 4735/4737, 4727/4730, 4731/4734; 4738 account
  changed (the most common account-management event), 4781, 4794; 4741/4742/4743 computer
  accounts; 4662 directory object access (DCSync with the replication GUIDs) and 5136; 4719,
  4713, 4706/4707, 4765/4766; 4740 preceded by a burst of 4771/4776 on the same user.
- **windows_sysmon**: 12/13/14 registry (advertised but missing; the TA has registry evals
  ready); 17/18 named pipes; 23/26 file delete, 15 ADS, 2 timestomp; 5 process terminated,
  6 driver loaded, 9 raw access read; 25 process tampering, 19/20/21 WMI, 24 clipboard, 16
  config change, 255 error; EID 1 with real argument lines (powershell -enc, rundll32,
  regsvr32, certutil, wmic) and matching OriginalFileName/Description/ParentImage; EID 3
  with DestinationHostname.
- **microsoft_defender**: AlertInfo rows paired with AlertEvidence; DeviceEvents
  AntivirusDetection, ExploitGuardNetworkProtectionBlocked, AsrPsexecWmiChildProcessBlocked,
  SmartScreenUrlWarning, PowerShellCommand, ScheduledTaskCreated, ServiceInstalled,
  UsbDriveMounted; DeviceRegistryEvents, DeviceImageLoadEvents, DeviceInfo,
  DeviceNetworkInfo; DeviceLogonEvents LogonFailed, IdentityLogonEvents (Defender for
  Identity); EmailEvents, EmailUrlInfo, UrlClickEvents if Defender for Office is in scope.
- **crowdstrike** (stream): AuthActivityAuditEvent (userAuthenticate, twoFactorAuthenticate,
  saml2Assert with Success true/false; the TA tags authentication); UserActivityAuditEvent
  (detection_update, update_policy, create_user, api_client_created with AuditKeyValues);
  IncidentSummaryEvent; RemoteResponseSessionStartEvent/EndEvent with Commands;
  EppDetectionSummaryEvent (the 2024 replacement, with CompositeId, PatternId, MitreAttack
  ids); IdpDetectionSummaryEvent. **crowdstrike_fdr** (once split): ProcessRollup2 with
  EndOfProcess, NetworkConnectIP4 and NetworkListenIP4, DnsRequest with SuspiciousDnsRequest,
  UserLogon and UserLogoff, NewExecutableWritten, PeFileWritten, NewScriptWritten,
  AsepValueUpdate, ScheduledTaskRegistered, ServiceStarted.
- **okta**: user.authentication.auth_via_mfa (success and failure) and
  user.mfa.okta_verify.deny_push; user.session.end and policy.evaluate_sign_on (ALLOW, DENY,
  CHALLENGE); security.threat.detected (ThreatInsight); admin actions with an admin actor and
  a different target (user.lifecycle.create/deactivate, user.account.privilege.grant,
  group.user_membership.add, application.user_membership.add, system.api_token.create,
  policy.rule.update); app.oauth2.token.grant.access_token and app.oauth2.as.token.grant (the
  bulk of a real log); a SystemPrincipal actor for system events.
- **aws_cloudtrail**: read-only bulk (DescribeInstances, ListBuckets, GetCallerIdentity);
  AccessDenied variants; StopLogging/DeleteTrail/UpdateTrail, PutEventSelectors,
  DeleteFlowLogs; AttachUserPolicy/PutUserPolicy/AddUserToGroup; CreateLoginProfile/
  UpdateLoginProfile, DeactivateMFADevice, UpdateAccountPasswordPolicy; PutBucketAcl/
  PutBucketPublicAccessBlock/DeleteBucketPolicy; S3 data events (GetObject/PutObject,
  eventCategory Data); ModifySnapshotAttribute, CreateSnapshot, ModifyInstanceAttribute
  (userData), SendCommand, GetPasswordData, CreateKeyPair; UpdateFunctionCode/
  CreateFunction; DisableKey/ScheduleKeyDeletion; ConsoleLogin by Root with MFA, SwitchRole,
  AssumeRoleWithSAML/WebIdentity; CreateSecurityGroup; failed ConsoleLogin with userName
  HIDDEN_DUE_TO_SECURITY_REASONS.
- **aws_guardduty**: the IAM anomaly family (CredentialAccess, Persistence,
  PrivilegeEscalation, Discovery, Exfiltration, Impact:IAMUser/AnomalousBehavior);
  Stealth:IAMUser/CloudTrailLoggingDisabled; Policy:IAMUser/RootCredentialUsage;
  UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS, MaliciousIPCaller,
  TorIPCaller; PenTest:IAMUser/KaliLinux; S3 (Policy:S3/BucketPublicAccessGranted,
  Exfiltration:S3/MaliciousIPCaller, Discovery:S3/MaliciousIPCaller); EKS
  (Policy:Kubernetes/AnonymousAccessGranted, Execution:Kubernetes/ExecInKubeSystemPod,
  Discovery:Kubernetes/SuccessfulAnonymousAccess); Runtime
  (Execution:Runtime/NewBinaryExecuted, CryptoCurrency:Runtime/BitcoinTool.B!DNS); Malware
  Protection (Execution:EC2/MaliciousFile); more EC2 (Recon:EC2/Portscan,
  UnauthorizedAccess:EC2/RDPBruteForce, Trojan:EC2/DNSDataExfiltration,
  UnauthorizedAccess:EC2/TorClient, Backdoor:EC2/DenialOfService.Tcp,
  UnauthorizedAccess:EC2/MetadataDNSRebind); a Critical attack sequence
  (AttackSequence:IAM/CompromisedCredentials).
- **aws_vpcflow**: custom (v5) records with vpc-id, subnet-id, instance-id, tcp-flags, type,
  pkt-srcaddr, pkt-dstaddr, region, az-id, flow-direction, traffic-path (what new
  deployments log and report-vpcflowlogs-custom parses); port scan bursts; IPv6; traffic to
  AWS service ranges; beaconing to one external IP over many flows.
- **aws_alb**: 4xx (404, 403 from WAF with actions_executed "waf", 401); 301/302 with
  actions_executed "redirect" and redirect_url; fixed-response; h2 and grpcs; 460/463/464;
  504 with times -1; authenticate action with error_reason; desync classification
  Ambiguous/Severe; Lambda targets; POST with large received_bytes; query strings; scanner
  user agents and paths (/.env, /wp-login.php, /admin, sqlmap, python-requests); request
  bursts from one client.
- **azure_activity**: Failure records (Failed.Forbidden, Failed.Conflict);
  roleAssignments/delete, roleDefinitions/write; policyAssignments/write,
  policyExemptions/write; virtualMachines/runCommand/action and extensions/write (the common
  execution path); networkSecurityGroups/write, publicIPAddresses/write;
  storageAccounts/listKeys/action (very frequent) and storageAccounts/write with
  allowBlobPublicAccess; Microsoft.Insights/diagnosticSettings/delete and
  Microsoft.Security/pricings/write (defense evasion); Microsoft.Resources/deployments/write;
  userAssignedIdentities/write; disks/beginGetAccess/action; automation runbooks/write; the
  other categories sharing the sourcetype (Security, Policy, ServiceHealth, Alert, Autoscale).
- **azure_ad_signin**: legacy auth (IMAP, SMTP, Authenticated SMTP, Exchange Online
  PowerShell); password spray shape (one IP, many users, 50126 bursts) and brute force (one
  user, many IPs); 500121 MFA denied, 50158, 50140, 53000/53001, 70044, 50097, 530032; guest
  sign-ins (#EXT#); non-interactive token refresh sharing a correlationId; managed identity
  sign-ins; Temporary Access Pass and FIDO2; anonymizer/Tor sign-ins with
  riskEventTypes_v2; unlikelyTravel pairs minutes apart; riskState remediated and
  confirmedCompromised updates.
- **o365_audit**: UserLoginFailed; Exchange admin cmdlets (Set-Mailbox ForwardingSmtpAddress,
  New-InboxRule/Set-InboxRule with ForwardTo or DeleteMessage, Add-MailboxPermission,
  New-TransportRule, Set-CASMailbox, Add-MailboxFolderPermission); Exchange item ops (Send,
  SendAs, SendOnBehalf, MoveToDeletedItems, HardDelete, SoftDelete, Update, MailboxLogin);
  AAD admin records (RecordType 8: "Add user.", "Update user.", "Add member to role.", "Add
  service principal.", "Add app role assignment grant to user.", "Consent to application.",
  "Update application - Certificates and secrets management", "Reset user password.",
  "Disable Strong Authentication.", "Add member to group."); SharePoint sharing (SharingSet,
  AnonymousLinkCreated, SharingInvitationCreated, AddedToSecureLink, FileDownloaded,
  FileSyncDownloadedFull, FileUploaded, FileRenamed, FileMoved, FileRecycled, FolderCreated,
  PageViewed, SearchQueryPerformed); DLP (DlpRuleMatch, RecordType 11 and 13); Security and
  Compliance alerts (AlertTriggered, RecordType 40); Teams (MemberAdded, MemberRoleChanged,
  TeamSettingChanged, AppInstalled, ChannelAdded, BotAddedToTeam); Power Platform and Copilot
  interaction records.
- **kubernetes_audit**: 403 Forbidden and 401 anonymous; list secrets cluster-wide;
  serviceaccounts/token create; aws-auth configmap patch in kube-system; clusterrolebinding
  of cluster-admin to a service account; pods/portforward and pods/attach; daemonset or pod
  create with hostPath or privileged; pod create in kube-system; nodes/proxy;
  deletecollection; impersonation (impersonatedUser); node identities (system:node:...,
  groups system:nodes); patch verbs; selfsubjectaccessreviews and selfsubjectrulesreviews
  (recon); non-resource requests (/version, /api, /healthz by scanners);
  certificatesigningrequests/approval; validatingwebhookconfigurations create; the EKS
  system users eks:node-manager and eks:addon-manager.
- **zeek**: weird.log, dpd.log, software.log, x509.log, ssh.log (auth_success,
  auth_attempts, banners), smtp.log, dhcp.log, kerberos.log and ntlm.log (Windows auth on the
  wire), smb_files.log and smb_mapping.log, rdp.log, known_hosts and known_services,
  capture_loss.log and stats.log (sensor health); dns.log with NXDOMAIN bursts and long TXT
  names (the tunneling story belongs here, not in an invented notice); long-lived conn
  entries and tunnel_parents.
- **suricata**: `stats` events (every 8 s; the first thing a SOC dashboards); `drop` events
  and `action: blocked` only in IPS mode; ssh, smtp/email, anomaly, dhcp, snmp, ftp, smb,
  krb5, rdp, quic event types; tls with ja4 (7.0.6+); alerts carrying payload_printable for a
  few signatures; a realistic ratio (flow and dns hundreds per alert).
- **webserver**: apache:error lines (the TA has a full stanza); a vhost/combined variant with
  `%v` and `%D` (sourcetype apache:access, which gives dest, bytes_in/out and response_time
  to CIM Web); burst patterns (a 4xx scan from one client, credential stuffing on /login, a
  bot crawl of robots.txt and sitemap.xml).
- **linux_auditbeat / linux_auditd**: USER_AUTH, USER_ACCT, CRED_ACQ/CRED_DISP,
  USER_START/USER_END, USER_CMD (sudo), USER_LOGIN failures with `acct="(invalid user)"`;
  ADD_USER, USER_MGMT, USER_CHAUTHTOK, ADD_GROUP, DEL_USER; changed-identity-of (setuid),
  changed-file-permissions-of, changed-file-ownership-of, loaded-kernel-module,
  changed-audit-configuration, changed-system-time, mounted; connected-to, bound-socket,
  listen-for-connections, accepted-connection-from; ANOM_LOGIN_FAILURES, ANOM_ABEND,
  ANOM_PROMISCUOUS; system module process dataset (process_started, process_stopped,
  existing_process); host and user state snapshots; file_integrity moved and config_change.
- **vmware_vcenter**: UserLogoutSessionEvent, BadUsernameSessionEvent, NoAccessUserEvent,
  SessionTerminatedEvent, AlreadyAuthenticatedSessionEvent; VmReconfiguredEvent (configSpec
  summary), VmRemovedEvent, VmClonedEvent, VmDeployedEvent, VmSuspendedEvent,
  VmResettingEvent, VmGuestShutdownEvent, VmGuestRebootEvent, VmRenamedEvent,
  VmRelocatedEvent, DrsVmMigratedEvent; snapshots as TaskEvent (createSnapshot,
  removeSnapshot) and VmBeingCreatedEvent; VmAcquiredTicketEvent, VmAcquiredMksTicketEvent,
  VmRemoteConsoleConnectedEvent; PermissionAdded/Updated/RemovedEvent, RoleAdded/UpdatedEvent,
  UserAssignedToGroup; HostConnectionLostEvent, HostConnected/DisconnectedEvent,
  EnteringMaintenanceModeEvent, HostAdded/Removed/ShutdownEvent; AlarmAcknowledgedEvent,
  AlarmClearedEvent, AlarmCreatedEvent, AlarmEmailCompletedEvent; EventEx and ExtendedEvent
  with eventTypeId (com.vmware.vc.HA.*, vim.event.esx.audit.*), ScheduledTaskCompletedEvent,
  GeneralUserEvent.
- **metrics_***: process-level metrics (process.cpu.percent, process.memory.rss with a
  process_name dimension) and container metrics (container.cpu.percent,
  container.memory.usage with container_id, pod, namespace); cumulative counters (`*.total`)
  monotonic per host across events rather than fresh randoms. A collectd or telegraf shaped
  alternative is not needed; the HEC metric JSON is what OpenTelemetry and the Splunk OTel
  collector send.

### 7.2 New sources

Datasets commonly fed to a SIEM that the generator lacks, roughly in priority order, with the
Splunk add-on and sourcetype that would parse each. Sourcetypes are the add-ons' documented
ones; a few community add-ons are marked as such.

| source | why a SOC wants it | Splunk add-on | sourcetype |
|---|---|---|---|
| Windows DNS Server debug log (replaces dns_query) | Query logs from the resolver every domain-joined host uses; DGA, tunneling, sinkhole hits, Network_Resolution | Splunk Add-on for Microsoft Windows (installed) | MSAD:NT6:DNS (debug log) or msdns:analytical (ETW channel) |
| BIND query log | The Linux resolver equivalent, with RPZ rewrites | Splunk Add-on for ISC BIND (2876) | isc:bind:query |
| Linux auditd raw text | Native Linux audit records (execve, USER_AUTH, USER_CMD, ADD_USER); what the Unix TA and most Linux detections expect | Splunk Add-on for Unix and Linux (installed) | linux_audit |
| Linux syslog auth (sshd, sudo, /var/log/secure) | SSH brute force, sudo use, su, PAM failures; the simplest Linux authentication feed | Splunk Add-on for Unix and Linux (installed) | linux_secure |
| Fortinet FortiGate | The most widely deployed firewall after PAN and Cisco; traffic, utm, event logs in key=value syslog | Fortinet FortiGate Add-On for Splunk (2846) | fgt_log (fgt_traffic, fgt_utm, fgt_event) |
| Check Point | Enterprise firewall with its own Log Exporter format | Splunk Add-on for Check Point Log Exporter (4293) | cp_log |
| Cisco IOS / NX-OS syslog | Switch and router events: interface flaps, config changes, login failures, ACL hits | Cisco Networks Add-on (1467) | cisco:ios |
| Cisco Meraki | Cloud-managed firewall, AP and switch events; common in branch offices | Cisco Meraki Add-on for Splunk (5580) | meraki (meraki:securityappliances, meraki:accesspoints) |
| Cisco ISE | NAC: RADIUS authentications, 802.1X failures, posture, TACACS admin sessions | Splunk Add-on for Cisco ISE (1915) | cisco:ise:syslog |
| Cisco Umbrella DNS | Cloud DNS security: blocked categories and threat domains per identity | Cisco Cloud Security add-on (5558) | cisco:umbrella:dns |
| Zscaler ZIA and ZPA | Web proxy and zero-trust access logs: URL categories, DLP, app access, user and device | Zscaler Technical Add-On (3865) | zscalernss-web, zscalernss-fw, zscalerlss-zpa-app, zscalerlss-zpa-auth |
| Proofpoint TAP | Email threat detections: clicks on malicious URLs, blocked and delivered messages | Proofpoint TAP Modular Input (3080) | proofpoint_tap_siem (clicks_blocked, clicks_permitted, messages_blocked, messages_delivered) |
| Exchange message tracking | On-prem mail flow: sender, recipient, subject, message id; phishing and forwarding investigations | Splunk Add-on for Microsoft Exchange (3225) | MSExchange:2013:MessageTracking |
| Mail gateway (Cisco ESA) | Perimeter mail: spam and malware verdicts, attachments, DKIM/SPF results | Splunk Add-on for Cisco ESA (1761) | cisco:esa:textmail |
| Microsoft Entra ID audit log (not just sign-in) | Directory changes: user and group changes, role assignments, app consent, MFA resets | Splunk Add-on for Microsoft Azure (installed) | azure:aad:audit |
| Azure NSG flow logs | Azure network flows, the VPC flow equivalent | Splunk Add-on for Microsoft Cloud Services (installed) | mscs:nsg:flow |
| GCP audit logs and VPC flow | Admin Activity and Data Access audit, plus VPC flow, for the third cloud | Splunk Add-on for Google Cloud Platform (3088) | google:gcp:pubsub:audit:admin_activity, google:gcp:pubsub:audit:data_access, google:gcp:compute:vpc_flows |
| AWS S3 server access logs | Bucket access by requester, operation and key; exfiltration and public access | Splunk Add-on for AWS (installed) | aws:s3:accesslogs |
| AWS Route 53 resolver query logs | DNS queries from every VPC; the cloud resolver feed | Splunk Add-on for AWS (installed) | aws:route53 |
| AWS WAF | Web ACL allow and block with rule, URI and client; pairs with the ALB source | Splunk Add-on for AWS (installed) | aws:waf |
| AWS Config and Security Hub | Resource configuration changes and compliance findings; posture detections | Splunk Add-on for AWS (installed) | aws:config, aws:config:notification, aws:securityhub:finding |
| Duo | MFA pushes, denials, fraud reports and admin changes; pairs with Okta and Entra | Duo Security Add-on for Splunk (3504) | duo:authentication, duo:administrator, duo:telephony |
| Ping (PingFederate) | SSO audit log for shops that are not on Okta | PingFederate Add-on for Splunk (Ping Identity) | pingfederate:audit |
| CrowdStrike FDR (own source) | Sensor telemetry (ProcessRollup2, NetworkConnectIP4, DnsRequest, UserLogon); two to three orders of magnitude above the stream | Splunk Add-on for CrowdStrike FDR (5579) | crowdstrike:events:sensor |
| SentinelOne | The other major EDR: threats, activities, agent telemetry | SentinelOne App for Splunk (5433) | sentinelone:channel:threats, sentinelone:channel:activities |
| Carbon Black | VMware Carbon Black Cloud alerts and endpoint events | VMware Carbon Black Cloud Add-on (5332) | vmware:cbc:s3:alerts, vmware:cbc:s3:endpoint.event |
| Microsoft Defender AlertInfo and Evidence (Event Hub shape) | The alert tables as streamed, joined on AlertId; incidents and XDR | Splunk Add-on for Microsoft Security (installed) | ms:defender:eventhub (category AdvancedHunting-AlertInfo, AdvancedHunting-AlertEvidence) or ms:defender:atp:alerts |
| Windows PowerShell 4104 and WMI | Script block logging and WMI-Activity (5857 to 5861); the two most used execution channels | Splunk Add-on for Microsoft Windows (installed) | XmlWinEventLog, source XmlWinEventLog:Microsoft-Windows-PowerShell/Operational and XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational |
| Linux Sysmon | Sysmon for Linux process, network and file events in XML | Splunk Add-on for Sysmon for Linux (installed) | sysmon:linux |
| IIS access | Windows web server logs (W3C), the IIS equivalent of the Apache source | Splunk Add-on for Microsoft IIS (3185) | ms:iis:auto |
| nginx access | The most common reverse proxy and web server; combined or key=value format | Splunk Add-on for NGINX (3258) | nginx:plus:access, nginx:plus:kv |
| Kubernetes container stdout | Application logs from pods, with namespace, pod and container metadata | Splunk OpenTelemetry Collector for Kubernetes (or Splunk Connect for Kubernetes) | kube:container:<name> |
| Docker container logs | Container stdout with container id and image, for non-Kubernetes hosts | Docker splunk logging driver (no TA; JSON) | docker (as set on the driver) |
| osquery | Scheduled query results and differential results (processes, listening ports, users) from the fleet | osquery Add-on for Splunk (Splunk) | osquery:results |
| DHCP (Windows and ISC) | Lease assignments tie IPs to hosts and MACs; required for IP-to-host attribution | Splunk Add-on for Microsoft Windows (installed); Splunk Add-on for ISC DHCP (2877) | DhcpSrvLog; isc:dhcp |
| VPN: Cisco AnyConnect 722xxx | Remote-access sessions: tunnel up/down, assigned address, user and group; the ASA source already parses them | Splunk Add-on for Cisco ASA (installed) | cisco:asa |
| VPN: Palo Alto GlobalProtect | Portal and gateway auth, connect, disconnect with public and private IP | Splunk Add-on for Palo Alto Networks (installed) | pan:globalprotect |
| VPN: Fortinet SSL VPN | FortiGate event logs for tunnel-up, tunnel-down, auth failures | Fortinet FortiGate Add-On (2846) | fgt_event |
| NetFlow / IPFIX | Flow records from routers and switches; east-west visibility without a sensor | Splunk Stream (stream:netflow) or Splunk Add-on for NetFlow | stream:netflow, netflow |
| Splunk internal logs | splunkd, scheduler, license, web access: the SOC watches its own pipeline | built in | splunkd, splunkd_access, scheduler, splunk_web_access |
| Cribl internal logs | Pipeline health, drops, destination errors for Cribl Stream shops | Cribl App for Splunk | cribl |
| GitHub audit log | Org and repo events: member changes, secrets, branch protection, token creation | GitHub Audit Log Monitoring Add-On (5595) | github:cloud:audit, github:enterprise:audit |
| HashiCorp Vault audit | Secret reads, token creation, policy changes | Vault Splunk App (HashiCorp) | hashicorp_vault_audit_log |
| 1Password audit | Sign-in attempts, item usage, vault and group changes | 1Password Events Reporting for Splunk (5632) | 1password:signinattempts, 1password:itemusages, 1password:auditevents |
| ServiceNow audit | Ticket and CMDB changes, admin actions; sys_audit | Splunk Add-on for ServiceNow (1928) | snow:sys_audit, snow:incident |
| Jira audit | Project, permission and user changes in Jira Cloud | community add-ons (JSON, KV_MODE=json) | jira:cloud:audit |
| Salesforce event monitoring | Login history, report exports, API usage, setup audit trail | Splunk Add-on for Salesforce (3549) | sfdc:logfile, sfdc:loginhistory, sfdc:setupaudittrail |
| Snowflake login history | Warehouse logins by user, client and IP; data platform access | Snowflake Add-on for Splunk (community) | snowflake:login_history |
| Honeypot (Cowrie or OpenCanary) | Any touch is a signal: SSH and telnet sessions, commands, credentials tried | Cowrie Splunk output (no TA; JSON) | cowrie (or opencanary) |

## 8. Appendix

### 8.1 Reusable Splunk searches per source

`~/tmp/msn-flow/splunk-search.sh '<spl>' [earliest]` runs a search on the mn1 search head
(default earliest -24h; the data is from 2026-11-14 09:05 to 09:35 UTC). verify.sh and
verify2.sh run all of them and print the SPL before each result.

```
# everything
index=noise_* | stats count by index sourcetype source

# aws_alb (expect nothing but tag/eventtype)
index=noise_network sourcetype=aws:elb:accesslogs | stats count by elb_status_code
index=noise_network sourcetype=aws:elb:accesslogs | head 1 | table _raw

# aws_cloudtrail
index=noise_cloud sourcetype=aws:cloudtrail | stats count by eventName
# aws_guardduty
index=noise_cloud sourcetype=aws:cloudwatch:guardduty | stats count by type severity
# aws_vpcflow
index=noise_network sourcetype=aws:cloudwatchlogs:vpcflow | stats count by action protocol
# azure_activity
index=noise_cloud sourcetype=azure:monitor:activity | stats count by operationName
# azure_ad_signin
index=noise_cloud sourcetype=azure:aad:signin | stats count by status.errorCode appDisplayName
# cisco_asa
index=noise_network sourcetype=cisco:asa | stats count by message_id
index=noise_network sourcetype=cisco:asa | stats count by action src dest
# cisco_firepower
index=noise_network sourcetype=cisco:ftd:syslog | stats count by event_type dst_ip action
# crowdstrike
index=noise_endpoint sourcetype=CrowdStrike:Event:Streams:JSON | stats count by metadata.eventType
# dns_query
index=noise_network sourcetype=msn:dns:query | stats count by query_type
# kubernetes_audit
index=noise_cloud sourcetype=msn:kubernetes:audit | stats count by verb stage
# linux_auditbeat
index=noise_linux sourcetype=msn:linux:auditbeat | stats count by event.action
# metrics_* as events
index=noise_app sourcetype=msn:metrics:* | stats count by sourcetype
index=noise_app sourcetype=msn:metrics:system | spath path={}.fields.metric_name output=m | stats dc(m) as metric_names count
# metrics in the metrics index (the unwrapped sample only)
| mcatalog values(metric_name) as metric_name WHERE index=noise_metrics by sourcetype
| mstats avg(cpu.percent) as cpu_avg count WHERE index=noise_metrics sourcetype=msn:metrics:system by host
# microsoft_ad and windows_security (same source)
index=noise_windows sourcetype=XmlWinEventLog source=XmlWinEventLog:Security | stats count by EventCode Computer
index=noise_windows sourcetype=XmlWinEventLog source=XmlWinEventLog:Security | stats count(TargetUserName) as TargetUserName count(LogonType) as LogonType count(user) as user count
# microsoft_defender
index=noise_endpoint sourcetype=m365:defender:incident:advanced_hunting | stats count by ActionType
# o365_audit
index=noise_cloud sourcetype=o365:management:activity | stats count by Operation Workload
# okta
index=noise_identity sourcetype=OktaIM2:log | stats count by eventType
index=noise_identity sourcetype=OktaIM2:log | stats count by user action
# paloalto
index=noise_network sourcetype=pan:traffic | stats count by action
index=noise_network sourcetype=pan:traffic | stats count by log_subtype src_ip dest_ip
index=noise_network sourcetype=pan:threat | stats count by log_subtype threat_name action
index=noise_network sourcetype=pan:threat | head 1 | table _raw
# suricata
index=noise_network sourcetype=suricata | stats count by event_type
# vmware_vcenter
index=noise_cloud sourcetype=msn:vmware:vcenter | stats count by eventType
# webserver
index=noise_network sourcetype=apache:access:combined | stats count by status
index=noise_network sourcetype=apache:access:combined | stats count by http_method uri_path
# windows_sysmon
index=noise_windows sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by EventCode
index=noise_windows sourcetype=XmlWinEventLog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count(Image) as Image count(CommandLine) as CommandLine count(process_name) as process_name count
# zeek
index=noise_network sourcetype=bro:conn:json | stats count by id.orig_h
index=noise_network sourcetype=bro:dns:json | stats count by query
index=noise_network sourcetype=bro:*:json | stats count(src) as src count(dest) as dest count(uid) as uid count by sourcetype
# CIM readiness without Splunk_SA_CIM
index=noise_* tag=* | stats values(tag) as tags count by sourcetype

# Windows quote proof (search-time only; re-parses stored events with single quotes)
index=noise_windows source=XmlWinEventLog:Security EventCode IN (4624,4625,4728) | head 30
| rex field=_raw mode=sed "s/\"/'/g" | extract reload=true
| stats count(TargetUserName) count(LogonType) count(IpAddress) count(Logon_Type) count(SubjectUserName) count by EventCode
```

### 8.2 Files the review was built from

All under `~/tmp/msn-flow/` on the operator host:

- `flow.md`: how the send ran, per-source counts, extraction summary, searches, problems hit.
- `tas.md` and `sourcetypes.json`: add-on staging decisions and the source to sourcetype,
  index, source and by_template map.
- `sender.md`: how the backend sets sourcetype, index, host and source; send.py; proofs.
- `build.md`: the mn1 stack build.
- `SME-BRIEF.md`: the reviewers' rules and verdict scale.
- `sme-firewall.md`: cisco_asa, cisco_firepower, paloalto.
- `sme-windows.md` (and `sme-windows-proof.log`): windows_security, microsoft_ad,
  windows_sysmon, microsoft_defender.
- `sme-cloud.md`: aws_cloudtrail, aws_guardduty, aws_vpcflow, aws_alb, azure_activity,
  azure_ad_signin, o365_audit, kubernetes_audit.
- `sme-identity-endpoint.md`: okta, crowdstrike.
- `sme-network.md`: zeek, suricata, dns_query, webserver.
- `sme-linux-infra.md`: linux_auditbeat, vmware_vcenter, metrics_*.
- `samples/<source>.jsonl|.log`: 20 raw events per source as generated.
- `conf/<app>/default/`: props and transforms of the installed add-ons.
- `send-report-20261114-040558.json`, `send-real.log`, `verify.log`, `verify2.log`: the
  run's counters and search output.
