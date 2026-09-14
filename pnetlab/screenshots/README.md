# Screenshot Evidence

This folder contains the evidence images already available from the live PNETLab build and validation sessions. Missing evidence is intentionally left as a placeholder rather than represented as completed.

## Included

| File | Evidence |
|---|---|
| `topology.jpeg` | Final PNETLab NIDS topology |
| `ovs-mirror.jpeg` | `ovs-vsctl show` and `ovs-vsctl list Mirror` verification |
| `sniffer-bruteforce-portscan.jpeg` | IDS sniffer showing BruteForce and PortScan alerts and packet counter |
| `webattack-bot-traffic.jpeg` | Kali terminal showing repeated HTTP test traffic and long repeated TCP payload test |
| `bot-server-listener.jpeg` | WEB-SRV01 receiving the long repeated TCP payload on port 9001 |
| `bot-no-alert.jpeg` | IDS packet counter increasing without a Bot alert |

## Placeholders / To Add Later

- `dos-alert.<png|jpeg>` — clear DoS alert/dashboard evidence.
- `ddos-not-detected.<png|jpeg>` — dashboard or sniffer evidence showing the three-source test without a DDoS label.
- `infiltration-alert.<png|jpeg>` — clear Infiltration alert/dashboard evidence.
- `benign-no-alert.<png|jpeg>` — optional benign validation evidence.
- `dashboard-overview.<png|jpeg>` — clean final dashboard overview.
- `webattack-no-alert.<png|jpeg>` — optional dashboard evidence after the WebAttack test.

When a placeholder screenshot is added, update the relevant section of `docs/TESTING.md` to embed it.
