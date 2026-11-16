# Week 1 - Documentation Log

## Step 1: Lab Preparation
- Date: 6 Nov 2026
- Goal: Check host machine can run the SIEM lab
- What I did: Checked specs using Task Manager
- Result: i7-6820HQ, 4 cores/8 threads, 15.9 GB RAM, SSD, Virtualization Enabled
- Screenshot name: 01_system_specs.png
- Problems & how I solved them: None. RAM is limited, so lab will use a lightweight design.

## Step 2: Software Download
- Date:
- Goal: Download virtualization software and VM images
- What I did: Downloaded VirtualBox, Wazuh OVA, Ubuntu Server ISO
- Screenshot name: 02_downloads.png
- Problems & how I solved them:

## Step 3: Wazuh Import & First Boot
- Date:
- Goal: Import Wazuh OVA and access dashboard
- What I did: Imported OVA, set 6GB RAM / 2 CPU, Bridged network, logged in
- Wazuh IP:
- Result:
- Screenshot names: 03_ova_import.png, 04_vm_settings.png, 05_ip_a.png, 06_wazuh_dashboard.png
- Problems & how I solved them:

## Step 4: Wazuh Verification
- Date: 7 Nov 2026
- Goal: Confirm Wazuh server is running and reachable
- Wazuh IP: 192.168.56.110 (Host-only), 10.0.3.15 (NAT)
- Services status: manager / indexer / dashboard = active (running)
- Result: Dashboard accessible, 0 agents registered
- Screenshot names: 05, 06, 07b, 07c, 08, 09, 10
- Problems & how I solved them: Adapter 1 was set to NAT by mistake; fixed with Adapter 1 = Host-only, Adapter 2 = NAT

## Step 5: Ubuntu Victim VM
- Date: 7 Nov 2026
- Goal: Create endpoint VM to be monitored by Wazuh
- Specs: 2GB RAM / 1 CPU / 25GB disk
- Network: Adapter 1 Host-only, Adapter 2 NAT
- Ubuntu IP (Host-only): 192.168.56.111
- Result: Ubuntu installed, ping to Wazuh (192.168.56.110) successful
- Screenshot names: 11 to 15
- Problems & how I solved them: None

## Step 6: Wazuh Agent Install
- Date: 7 Nov 2026
- Goal: Connect Ubuntu endpoint to Wazuh server
- Agent name: ubuntu-victim (ID 001)
- Manager address: 192.168.56.110
- Result: Agent active, visible in Dashboard (Ubuntu 26.04.1 LTS, v4.14.10)
- Screenshot names: 16 to 19
- Problems & how I solved them: None

## Step 7: First Logs in SIEM
- Date: 7 Nov 2026
- Goal: Verify logs reach Wazuh and inspect their structure
- Events generated: failed sudo, adduser, failed SSH (localhost), file creation
- Events seen in dashboard: 68 hits. Rules 2502, 5710, 5902, 5901, 5402, 5501/5502, 5503
- Result: Logs reach the SIEM and are decoded into fields (rule.id, rule.level, agent.name, data.srcip...)
- Screenshot names: 20, 21, 22
- Problems & how I solved them: None. FIM event not seen yet (scan is periodic).

## Step 8: Data Source Inventory & Field Mapping
- Date: 7 Nov 2026
- Goal: Document data sources and map raw logs to normalized fields
- What I did: Built field mapping for rules 5710, 5402, 2502 and a 13-source inventory
- Result: field_mapping.md and data_source_inventory.md completed
- Screenshot names: 23, 24, 25, 26
- Problems & how I solved them: Verified decoder fields in the JSON tab

## Step 9: SIEM Architecture Diagram
- Date: 7 Nov 2026
- Goal: Design SIEM architecture for a medium organization
- What I did: Drew layered architecture (sources → collection → Wazuh → analyst/SOAR)
- Result: Diagram marks what is built in the lab vs documented/planned
- Screenshot name: 27_siem_architecture_diagram.png
- Problems & how I solved them: None

## Step 10: Retention Plan
- Date: 7 Nov 2026
- Goal: Define how long each log type is kept
- What I did: Created 4-tier retention plan, per-source periods, storage estimate
- Result: retention_plan.md completed
- Screenshot name: 28_retention_plan.png
- Problems & how I solved them: None

## Step 11: Hardening & Snapshots
- Date: 7 Nov 2026
- Goal: Secure default credentials and create restore points
- What I did: Changed Wazuh OS password and Dashboard admin password, updated Filebeat keystore, verified alerts still indexed, took baseline snapshots
- Snapshot name: Week1_Clean_Baseline (Wazuh, Ubuntu-Victim)
- Result: Agent active, new alerts visible after password change
- Screenshot names: 29 to 35
- Problems & how I solved them: Dashboard password change does not update Filebeat; fixed with filebeat keystore