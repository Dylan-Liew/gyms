## SNMP — 161/UDP

```bash
# Discover the SNMP community string.
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt "$IP" | tee snmp-community.txt
# Query basic system information.
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.1 | tee snmp-system.txt
# Walk every accessible SNMP object efficiently.
snmpbulkwalk -v2c -c public "$IP" | tee snmp-all.txt
# Enumerate NET-SNMP extended commands.
snmpwalk -v2c -c public "$IP" NET-SNMP-EXTEND-MIB::nsExtendObjects | tee snmp-extend.txt
# Enumerate SNMP system, interface, and process data.
sudo nmap -sU -p161 --script snmp-info,snmp-interfaces,snmp-processes "$IP" -oN snmp.txt
```

```text
192.168.50.20 [public] Linux web01 5.15.0-91-generic
```
