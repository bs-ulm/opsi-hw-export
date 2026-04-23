# Schmierzettel 

übergebliebene Skript Schnipsel zum sortieren

```
# folgendes Skript (jq) exportiert Processor Info mit vorangestellter Dateinamen
for f in *.txt; do echo -n "$f"; jq --arg file "$f" ".PROCESSOR[0].name"  "$f"; done
opsi-cli jsonrpc execute host_getObjects [] {}

# Prozessor: 
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": ""$HOST_ID"l"}' | jq '.[] | select(.hardwareClass == "PROCESSOR") | .name' 

# TPM : 
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '.[] | select(.hardwareClass == "TPM") | .name'

# RAM (zusammengerechnet)
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "MEMORY_MODULE") | .capacity ] | add  opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "MEMORY_MODULE") | .capacity ] | add  '

# HDD
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "HARDDISK_DRIVE") | .size ] | add'

Prozessor: 
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": ""$HOST_ID"l"}' | jq '.[] | select(.hardwareClass == "PROCESSOR") | .name' 

TPM: 
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '.[] | select(.hardwareClass == "TPM") | .name' 

RAM (zusammengerechnet)
 opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "MEMORY_MODULE") | .capacity ] | add  opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "MEMORY_MODULE") | .capacity ] | add  '

HDD
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}' | jq '[.[] | select(.hardwareClass == "HARDDISK_DRIVE") | .size ] | add'

Windows: 
 opsi-cli jsonrpc execute auditSoftwareOnClient_getObjects '[]' '{"clientId": "nb2024-32.paedml-linux.lokal"}' | jq '.[] | select(.name | test("^Windows [0-9]") ) | .name '

opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}'
opsi-cli jsonrpc execute method auditHardwareOnHost_getObjects [] {"hostId": \"$id \"

opsi-cli client-action --clients=all set-action-request --products=hwaudit,swaudit

HW=$(opsi-admin -d method getHardwareInformation_hash $HOST_ID) 

cat hw.txt | jq " .PROCESSOR[0].name "
cat hw.txt | jq " .TPM[0].version "
 cat hw.txt | jq " [ .MEMORY_MODULE[] | .capacity ] | add / 1024 / 1024 / 1024"

cat hw.txt | jq " [ .HARDDISK_DRIVE[] | .size ] | add / 1024 / 1024 / 1024""

Windows: 
 opsi-cli jsonrpc execute auditSoftwareOnClient_getObjects '[]' '{"clientId": "nb2024-32.paedml-linux.lokal"}' | jq '.[] | select(.name | test("^Windows [0-9]") ) | .name '
opsi-cli jsonrpc execute auditHardwareOnHost_getObjects '[]' '{"hostId": "nb2024-32.paedml-linux.lokal"}'
opsi-cli jsonrpc execute method auditHardwareOnHost_getObjects [] {"hostId": \"$id \"

opsi-cli client-action --clients=all set-action-request --products=hwaudit,swaudit

HW=$(opsi-admin -d method getHardwareInformation_hash $HOST_ID) 
cat hw.txt | jq " .PROCESSOR[0].name "
cat hw.txt | jq " .TPM[0].version "
 cat hw.txt | jq " [ .MEMORY_MODULE[] | .capacity ] | add / 1024 / 1024 / 1024"


cat hw.txt | jq " [ .HARDDISK_DRIVE[] | .size ] | add / 1024 / 1024 / 1024""
 ``` 
