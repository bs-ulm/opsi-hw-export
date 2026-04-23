#!/bin/bash

# source: Source: https://forum.opsi.org/viewtopic.php?t=612

# installs jq requirement
apt update && apt install jq -y

# Export Folder
EXPORT=/tmp/HardwareInformationAllClients


# NO NEED TO EDIT ANYTHING BELOW THIS LINE
echo "##################################################"
echo "# START TO EXPORT HARDWARE INVENTORY INFORMATION #"
echo "##################################################"
echo "[INFO]    Will export the Hardwareinformation for all Clients into $EXPORT/<hostname>.txt"
# Returns all Host- and Servernames
HOSTIDS=`opsi-admin -dS method host_getIdents`
# Returns the opsi-Servername to exclude from getHardwareInforamation
SERVER=`hostname -f`
if [ -d "$EXPORT" ]; then
        echo "[WARN]    $EXPORT allready exists - will merge new information into and overwrite existing ones"
else
        mkdir $EXPORT 
fi
# for loop to export HardwareInformation for each client except the opsi-server
for i in $HOSTIDS; do
        if ! [ $i = $SERVER ]; then
                echo "[INFO]    Exporting $i"
	 opsi-cli jsonrpc execute host_getObjects [] '{"id":"$i"}' | jq ".[] > $EXPORT/$i_info.txt
                opsi-admin -d method getHardwareInformation_hash $i > $EXPORT/$i_hw.txt
        fi
done
