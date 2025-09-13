#!/bin/bash

# Interface to listen on
INTERFACE="wlp1s0"

echo "[*] Listening for DHCP requests on $INTERFACE..."
echo "[*] Press Ctrl+C to stop."

# Run tcpdump and filter for DHCP Request lines
tcpdump -i "$INTERFACE" port 67 -l -nn -vvv 2>/dev/null | \
awk '
BEGIN {
    mac = "";
    xid = "";
    collecting = 0;
}
/Request from/ {
    # Extract MAC address
    printf "match mac\n";
    match($0, /Request from ([0-9a-f:]{17})/, m);
    if (m[1] != "") {
        mac = m[1];
        collecting = 1;
    }
}
/xid/ && collecting {
    printf "match xid\n";
    match($0, /xid 0x([0-9a-f]{8})/, m)
    if (m[1] != "") {
        xid = m[1];
        printf "[+] MAC: %s | XID: 0x%s\n", mac, xid;
        system("./send-offer " mac " " xid);
        collecting = 0;
    }
}'

