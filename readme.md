#### Deploy-Leak-Stack.sh

## Build A Full Leak Stack

**Installation**

curl -LO https://raw.githubusercontent.com/Arkinats/deploy-leak/main/deploy-leak-stack.sh

chmod +x deploy-leak-stack.sh

sudo ./deploy-leak-stack.sh

**Requirements**
- Rocky Linux 9.x
- Internet Access
- At least 2 NIC interfaces

## After Install Manual Configuration Requirements
**Create a Data View in Kibana**

ES has the data, but Kibana doesn't display indices it doesn't have a Data View (formerly "index pattern") for. To make zeek-* searchable through Kibana's Discover UI:

- Log into Kibana → ☰ → Stack Management → Kibana → Data Views.
- Click Create data view.
- Set:
  - Name: Zeek Logs
  - Index pattern: zeek-*
  - Timestamp field: @timestamp
- Save.

Then go to ☰ → Discover, pick the Zeek Logs data view from the dropdown, and you'll see events. 
Same flow for logstash-* (everything else from the Logstash pipeline) and arkime_sessions3-* (Arkime's session indices) and syslog-* if you have any syslog sources.
