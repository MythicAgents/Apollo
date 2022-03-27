function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "Status", "type": "string", "cellStyle": {}, "width": 80},
            {"plaintext": "Name", "type": "string", "cellStyle": {}, "width": 200},
            {"plaintext": "IPv4", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "DNS", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "Gateway", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "IPv6", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "More Info", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
        ];

        try {
            data = JSON.parse(responses[0]);
        } catch (error) {
            console.log(error);
            const combined = responses.reduce((prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
        for(let j = 0; j < data.length; j++){
            let moreInfo = "";
            let nic = data[j];

            moreInfo = nic["Description"]
            moreInfo += `\n   Adapter Name ............................ : ${nic["AdapterName"]}\n`;
            moreInfo += `   Adapter ID .............................. : ${nic["AdapterId"]}\n`;
            moreInfo += `   Adapter Status .......................... : ${nic["Status"]}\n`;

            for(let i = 0; i < nic["AdressesV4"].length; i++){
                moreInfo += `   Unicast Address ......................... : ${nic["AdressesV4"][i]}\n`;
            }
            for(let i = 0; i < nic["AdressesV6"].length; i++){
                moreInfo += `   Unicast Address ......................... : ${nic["AdressesV6"][i]}\n`;
            }
            for(let i = 0; i < nic["DnsServers"].length; i++){
                moreInfo += `   DNS Servers ............................. : ${nic["DnsServers"][i]}\n`;
            }
            for(let i = 0; i < nic["Gateways"].length; i++){
                moreInfo += `   Gateway Address ......................... : ${nic["Gateways"][i]}\n`;
            }
            for(let i = 0; i < nic["DhcpAddresses"].length; i++){
                moreInfo += `   Dhcp Server ............................. : ${nic["DhcpAddresses"][i]}\n`;
            }
            moreInfo += `   DNS suffix .............................. : ${nic["DnsSuffix"]}\n`;
            moreInfo += `   DNS enabled ............................. : ${nic["DnsEnabled"]}\n`;
            moreInfo += `   Dynamically configured DNS .............. : ${nic["DynamicDnsEnabled"]}\n`;

            let backgroundColor = "";
            let rowStyle = {};
            let row = {
                "rowStyle": rowStyle,
                "Name": {"plaintext": nic["AdapterName"], "cellStyle": {}},
                "IPv4": {"plaintext": nic["AdressesV4"].toString(), "cellStyle": {}},
                "IPv6": {"plaintext": nic["AdressesV6"].toString(), "cellStyle": {}},
                "DNS": {"plaintext": nic["DnsServers"].toString(), "cellStyle": {}},
                "Gateway": {"plaintext": nic["Gateways"].toString(), "cellStyle": {}},
                "Status": {"plaintext": nic["Status"], "cellStyle": {}},

                "More Info": {
                    "button": {
                        "name": "Expand",
                        "type": "string",
                        "value": moreInfo,
                        "title": nic["Description"],
                        "hoverText": "View additional attributes"
                    }
                }
            };

            rows.push(row);
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "IP Configuration"
        }]};


    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}