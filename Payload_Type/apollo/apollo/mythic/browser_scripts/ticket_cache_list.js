function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => {
            return prev + cur;
        }, "");
        return { 'plaintext': combined };
    }
    let currentLUID = "";
    if (responses.length > 0) {
        let rows = [];
        let data = [];

        let headers = [
            { "plaintext": "action", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true },
            { "plaintext": "client", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "service", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "luid", "type": "string", "cellStyle": {}, width: 110 },
            { "plaintext": "end", "type": "string", "cellStyle": {}, width: 170 },
        ];
        for (let i = 0; i < responses.length; i++) {
            try {
                data = JSON.parse(responses[i]);
            } catch (error) {
                console.log(error);
                const combined = responses.reduce((prev, cur) => {
                    return prev + cur;
                }, "");
                return { 'plaintext': combined };
            }
            for (let j = 0; j < data.length; j++) {
                let jinfo = data[j];
                if(currentLUID === "" && jinfo["current_luid"]){
                    currentLUID = jinfo["current_luid"];
                }
                let row = {
                    "action": {
                        "button": {
                            "name": "Action",
                            "type": "menu",
                            value: [
                                {
                                    name: "extract",
                                    type: "task",
                                    ui_feature: "apollo:ticket_cache_extract",
                                    parameters: {service: jinfo["service_name"], luid: jinfo["luid"]}
                                },
                                {
                                    name: "purge",
                                    type: "task",
                                    ui_feature: "apollo:ticket_cache_purge",
                                    getConfirmation: true,
                                    parameters: {serviceName: jinfo["service_name"] + "@" + jinfo["service_realm"], luid: jinfo["luid"]}
                                }
                            ]
                        }
                    },
                    "client": { "plaintext": jinfo["client_name"] + "@" + jinfo["client_realm"], "cellStyle": {}, copyIcon: true },
                    "service": { "plaintext": jinfo["service_name"] + "@" + jinfo["service_realm"], "cellStyle": {}, copyIcon: true },
                    "luid": { "plaintext": jinfo["luid"], "cellStyle": {} },
                    "end": { "plaintext": jinfo["end_time"], "cellStyle": {} },
                    "rowStyle": {backgroundColor: jinfo["luid"] === jinfo["current_luid"] ? "#7fce70": ""}
                };
                rows.push(row);
            }
            rows.push({
                action: {
                    button: {
                        name: "add",
                        startIcon: "add",
                        startIconColor: "success",
                        type: "task",
                        openDialog: true,
                        ui_feature: "apollo:ticket_cache_add",
                    }
                },
                client: {plaintext: ""},
                service: {plaintext: ""},
                luid: {plaintext: ""},
                end: {plaintext: ""}
            })
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Cached Kerberos Tickets" + (currentLUID !== "" ? ": current LUID: " + currentLUID : ""),
            }]
        };
    }

    // this means we shouldn't have any output
    return { "plaintext": "Not response yet from agent..." }

}
