function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => {
            return prev + cur;
        }, "");
        return { 'plaintext': combined };
    }
    if (responses.length > 0) {
        let rows = [];
        let data = [];
        let headers = [
            { "plaintext": "action", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true },
            { "plaintext": "client", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "service", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "end", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "ticket", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                let row = {
                    "action": {
                        "button": {
                            "name": "purge",
                            startIcon: "delete",
                            startIconColor: "error",
                            "type": "task",
                            "ui_feature": "apollo:ticket_store_purge",
                            "parameters": {serviceName: jinfo["service_fullname"]},
                        }
                    },
                    "client": { "plaintext": jinfo["client_fullname"], "cellStyle": {}, copyIcon: true },
                    "service": { "plaintext": jinfo["service_fullname"], "cellStyle": {}, copyIcon: true },
                    "end": { "plaintext": jinfo["end_time"], "cellStyle": {} },
                    "ticket": { "plaintext": jinfo["ticket"], "cellStyle": {}, copyIcon: true },
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
                        ui_feature: "apollo:ticket_store_add",
                    }
                },
                client: {"plaintext": ""},
                service: {plaintext: ""},
                start: {plaintext: ""},
                end: {plaintext: ""},
                ticket: {plaintext: ""}
            })
        }
        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Stored Kerberos Tickets",
            }]
        };
    }

    // this means we shouldn't have any output
    return { "plaintext": "Not response yet from agent..." }

}
