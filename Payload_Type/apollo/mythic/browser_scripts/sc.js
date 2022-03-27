function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let file = {};
        let data = "";
        let rows = [];
        let tableTitle = "";

        for(let i = 0; i < responses.length; i++)
        {
            try{
                data = JSON.parse(responses[i]);
            }catch(error){
                console.log(error);
               const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
            let headers = [
                {"plaintext": "actions", "type": "button", "cellStyle": {}, "width": 120, "disableSort": true},
                {"plaintext": "status", "type": "string", "cellStyle": {}, "width": 125},
                {"plaintext": "pid", "type": "string", "cellStyle": {}, "width": 125},
                {"plaintext": "service", "type": "string", "cellStyle": {}, "fillWidth": true},
                {"plaintext": "display name", "type": "string", "cellStyle": {}, "fillWidth": true},
                {"plaintext": "binary path", "type": "string", "cellStyle": {}, "fillWidth": true},
            ];
            for(let j = 0; j < data.length; j++){
                let jinfo = data[j];
                let isStart = jinfo["status"] === "Stopped";
                let isStop = jinfo["can_stop"] && (jinfo["status"] === "Running" || jinfo["status"] === "StartPending");
                let row = {
                    "rowStyle": {},
                    "actions": {"button": {
                        "name": "Actions",
                        "type": "menu",
                        "startIcon": "list",
                        "value": [
                            {
                                "name": "Start",
                                "type": "task",
                                "ui_feature": "sc:start",
                                "parameters": JSON.stringify({
                                    "start": true,
                                    "computer": jinfo["computer"],
                                    "service": jinfo["service"],
                                }),
                                "disabled": !isStart,
                                "hoverText": "Start Service",
                                "openDialog": false,
                                "getConfirmation": false
                            },
                            {
                                "name": "Stop",
                                "type": "task",
                                "ui_feature": "sc:stop",
                                "parameters": JSON.stringify({
                                    "stop": true,
                                    "computer": jinfo["computer"],
                                    "service": jinfo["service"],
                                }),
                                "disabled": !isStop,
                                "hoverText": "Stop Service",
                                "openDialog": false,
                                "getConfirmation": false
                            },
                            {
                                "name": "Delete",
                                "type": "task",
                                "ui_feature": "sc:delete",
                                "parameters": {
                                    "start": true,
                                    "computer": jinfo["computer"],
                                    "service": jinfo["service"],
                                },
                                "openDialog": false,
                                "getConfirmation": true,
                                "acceptText": "delete",
                                "hoverText": "Delete Service"
                            },
                            {
                                "name": "Modify",
                                "type": "task",
                                "ui_feature": "sc:modify",
                                "parameters": {
                                    "modify": true,
                                    "computer": jinfo["computer"],
                                    "service": jinfo["service"],
                                    "dependencies": []
                                },
                                "openDialog": true,
                                "getConfirmation": false,
                                "hoverText": "Modify Service"
                            },
                                                        {
                                "name": "More Info",
                                "type": "dictionary",
                                "value": {
                                    "Service Name": jinfo["service"],
                                    "Display Name": jinfo["display_name"],
                                    "Description": jinfo["description"],
                                    "Binary Path": jinfo["binary_path"],
                                    "Run As": jinfo["run_as"],
                                    "Start Type": jinfo["start_type"],
                                    "Status": jinfo["status"],
                                    "PID": jinfo["pid"] === "0" ? "":jinfo["pid"],
                                    "Dependencies": jinfo["dependencies"].toString(),
                                    "Service Type": jinfo["service_type"],
                                    "Accepted Control": jinfo["accepted_controls"][0] === "0" ? "":jinfo["accepted_controls"].toString(),
                                    "Error Control": jinfo["error_control"],
                                    "Load Order Group": jinfo["load_order_group"],
                                    "Computer": jinfo["computer"]
                                },
                                "leftColumnTitle": "Attribute",
                                "rightColumnTitle": "Values",
                                "title": "Information for " + jinfo["name"],
                                "hoverText": "More Info"
                            }
                        ]
                    }},
                    "status": {"plaintext": jinfo["status"], "cellStyle": {}},
                    "pid": {"plaintext": jinfo["pid"] === "0" ? "":jinfo["pid"], "cellStyle": {}},
                    "service": {"plaintext": jinfo["service"], "cellStyle": {}},
                    "display name": {"plaintext": jinfo["display_name"], "cellStyle": {}},
                    "binary path": {"plaintext": jinfo["binary_path"], "cellStyle": {}},
                };
                rows.push(row);
            }
            return {"table":[{
                "headers": headers,
                "rows": rows,
                "title": "Services",
            }]};
        }

    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}