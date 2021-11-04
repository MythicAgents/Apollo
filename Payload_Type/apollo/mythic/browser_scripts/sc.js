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
        
        let headers = [
            {"plaintext": "start", "type": "button", "cellStyle": {}, "width": 10},
            {"plaintext": "stop", "type": "button", "cellStyle": {}, "width": 10},
            {"plaintext": "status", "type": "string", "cellStyle": {}, "width": 10},
            {"plaintext": "service", "type": "string", "cellStyle": {}},
            {"plaintext": "display name", "type": "string", "cellStyle": {}},
        ];
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
            let original_params = JSON.loads(task.original_params);
            for(let j = 0; j < data.length; j++){
                let jinfo = data[j];
                let isStart = jinfo["status"] == "Stopped";
                let isStop = jinfo["can_stop"] && (jinfo["status"] == "Running" || jinfo["status"] == "StartPending");
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "start": {"button": {
                        "name": "start",
                        "type": "task",
                        "disabled": !isStart,
                        "ui_feature": "sc:start",
                        "parameters": JSON.stringify({
                            "Action": "start",
                            "Computer": original_params["Computer"],
                            "Service Name": jinfo["service"],
                            "Display Name": jinfo["display_name"],
                            "Binary Path": "",
                        }),
                        "cellStyle": {},
                    }},
                    "stop": {"button": {
                        "name": "stop",
                        "type": "task",
                        "disabled": !isStop,
                        "ui_feature": "sc:stop",
                        "parameters": JSON.stringify({
                            "Action": "stop",
                            "Computer": original_params["Computer"],
                            "Service Name": jinfo["service"],
                            "Display Name": jinfo["display_name"],
                            "Binary Path": "",
                        }),
                        "cellStyle": {},
                    }},
                    "status": {"plaintext": jinfo["status"], "cellStyle": {}},
                    "service": {"plaintext": jinfo["service"], "cellStyle": {}},
                    "display name": {"plaintext": jinfo["display_name"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Services",
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}