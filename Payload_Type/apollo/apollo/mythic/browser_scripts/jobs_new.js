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
        let headers = [
            {"plaintext": "kill", "type": "button", "startIcon": "kill", "cellStyle": {}, "width": 100, "disableSort": true},
            {"plaintext": "operator", "type": "string", "cellStyle": {}, "width": 200},
            {"plaintext": "command", "type": "string", "cellStyle": {}, "width": 200},
            {"plaintext": "arguments", "type": "string", "cellStyle": {}, "fillWidth": true},
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
            
            for(let j = 0; j < data.length; j++){
                let jinfo = data[j];
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "kill": {"button": {
                        "name": "kill",
                        "type": "task",
                        "ui_feature": "jobkill",
                        "parameters": jinfo["agent_task_id"],
                        "cellStyle": {},
                    }},
                    "operator": {"plaintext": jinfo["operator"], "cellStyle": {}},
                    "command": {"plaintext": jinfo["command"], "cellStyle": {}},
                    "arguments": {"plaintext": jinfo["display_params"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Running Jobs"
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}