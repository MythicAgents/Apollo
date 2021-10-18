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
            {"plaintext": "ppid", "type": "number", "cellStyle": {}, "width": 6},
            {"plaintext": "pid", "type": "number", "cellStyle": {}, "width": 6},
            {"plaintext": "arch", "type": "string", "cellStyle": {}, "width": 3},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "user", "type": "string", "cellStyle": {}},
            {"plaintext": "session", "type": "number", "cellStyle": {}, "width": 2},
            {"plaintext": "signer", "type": "string", "cellStyle": {}},
            {"plaintext": "info", "type": "button", "cellStyle": {}, "width": 6},
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
                let pinfo = data[j];
                let row = {
                    /*
                    {"plaintext": "ppid", "type": "number", "cellStyle": {}},
            {"plaintext": "pid", "type": "number", "cellStyle": {}},
            {"plaintext": "arch", "type": "string", "cellStyle": {}},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "session", "type": "number", "cellStyle": {}},
            {"plaintext": "signer", "type": "string", "cellStyle": {}},
            {"plaintext": "info", "type": "button", "cellStyle": {}, "width": 6},
                    */
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "ppid": {"plaintext": pinfo["parent_process_id"], "cellStyle": {}},
                    "pid": {"plaintext": pinfo["process_id"], "cellStyle": {}},
                    "arch": {"plaintext": pinfo["architecture"], "cellStyle": {}},
                    "name": {"plaintext": pinfo["name"], "cellStyle": {}},
                    "user": {"plaintext": pinfo["user"], "cellStyle": {}},
                    "session": {"plaintext": pinfo["session_id"], "cellStyle": {}},
                    "signer": {"plaintext": pinfo["company_name"], "cellStyle": {}},
                    "info": {"button": {
                        "name": "info",
                        "type": "dictionary",
                        "value": {
                            "Process Path": pinfo["bin_path"],
                            "File Description" : pinfo["description"],
                            "Command Line": pinfo["command_line"],
                            "Window Title": pinfo["window_title"]
                        },
                        "leftColumnTitle": "Attribute",
                        "rightColumnTitle": "Values",
                        "title": "Information for " + pinfo["name"]
                    }},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Process List"
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}