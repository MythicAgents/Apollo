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
            {"plaintext": "query", "type": "button", "cellStyle": {}, "width": 120, "disableSort": true},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "type", "type": "string", "cellStyle": {}, "width": 100},
            {"plaintext": "value", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                let fullname = jinfo["full_name"];
                if (fullname[0] == "\\")
                {
                    fullname = jinfo["hive"] + ":" + fullname;
                } else {
                    fullname = jinfo["hive"] + ":\\" + fullname;
                }
                let shouldCopy = false;
                if (jinfo["result_type"] != "key" && jinfo["value"]!=null && jinfo["value"].length > 0) {
                    shouldCopy = true;
                }
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "query": {"button": {
                        "name": "query",
                        "type": "task",
                        "startIcon": "list",
                        "disabled": jinfo["result_type"] != "key",
                        "ui_feature": "reg_query",
                        "parameters": fullname,
                        "cellStyle": {},
                    }},
                    "name": {"plaintext": jinfo["name"], "cellStyle": {}},
                    "type": {"plaintext": jinfo["value_type"], "cellStyle": {}},
                    "value": {"plaintext": jinfo["value"], "copyIcon": shouldCopy, "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": task.display_params,
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}