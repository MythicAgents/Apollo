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
        try {
            let originalParams = JSON.parse(task.original_params);
            tableTitle = originalParams["hive"] + "\\" + originalParams["key"];
        } catch (error){
            console.log("Error trying to load original params: " + error);
            tableTitle = "Registry Listing";
        }
        let headers = [
            {"plaintext": "query", "type": "button", "cellStyle": {}, "width": 10},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "type", "type": "string", "cellStyle": {}, "width": 10},
            {"plaintext": "value", "type": "string", "cellStyle": {}},
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
                    "query": {"button": {
                        "name": "query",
                        "type": "task",
                        "disabled": jinfo["result_type"] != "key",
                        "ui_feature": "reg_query",
                        "parameters": jinfo["full_name"],
                        "cellStyle": {},
                    }},
                    "name": {"plaintext": jinfo["name"], "cellStyle": {}},
                    "type": {"plaintext": jinfo["value_type"], "cellStyle": {}},
                    "value": {"plaintext": jinfo["value"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": tableTitle
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}