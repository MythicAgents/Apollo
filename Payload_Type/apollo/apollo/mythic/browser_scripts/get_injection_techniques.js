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
            {"plaintext": "set", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true },
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
                    "set": {"button": {
                        "name": "set",
                        "type": "task",
                        "disabled": jinfo["is_current"],
                        "ui_feature": "set_injection_technique",
                        "parameters": jinfo["name"],
                        "cellStyle": {},
                    }},
                    "name": {"plaintext": jinfo["name"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Loaded Injection Techniques",
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}