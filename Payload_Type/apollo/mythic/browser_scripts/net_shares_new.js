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
            {"plaintext": "list", "type": "button", "startIcon": "list", "cellStyle": {}, "width": 100},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "comment", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "type", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                if (tableTitle == "")
                {
                    tableTitle = "Shares for " + jinfo["computer_name"];
                }
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "list": {"button": {
                        "name": "list",
                        "type": "task",
                        "ui_feature": "file_browser:list",
                        "parameters": "\\\\" + jinfo["computer_name"] + "\\" + jinfo["share_name"],
                        "disabled": !jinfo["readable"],
                        "cellStyle": {},
                    }},
                    "name": {"plaintext": jinfo["share_name"], "cellStyle": {}},
                    "comment": {"plaintext": jinfo["comment"], "cellStyle": {}},
                    "type": {"plaintext": jinfo["type"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Local Groups",
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}