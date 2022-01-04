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
            {"plaintext": "members", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "comment", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "sid", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                    "members": {"button": {
                        "name": "query",
                        "type": "task",
                        "startIcon": "list",
                        "ui_feature": "net_localgroup_member",
                        "parameters": JSON.stringify(
                            {
                                "Computer": jinfo["computer_name"],
                                "Group": jinfo["group_name"],
                            }
                        ),
                        "cellStyle": {},
                    }},
                    "name": {"plaintext": jinfo["group_name"], "cellStyle": {}},
                    "comment": {"plaintext": jinfo["comment"], "cellStyle": {}},
                    "sid": {"plaintext": jinfo["sid"], "cellStyle": {}, "copyIcon": true,},
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