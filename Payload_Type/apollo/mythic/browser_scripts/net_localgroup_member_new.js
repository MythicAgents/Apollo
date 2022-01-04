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
            {"plaintext": "group", "type": "string", "cellStyle": {}, "width": 100},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                if (tableTitle == ""){
                    tableTitle = jinfo["group_name"] + " Membership";
                }
                let groupText = "";
                if (jinfo["is_group"])
                {
                    groupText = "Group";
                }
                else
                {
                    groupText = "User";
                }
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "group": {"plaintext": groupText, "cellStyle": {}},
                    "name": {"plaintext": jinfo["member_name"], "copyIcon": true, "cellStyle": {}},
                    "sid": {"plaintext": jinfo["sid"], "copyIcon": true, "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": tableTitle,
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}