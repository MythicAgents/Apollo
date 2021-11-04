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
            {"plaintext": "group", "type": "string", "cellStyle": {}, "width": 10},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "sid", "type": "string", "cellStyle": {}},
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
            let tableTile = "";
            for(let j = 0; j < data.length; j++){
                let jinfo = data[j];
                if (tableTile == ""){
                    tableTile = jinfo["group_name"] + " Membership";
                }
                let row = {
                    // If process name is BAD, then highlight red.
                    "rowStyle": {},
                    "group": {"plaintext": jinfo["is_group"], "cellStyle": {}},
                    "name": {"plaintext": jinfo["member_name"], "cellStyle": {}},
                    "sid": {"plaintext": jinfo["sid"], "cellStyle": {}},
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