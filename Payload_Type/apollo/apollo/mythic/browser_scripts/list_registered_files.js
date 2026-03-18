function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "remove", "type": "button", "cellStyle": {}, "width": 120, "disableSort": true},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
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
                let row = {
                    "rowStyle": {},
                    "remove": {
                        button: {
                            "name": "Remove",
                            "type": "task",
                            "ui_feature": "apollo:remove_registered_file",
                            "parameters": {
                                "file_name": data[j],
                            },
                            "openDialog": false,
                            "getConfirmation": false,
                            "hoverText": "Remove from Memory"
                        }
                    },
                    "name": {"plaintext": data[j], "cellStyle": {}}
                };
                rows.push(row);
            }
        }
        return {"table":[{
                "headers": headers,
                "rows": rows,
                "title": "Files Registered in Memory",
            }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "No response yet from agent..."}
    }
}