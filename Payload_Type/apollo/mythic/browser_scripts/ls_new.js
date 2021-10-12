function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let folder = {
                    backgroundColor: "mediumorange",
                    color: "white"
                };
        let file = {};
        let data = "";
        for(let i = 0; i < respondes.length; i++)
        {
            try{
                data = JSON.parse(responses[i]);
            }catch(error){
               const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
            let ls_path = "";
            if(data["parent_path"] === "/"){
                ls_path = data["parent_path"] + data["name"];
            }else{
                ls_path = data["parent_path"] + "/" + data["name"];
            }
            let headers = [
                {"plaintext": "name", "type": "string"},
                {"plaintext": "size", "type": "size"},
                {"plaintext": "owner", "type": "string"},
                {"plaintext": "group", "type": "string"},
                {"plaintext": "creation_date", "type": "string"},
                {"plaintext": "modify_time", "type": "string"},
                {"plaintext": "access_time", "type": "string", "width": 8},
                {"plaintext": "extended_attributes", "type": "string", "width": 6},
                {"plaintext": "ACE", "type": "button", "width": 10},
                {"plaintext": "DL", "type": "button", "width": 6},
                {"plaintext": "LS", "type": "button", "width": 6}
            ];
            let rows = [{
                "rowStyle": data["is_file"] ? file : folder,
                "name": {"plaintext": data["name"]},
                "size": {"plaintext": data["size"]},
                "owner": {"plaintext": data["owner"]},
                "group": {"plaintext": data["group"]},
                "creation_date": {"plaintext": data["creation_date"]},
                "modify_time": {"plaintext": data["modify_time"]},
                "access_time": {"plaintext": data["access_time"]},
                "extended_attributes": {"plaintext": ""},
                "ACE": {"button": {
                    "name": "View Access Control Lists",
                    "type": "dictionary",
                    "value": {"acls": data["permissions"]},
                    "leftColumnTitle": "acls",
                    "rightColumnTitle": "Values",
                    "title": "Viewing Acess Control Lists for " + data["name"]
                }},
                "DL": {"button": {
                  "name": "DL",
                  "type": "task",
                  "disabled": !data["is_file"],
                  "ui_feature": "file_browser:download",
                  "parameters": ls_path
                }},
                "LS": {"button": {
                    "name": "LS",
                    "type": "task",
                    "ui_feature": "file_browser:list",
                    "parameters": ls_path
                }}
            }];
            for(let j = 0; j < data["files"].length; j++){
                let ls_path = "";
                if(data["parent_path"] === "/"){
                    ls_path = data["parent_path"] + data["name"] + "\\" + data["files"][j]["name"];
                }else{
                    ls_path = data["parent_path"] + "\\" + data["name"] + "\\" + data["files"][j]["name"];
                }
                let row = {
                    "rowStyle": data["files"][j]["is_file"] ? file:  folder,
                    "name": {"plaintext": data["files"][j]["name"]},
                    "size": {"plaintext": data["files"][j]["size"]},
                    "creation_date": {"plaintext": data["files"][j]["creation_date"]},
                    "modify_time": {"plaintext": data["files"][j]["modify_time"]},
                    "access_time": {"plaintext": data["files"][j]["access_time"],
                        "cellStyle": {
    
                        }
                    },
                    "extended_attributes": {"plaintext": data["files"][j]["extended_attributes"]},
                    "ACE": {"button": {
                        "name": "View Access Control Lists",
                        "type": "dictionary",
                        "value": {"acls": data["permissions"]},
                        "leftColumnTitle": "acls",
                        "rightColumnTitle": "Values",
                        "title": "Viewing Acess Control Lists for " + data["files"][j]
                    }},
                    "DL": {"button": {
                    "name": "DL",
                    "type": "task",
                    "disabled": !data[j]["is_file"],
                    "ui_feature": "file_browser:download",
                    "parameters": data[j]["full_name"]
                    }},
                    "LS": {"button": {
                        "name": "LS",
                        "type": "task",
                        "ui_feature": "file_browser:list",
                        "parameters": data[j]["full_name"]
                    }}
                };
                rows.push(row);
            }
            return {"table":[{
                "headers": headers,
                "rows": rows,
                "title": "File Listing Data"
            }]};
        }
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}