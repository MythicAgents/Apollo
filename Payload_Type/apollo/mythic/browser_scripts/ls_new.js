function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let folder = {
                    backgroundColor: "rgb(248, 240, 120)",
                    color: "black"
                };
        let file = {};
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "size", "type": "size", "cellStyle": {}},
            {"plaintext": "owner", "type": "string", "cellStyle": {}},
            {"plaintext": "creation date", "type": "string", "cellStyle": {}},
            {"plaintext": "last modified", "type": "string", "cellStyle": {}},
            {"plaintext": "last accessed", "type": "string", "cellStyle": {}},
            {"plaintext": "EA", "type": "button", "cellStyle": {}, "width": 6},
            {"plaintext": "ACE", "type": "button", "cellStyle": {}, "width": 6},
            {"plaintext": "DL", "type": "button", "cellStyle": {}, "width": 6},
            {"plaintext": "ACT", "type": "button", "cellStyle": {}, "width": 6}
        ];
        let tableHeader = "";
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
            let ls_path = "";
            if(data["parent_path"] === "/"){
                ls_path = data["parent_path"] + data["name"];
            }else{
                ls_path = data["parent_path"] + "\\" + data["name"];
            }
            tableHeader = "Contents of " + ls_path;
            for(let j = 0; j < data["files"].length; j++){
                let finfo = data["files"][j];
                let buttonSettings = {};
                if (finfo["is_file"]) {
                    buttonSettings = {
                        "button": {
                            "name": "CAT",
                            "type": "task",
                            "ui_feature": "cat",
                            "parameters": finfo["full_name"],
                        },
                        "cellStyle": {},
                    }
                } else {
                    buttonSettings = {"button": {
                        "name": "LS",
                        "type": "task",
                        "ui_feature": "file_browser:list",
                        "parameters": finfo["full_name"],
                        },
                        "cellStyle": {},
                    }
                }
                let row = {
                    "rowStyle": data["files"][j]["is_file"] ? file:  folder,
                    "name": {"plaintext": data["files"][j]["name"], "cellStyle": {}},
                    "size": {"plaintext": data["files"][j]["size"], "cellStyle": {}},
                    "owner": {"plaintext": data["files"][j]["owner"], "cellStyle": {}},
                    "creation date": {"plaintext": data["files"][j]["creation_date"], "cellStyle": {}},
                    "last modified": {"plaintext": data["files"][j]["modify_time"], "cellStyle": {}},
                    "last accessed": {"plaintext": data["files"][j]["access_time"], "cellStyle": {}},
                    "EA": {"button": {
                        "name": "EA",
                        "type": "dictionary",
                        "value": {"Extended Attributes": finfo["extended_attributes"]},
                        "leftColumnTitle": "Extended Attributes",
                        "rightColumnTitle": "Values",
                        "title": "Viewing Extended Attributes for " + finfo["name"]
                    }},
                    "ACE": {"button": {
                        "name": "ACE",
                        "type": "dictionary",
                        "value": {"acls": finfo["permissions"]},
                        "leftColumnTitle": "acls",
                        "rightColumnTitle": "Values",
                        "title": "Viewing Acess Control Lists for " + data["files"][j]["name"]
                        },
                        "cellStyle": {},
                    },
                    "DL": {"button": {
                        "name": "DL",
                        "type": "task",
                        "disabled": !finfo["is_file"],
                        "ui_feature": "file_browser:download",
                        "parameters": finfo["full_name"]
                        },
                        "cellStyle": {},
                    },
                    "ACT": buttonSettings,
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": tableHeader,
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}