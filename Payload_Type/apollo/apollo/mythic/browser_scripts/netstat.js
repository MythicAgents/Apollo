function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let data = "";
        let rows = [];
        let tableTitle = "Network Connections";

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
            let headers = [
                {"plaintext": "proto", "type": "string", "cellStyle": {}, "width": 70},
                {"plaintext": "local address", "type": "string", "cellStyle": {}, "width": 400},
                {"plaintext": "local port", "type": "number", "cellStyle": {}, "width": 150},
                {"plaintext": "remote address", "type": "string", "cellStyle": {}, "width": 400},
                {"plaintext": "remote port", "type": "number", "cellStyle": {}, "width": 150},
                {"plaintext": "state", "type": "string", "cellStyle": {}, "width": 200},
                {"plaintext": "pid", "type": "number", "cellStyle": {}, "width": 120},
            ];
            for(let j = 0; j < data.length; j++){
                let jinfo = data[j];
                let row = {
                    "rowStyle": {},
                    "proto": {"plaintext": jinfo["protocol"], "cellStyle": {}},
                    "local address": {"plaintext": jinfo["local_address"], "cellStyle": {}},
                    "local port": {"plaintext": jinfo["local_port"], "cellStyle": {}},
                    "remote address": {"plaintext": jinfo["remote_address"], "cellStyle": {}},
                    "remote port": {"plaintext": jinfo["remote_port"], "cellStyle": {}},
                    "state": {"plaintext": jinfo["state"] ? jinfo["state"]:"", "cellStyle": {}},
                    "pid": {"plaintext": jinfo["pid"], "cellStyle": {}},
                };
                rows.push(row);
            }
            return {"table":[{
                "headers": headers,
                "rows": rows,
                "title": tableTitle,
            }]};
        }

    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}