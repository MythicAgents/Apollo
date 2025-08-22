function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            try{
                let data = JSON.parse(responses[0]);
                return {"download":[{
                        "agent_file_id": data["file_id"],
                        "variant": "contained",
                        "name": "Download",
                        "plaintext": "Download the file here: ",
                        "hoverText": "download the file"
                }]};
            }catch(error){
                // If it's not JSON, assume it's just a UUID and use that directly
                const fileId = responses[0].trim();
                return {"download":[{
                        "agent_file_id": fileId,
                        "variant": "contained", 
                        "name": "Download",
                        "plaintext": "Download the file here: ",
                        "hoverText": "download the file"
                }]};
            }

        }else{
            return {"plaintext": "No data to display..."}
        }

    }else if(task.status === "processed"){
        if(responses.length > 0){
            try{
                const task_data = JSON.parse(responses[0]);
                return {"plaintext": "Downloading a file with " + task_data["total_chunks"] + " total chunks..."};
            }catch(error){
                return {"plaintext": "Downloading file..."};
            }
        }
        return {"plaintext": "No data yet..."}
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}