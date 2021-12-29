function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            try{
                console.log(data);
                let data = JSON.parse(responses[0]);
                return {"download":[{
                    "agent_file_id": data["agent_file_id"],
                    "variant": "contained",
                    "name": "Download " + data["filename"]
                }]};
            }catch(error){
                const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }

        }else{
            return {"plaintext": "No data to display..."}
        }

    }else if(task.status === "processed"){
        if(responses.length > 0){
            const task_data = JSON.parse(responses[0]);
            console.log(task_data);
            return {"plaintext": "Downloading a file with " + task_data["total_chunks"] + " total chunks..."};
        }
        return {"plaintext": "No data yet..."}
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}