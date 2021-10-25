function(task, responses){
  if(task.status.toLowercase().includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            return {"screenshot":[{
                "agent_file_id": responses[0],
                "variant": "contained",
                "name": "View Screenshot"
            }]};
        }else{
            return {"plaintext": "No data to display..."}
        }
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for all chunks..."}
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}