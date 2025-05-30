function(task, responses){

    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }
    if(responses.length > 0){
        try{
            const task_data = JSON.parse(responses[0]);
            return { "media": [{
                    "filename": `${task.display_params}`,
                    "agent_file_id": task_data["file_id"],
                }]};
        }catch(error){
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    } else {
        return {"plaintext": "No response yet..."}
    }

}