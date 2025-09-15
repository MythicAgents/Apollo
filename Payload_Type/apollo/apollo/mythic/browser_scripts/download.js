function(task, responses){
    // Handle error status
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }
    
    if(responses.length > 0){
        // The response is just the UUID string, not JSON
        const uuid = responses[0].trim();
        
        // Basic UUID validation (optional)
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        
        if(uuidRegex.test(uuid)){
            // Use the UUID directly as the agent_file_id
            return {
                "media": [{
                    "filename": task.display_params || "file",
                    "agent_file_id": uuid
                }]
            };
        } else {
            // If it's not a valid UUID, just display what we got
            return {'plaintext': responses[0]};
        }
    } else {
        return {"plaintext": "No response yet..."};
    }
}