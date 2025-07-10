function(task, responses){

    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }
    if(responses.length > 0){
        try{
            var response_data = [];
            for(let i = 0; i < responses.length; i++){
                const task_data = JSON.parse(responses[i]);
                response_data.push(...task_data);
            }
            return {'plaintext': JSON.stringify(response_data, null, 2)}
        }catch(error){
            console.log(error);
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    } else {
        return {"plaintext": "No response yet..."}
    }

}