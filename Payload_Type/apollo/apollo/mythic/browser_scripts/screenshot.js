function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }
    if(responses.length > 0){
        let responseArr = [];
        for(let i = 0; i < responses.length; i++){
            try{
                let fileJSON = JSON.parse(responses[i]);
                responseArr.push({
                    "agent_file_id": fileJSON['file_id'],
                    "filename": "file.png",
                });
            }catch(error){
                console.log(error);
            }
        }
        return {"media":responseArr};
    }else{
        return {"plaintext": "No data to display..."}
    }
}