function(task, responses){
    if (responses.length == 1) {
        try {
            let jsonStatus = JSON.parse(responses[0]['response']);
            console.log(jsonStatus);
            if(jsonStatus['agent_file_id']){
                let output = "<div class='card'><div class='card-header border border-dark shadow'>Started download of <span class='display'>" + jsonStatus['filename'] + "</span></div></div>";
                return output;
            }
        } catch(error) {
            return responses[0]['response'];
        }
    }
    if(responses.length == 2){
        try{
            let jsonStatus = JSON.parse(responses[0]['response']);
            console.log(jsonStatus);
            if(jsonStatus['agent_file_id']){
                let output = "<div class='card'><div class='card-header border border-dark shadow'>Finished Downloading <span class='display'>" + jsonStatus['filename'] + "</span>. Click <a href='/api/v1.4/files/download/" + jsonStatus['agent_file_id'] + "'>here</a> to download</div></div>";
                return output;
            }
         }catch(error){
            return responses[0]['response'];
        }
    }
    return responses[0]['response'];
}