function(task, responses){
    if (responses.length == 1) {
        try {
            let jsonStatus = JSON.parse(responses[0]['response'].replaceAll("\\", "\\\\"));
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
        if (responses[0]['response'].indexOf("-") != -1)
        {
            let output = "<div class='card'><div class='card-header border border-dark shadow'>Download of <span class='display'>" + responses[0]['response'] + "</span> failed</div></div>";
            return output;
        }
        else
        {
            return responses[0]['response'];
        }
    }
    return responses[0]['response'];
}