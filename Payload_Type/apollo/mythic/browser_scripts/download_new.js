function(task, responses){
    let output = responses[0];
    if (responses.length == 0) {
        try {
            output = "<div class='card'><div class='card-header border border-dark shadow'>Downloading...</div></div>";
        } catch(error) {
            console.log(error);
        }
    }
    if(responses.length == 1){
        if (responses[0].indexOf("-") != -1)
        {
            output = "<div class='card'><div class='card-header border border-dark shadow'>Click <a href='/api/v1.4/files/download/" + responses[0] + "'>here</a> to download.</div></div>";
        }
    }
    return {"plaintext": output};
}