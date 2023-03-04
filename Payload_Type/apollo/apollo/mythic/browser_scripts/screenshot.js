function(task, responses){
  if(responses.length > 0){
    let responseArr = [];
    for(let i = 0; i < responses.length; i++){
        responseArr.push(responses[i]);
    }
    return {"screenshot": [{
        "agent_file_id": responseArr,
        "variant": "contained",
        "name": "View Screenshots (" + String(responseArr.length) + ")"
    }]};
  }else{
      return {"plaintext": "No data to display..."}
  }
}