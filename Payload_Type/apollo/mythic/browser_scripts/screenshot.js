function(task, responses){
  if(responses.length > 0){
    let responseArr = [];
    for(let i = 0; i < responses.length; i++){
      responseArr.push({
          "agent_file_id": responses[i],
          "variant": "contained",
          "name": "View Screenshot " + String(i+1)
      });
    }
    return {"screenshot": responseArr};
  }else{
      return {"plaintext": "No data to display..."}
  }
}