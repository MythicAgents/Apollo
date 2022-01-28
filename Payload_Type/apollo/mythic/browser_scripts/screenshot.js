function(task, responses){
  if(responses.length > 0){
    let responseArr = [];
    responseArr.push({
        "agent_file_id": responses,
        "variant": "contained",
        "name": "View Screenshot"
    });
    return {"screenshot": responseArr};
  }else{
      return {"plaintext": "No data to display..."}
  }
}