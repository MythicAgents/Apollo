function(task, responses){
  console.log(responses);
  if(task.completed){
    try{
        // let status = JSON.parse(responses[0]['response']);
    	  let id = responses[0]['response'];
        let output = "<div class='card'><div class='card-header border border-dark shadow'><a class='btn stretched-link' type='button' data-toggle='collapse' data-target='#task" + task['id'] + "screencapture' aria-expanded='false' aria-controls='task" + task['id'] + "screencapture'>Finished <font color='red'>Screencapture " + task['original_params'] + "</font>. Click to view</div>";
      output += "<div class='collapse' id=\"task" + task['id'] + "screencapture\" style='width:100%'>";
      output += "<div class='response-background card-body'><img src='/api/v1.4/files/screencaptures/" + id + "' width='100%'></div></div></div>";
		      return output;
    }catch(error){
      var msg = "Unhandled exception in screenshot.js for " + task.command + " (ID: " + task.id + "): " + error;
      console.error(msg);
       return responses[0]['response'];
    }
  }if(task.status === 'processing'){
  	return "<pre> downloading pieces ...</pre>";
  }if(task.status === 'error'){
  	return responses[0]['response'];
  }
}