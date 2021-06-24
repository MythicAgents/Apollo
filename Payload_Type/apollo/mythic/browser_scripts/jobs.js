function(task, response){
    var rows = [];
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response'].replace("'", '"'));
      }catch(error){
        var msg = "Unhandled exception in jobs.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);  
        return response[i]['response'];
      }
      var row_style = "";
      var cell_style = {"hidden": "text-align:center","type":"text-align:center"};
      for (var j = 0; j < data.length; j++)
      {
        rows.push({"Job ID": data[j]['JobID'],
          "Process ID": data[j]['ProcessID'],
          "Command": data[j]['TaskString'],
          "row-style": row_style,
          "cell-style": cell_style
        });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"Job ID", "size":"4em"},{"name":"Process ID", "size":"2em"},{"name":"Command", "size":"6em"}], rows);
    return output;
  }