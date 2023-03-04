function(task, response){
    var rows = [];
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response']);
      }catch(error){
        var msg = "Unhandled exception in reg_query_subkeys.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);
        console.log(response[i]['response']);
        return response[i]['response'];
      }
      var row_style = "";
      var cell_style = {"Key (Expanded)": "max-width:0;"};
      for (var j = 0; j < data.length; j++)
      {
        rows.push({"Key": data[j]['key'],
          "Key (Expanded)": '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy key to clipboard" additional-info=' + btoa(data[j]['full_key']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i> ' + data[j]['full_key'],
          "row-style": row_style,
          "cell-style": cell_style
        });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"Key", "size":"50%"},{"name":"Key (Expanded)", "size":"50%"}], rows);
    return output;
  }