function(task, response){
    var rows = [];
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response']);
      }catch(error){
        var msg = "Unhandled exception in reg_query_subvalues.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);  
        return response[i]['response'];
      }
      var row_style = "";
      var cell_style = {"Type": "max-width:0;", "Data": "max-width:0;"};
      for (var j = 0; j < data.length; j++)
      {
        rows.push({"Name": data[j]['name'],
          "Type": data[j]['type'],
          "Data": '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy data to clipboard" additional-info=' + btoa(data[j]['value']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i> ' + data[j]['value'],
          "row-style": row_style,
          "cell-style": cell_style
        });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"Name", "size":"35%"},{"name":"Type", "size":"5%"},{"name":"Data", "size":"60%"}], rows);
    return output;
  }
  