function(task, response){
    var rows = [];
    console.log(response);
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response'].replace("'", '"'));
      }catch(error){
        var msg = "Unhandled exception in net_shares.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);  
        return response[i]['response'];
      }
     var row_style = "";
     var cell_style = {"hidden": "text-align:center"};
     var suffix = "</span>";
     if (data.length == 0) {
     	return "No shares available."
     }
      for (var j = 0; j < data.length; j++)
      {
          console.log(data[j]);
          var prefix = "";
          if (!data[j]["Readable"])
          {
          	prefix = '<i class="fas fa-lock fa-fw" data-toggle="tooltip" title="Cannot read share."></i>  ';
          } else {
          	prefix = '<i class="fas fa-folder-open fa-fw" data-toggle="tooltip" title="Share is accessible"></i>  ';
          }
          
          rows.push({"sharename": prefix + data[j]['ShareName'],
                    "comment": data[j]['Comment'],
                    "computername": data[j]['ComputerName'],
                    "type": data[j]["Type"],
                  //    "type": data['type'],
                     "row-style": row_style,
                     "cell-style": cell_style
                   });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"sharename", "size":"2em"},{"name":"comment", "size":"2em"},{"name":"computername", "size":"2em"},{"name":"type", "size":"2em"}], rows);
    return output;
  }