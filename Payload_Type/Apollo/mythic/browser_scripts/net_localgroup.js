function(task, response){
  var rows = [];
  console.log(response);
  for(var i = 0; i < response.length; i++){
    try{
        var data = JSON.parse(response[i]['response'].replace("'", '"'));
    }catch(error){
      var msg = "Unhandled exception in net_localgroup.js for " + task.command + " (ID: " + task.id + "): " + error;
      console.error(msg);  
      return response[i]['response'];
    }
   var row_style = "";
   var cell_style = {"hidden": "text-align:center",
                                                 "type":"text-align:center"};
   var suffix = "</span>";
    for (var j = 0; j < data.length; j++)
    {
        console.log(data[j]);
        var prefix = "";
        
        rows.push({"groupname": data[j]['GroupName'],
                  "comment": data[j]['Comment'],
                  "computername": data[j]["ComputerName"],
                //    "type": data['type'],
                   "row-style": row_style,
                   "cell-style": cell_style
                 });
    }
  }
  var output = support_scripts['apollo_create_table']([{"name":"groupname", "size":"2em"},{"name":"comment", "size":"2em"},{"name":"computername", "size":"2em"}], rows);
  return output;
}