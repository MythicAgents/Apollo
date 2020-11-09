function(task, response){
  var rows = [];
  console.log(response);
  for(var i = 0; i < response.length; i++){
    try{
        var data = JSON.parse(response[i]['response'].replace("'", '"'));
    }catch(error){
      var msg = "Unhandled exception in net_localgroup_member.js for " + task.command + " (ID: " + task.id + "): " + error;
      console.error(msg);  
      return response[i]['response'];
    }
   var row_style = "";
   var cell_style = {"hidden": "text-align:center",
                                                 "type":"text-align:center"};
   var suffix = "</span>";
   if (data.length == 0) {
     return "This group contains no members."
   }
    for (var j = 0; j < data.length; j++)
    {
        var prefix = "";
        if (!data[j]["IsGroup"])
        {
          prefix = '<i class="fas fa-user-circle fa-fw" data-toggle="tooltip" title="User"></i>  ';
        } else {
          prefix = '<i class="fas fa-users fa-fw" data-toggle="tooltip" title="Group"></i>  ';
        }
        
        rows.push({"membername": prefix + data[j]['MemberName'],
                  "sid": data[j]['SID'],
                  "groupname": data[j]['GroupName'],
                  "computername": data[j]["ComputerName"],
                //    "type": data['type'],
                   "row-style": row_style,
                   "cell-style": cell_style
                 });
    }
  }
  var output = support_scripts['apollo_create_table']([{"name":"membername", "size":"2em"},{"name":"sid", "size":"2em"},{"name":"groupname", "size":"2em"},{"name":"computername", "size":"2em"}], rows);
  return output;
}