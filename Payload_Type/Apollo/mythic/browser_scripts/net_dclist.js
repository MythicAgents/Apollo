function(task, response){
  var rows = [];
  console.log(response);
  for(var i = 0; i < response.length; i++){
    try{
        var data = JSON.parse(response[i]['response'].replace("'", '"'));
    }catch(error){
      var msg = "Unhandled exception in net_dclist.js for " + task.command + " (ID: " + task.id + "): " + error;
      console.error(msg);
        return response[i]['response'];
    }
   var row_style = "";
   var cell_style = {"hidden": "text-align:center",
                                                 "type":"text-align:center"};
   var suffix = "</span>";
   if (data.length == 0) {
     return "No domain controllers discovered."
   }
    for (var j = 0; j < data.length; j++)
    {
        console.log(data[j]);
        var prefix = "";
        if (data[j]["IsGlobalCatalog"])
        {
          prefix = '<i class="fas fa-book fa-fw" data-toggle="tooltip" title="DC is a Global Catalog"></i>  ';
        } else {
          prefix = '<i class="fas fa-fw"></i>  ';
        }
        
        rows.push({"computername": prefix + data[j]['ComputerName'],
                  "ipaddress": data[j]['IPAddress'],
                  "domain": data[j]['Domain'],
                  "forest": data[j]["Forest"],
                  "os version": data[j]["OSVersion"],
                //    "type": data['type'],
                   "row-style": row_style,
                   "cell-style": cell_style
                 });
    }
  }
  var output = support_scripts['apollo_create_table']([{"name":"computername", "size":"2em"},{"name":"ipaddress", "size":"2em"},{"name":"domain", "size":"2em"},{"name":"forest", "size":"2em"},{"name":"os version", "size":"2em"}], rows);
  return output;
}