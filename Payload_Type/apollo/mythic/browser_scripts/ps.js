function(task, response){
    var rows = [];
    console.log(response);
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response'].replace("'", '"'));
      }catch(error){
        var msg = "Unhandled exception in ps.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);
          return response[i]['response'];
      }
     var row_style = "";
     var cell_style = {"name": "max-width:0;",
     "user": "max-width:0;",
     "description": "max-width:0;",
     "company name": "max-width:0;",};
      for (var j = 0; j < data.length; j++)
      {
            //   console.log(data[j]);
            var ppid = "";
            var session = "";
            if (data[j]["parent_process_id"] != -1) {
                ppid = data[j]["parent_process_id"];
            }
            if (data[j]["session"] != -1) {
                session = data[j]["session"];
            }

            function escapeHTML(content)
            {
                return content
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }
            rows.push({"pid": data[j]['process_id'],
                       "ppid": ppid,            
                       "name": data[j]["name"],
                       "arch": data[j]["architecture"],
                       "user": data[j]["user"],
                       "path": data[j]["bin_path"],
                        //    "type": data['type'],
                            "row-style": row_style,
                            "cell-style": cell_style
                        });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"pid", "size":"30px"},{"name":"ppid", "size":"30px"},{"name":"arch", "size":"60px"},{"name":"name", "size":"30em"},{"name": "user", "size": "15em"}, {"name":"path", "size":"15em"}], rows);
    return output;
  }