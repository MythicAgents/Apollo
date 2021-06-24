function(task, response){
    var rows = [];
    console.log(response);
    for(var i = 0; i < response.length; i++){
      try{
          var data = JSON.parse(response[i]['response'].replace("'", '"'));
      }catch(error){
        var msg = "Unhandled exception in ps_full.js for " + task.command + " (ID: " + task.id + "): " + error;
        console.error(msg);  
        return response[i]['response'];
      }
     var row_style = "";
     var cell_style = {"name": "max-width:0;",
     "user": "max-width:0;",
     "description": "max-width:0;",
     "company name": "max-width:0;",};
      var uniqueName = task.id + "_additional_process_info_modal";
      console.log(uniqueName);
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
            var additionalInfo = {
                "integrity_level": support_scripts['apollo_integrity_level_to_string'](data[j]["integrity_level_string"]),
                "file_path": data[j]["bin_path"],
                "command_line": data[j]["command_line"],
                "session": session,
                "name": data[j]["name"],
                "pid": data[j]['process_id']
            };
            var integrityLevel = escapeHTML(support_scripts['apollo_integrity_level_to_string'](data[j]["integrity_level_string"]));
            var icon = '';
            if (integrityLevel.includes("HIGH") || integrityLevel.includes("SYSTEM")) {
                icon = '<i style="color: red; cursor: pointer;" class="fas fa-info-circle" modal-name="' + uniqueName + '" additional-info="' + btoa(JSON.stringify(additionalInfo)) + '" onclick=support_scripts[\"apollo_show_process_additional_info_modal\"](this)></i> ';
            } else {
                icon = '<i class="fas fa-info-circle" style="cursor: pointer;" modal-name="' + uniqueName + '" additional-info="' + btoa(JSON.stringify(additionalInfo)) + '" onclick=support_scripts[\"apollo_show_process_additional_info_modal\"](this)></i> ';
            }
            rows.push({"pid": data[j]['process_id'],
                       "ppid": ppid,            
                       "name": icon + data[j]["name"],
                       "arch": data[j]["architecture"],
                       "user": data[j]["user"],
                       "description": data[j]["description"],
                       "company name": data[j]["signer"],
                        //    "type": data['type'],
                            "row-style": row_style,
                            "cell-style": cell_style
                        });
      }
    }
    var output = support_scripts['apollo_create_table']([{"name":"pid", "size":"30px"},{"name":"ppid", "size":"30px"},{"name":"arch", "size":"60px"},{"name":"name", "size":"30em"},{"name": "user", "size": "15em"},{"name":"description", "size":"15em"},{"name": "company name", "size": "15em"}], rows);
    output += support_scripts['apollo_create_process_additional_info_modal'](uniqueName);
    return output;
  }