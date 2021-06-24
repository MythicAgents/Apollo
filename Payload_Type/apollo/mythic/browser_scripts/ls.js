function(task, response){
  var rows = [];
  var curdir = task.original_params;
  if (curdir == "") {
    curdir = "current directory";
  }
  var FILE_THRESHOLD = 500;
  var archiveFormats = [".a",".ar",".cpio",".shar",".LBR",".lbr",".mar",".sbx",".tar",".bz2",".F",".gz",".lz",".lz4",".lzma",".lzo",".rz",".sfark",".sz",".?Q?",".?Z?",".xz",".z",".Z",".zst",".??",".7z",".s7z",".ace",".afa",".alz",".apk",".arc",".arc",".arj",".b1",".b6z",".ba",".bh",".cab",".car",".cfs",".cpt",".dar",".dd",".dgc",".ear",".gca",".ha",".hki",".ice",".jar",".kgb",".lzh",".lzx",".pak",".pak",".parti",".paq6",".pea",".pim",".pit",".qda",".rar",".rk",".sda",".sea",".sen",".sfx",".shk",".sit",".sitx",".sqx",".tar",".tbz2",".uc",".uca",".uha",".war",".wim",".xar",".xp3",".yz1",".zip",".zoo",".zpaq",".zz",".ecc",".ecsbx",".par",".par2",".rev"];
  var diskImages = [".dmg", ".iso", ".vmdk"];
  var wordDocs = [".doc", ".docx", ".dotm", ".dot", ".wbk", ".docm", ".dotx", ".docb"];
  var excelDocs = [".xls", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlmx", ".xlmt"];
  var powerPoint = [".ppt", ".pptx", ".potx", ".ppsx", ".thmx", ".pot", ".pps"];
  var pdfExt = [".pdf"];
  var dbExt = [".db", ".sql", ".psql"];
  var keyFiles = [".pem", ".ppk"];
  var scriptFiles = [".config", ".ps1", ".psm1", ".psd1", ".vbs", ".js", ".py", ".pl", ".rb", ".go", ".xml", ".html", ".css", ".sh", ".bash", ".yaml", ".yml"];
  var uniqueName = task.id + "_additional_permission_info_modal";
  for(var i = 0; i < response.length; i++){
    try{
        var data = JSON.parse(response[i]['response'].replace("'", '"'));
    }catch(error){
      var msg = "Unhandled exception in ls.js for " + task.command + " (ID: " + task.id + "): " + error;
      console.error(msg);
        return response[i]['response'];
    }
    var files = data['files'];
    var row_style = "";
    var cell_style = {"name":"max-width:0;",
    "size":"max-width:0;",
    "last modified":"max-width:0;",
    "last accessed":"max-width:0;",
    "creation date":"max-width:0;",
    "owner":"max-width:0;"};
    if (files.length < FILE_THRESHOLD)
    {
      for (var j = 0; j < files.length; j++)
      {
        var additionalInfo = btoa(files[j]['name']) + "|" + btoa(files[j]['full_name']) + "|" + btoa(data['host']);
          copyicon = '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy filename to clipboard" additional-info=' + btoa(files[j]['full_name']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i>';   
          if (files[j]["is_file"]){
            var fileExt = "." + files[j]['name'].split(".").slice(-1)[0].toLowerCase();
            // do big conditional for fancy icons <@:^)
            var icon = '<i class="fas fa-file"></i>';
            if (archiveFormats.includes(fileExt)) {
              icon = '<i class="fas fa-file-archive" data-toggle="tooltip" title="Archive Format" style="color:goldenrod;"></i>';
            } else if (diskImages.includes(fileExt)) {
              icon = '<i class="fas fa-save" style="color:goldenrod;" data-toggle="tooltip" title="Disk Image Format"></i>';
            } else if (wordDocs.includes(fileExt)) {
              icon = '<i class="fas fa-file-word" style="color:cornflowerblue;" data-toggle="tooltip" title="Word Document"></i>';
            } else if (excelDocs.includes(fileExt)){
              icon = '<i class="fas fa-file-excel" style="color:darkseagreen;" data-toggle="tooltip" title="Excel Document"></i>';
            } else if (powerPoint.includes(fileExt)) {
              icon = '<i class="fas fa-file-powerpoint" style="color:indianred;" data-toggle="tooltip" title="PowerPoint Document"></i>';
            } else if (pdfExt.includes(fileExt)){
              icon = '<i class="fas fa-file-pdf" style="color:orangered;" data-toggle="tooltip" title="Adobe Acrobat Document"></i>';
            } else if (dbExt.includes(fileExt)) {
              icon = '<i class="fas fa-database" data-toggle="tooltip" title="Database File"></i>';
            } else if (keyFiles.includes(fileExt)) {
              icon = '<i class="fas fa-key" data-toggle="tooltip" title="Private Key File"></i>';
            } else if (scriptFiles.includes(fileExt)) {
              icon = '<i class="fas fa-file-code" style="color:rgb(25,142,117);" data-toggle="tooltip" title="Code File"></i>';
            }
            rows.push({ "": copyicon,
                        "name": icon + ' ' + files[j]['name'],
                        "size": support_scripts['apollo_file_size_to_human_readable_string'](files[j]['size']),
                        "last accessed": files[j]["access_time"],
                        "last modified": files[j]["modify_time"],
                        "creation date": files[j]["creation_date"],
                        "acls": '<i class="fas fa-users" data-toggle="tooltip" title="Access Control List for ' + files[j]['name'] + '" style="cursor: pointer;" modal-name="' + uniqueName + '" additional-info="' + additionalInfo + '" onclick=support_scripts[\"apollo_show_permission_additional_info_modal\"](this)></i>',
                        "owner": files[j]['owner'],
                        "row-style": row_style,
                        "cell-style": cell_style
                      });
          } else {
            rows.push({"": copyicon,
            "name": '<i class="fas fa-folder-open"></i> ' + files[j]['name'],
            "size": support_scripts['apollo_file_size_to_human_readable_string'](0),
            "last modified": files[j]["modify_time"],
            "last accessed": files[j]["access_time"],
            "creation date": files[j]["creation_date"],
            "acls": '<i class="fas fa-users" style="cursor: pointer;" data-toggle="tooltip" title="Access Control List for ' + files[j]['name'] + '" modal-name="' + uniqueName + '" additional-info="' + additionalInfo + '" onclick=support_scripts[\"apollo_show_permission_additional_info_modal\"](this)></i>',
            "owner": files[j]['owner'],
            "row-style": row_style,
            "cell-style": cell_style
          });
        }
      }
      var output = support_scripts['apollo_create_table']([{"name":"", "size":"1em"}, {"name":"name", "size":"30em"},{"name":"size", "size":"6em"},{"name":"last accessed", "size":"8em"},{"name":"last modified", "size":"8em"},{"name":"creation date", "size":"8em"},{"name":"acls", "size":"1em"}, {"name":"owner", "size":"15em"}], rows);
      output += support_scripts['apollo_create_permission_additional_info_modal'](uniqueName);
      return output;
    } else {
      var output = "<pre>Files in " + curdir + "\n\n";
      output += "creation_date,last_modified,last_accessed,owner,size,name\n";
      for (var j = 0; j < files.length; j++)
      {
        output += files[j]['creation_date'] + "," + files[j]['modify_time'] + "," + files[j]['access_time'] + "," + files[j]['owner'] + "," + support_scripts['apollo_file_size_to_human_readable_string'](files[j]['size']) + "," + files[j]['name'] + "\n";
      }
      output += "</pre>"
      return output;
    }
  }
}


/*
httpGetAsync("{{http}}://{{links.server_ip}}:{{links.server_port}}{{links.api_base}}/filebrowserobj/" + data['id'] + "/permissions", (response)=>{
                  try{
                      let perms = JSON.parse(response);
                      if(perms['status'] === "success"){
                          try {
                              this.file_browser_permissions = JSON.parse(perms['permissions']);
                          } catch (error) {
                              this.file_browser_permissions = {"Permissions": perms['permissions']};
                          }
                      }else{
                          alertTop("warning", "Failed to fetch permissions: " + perms['error']);
                      }
                  }catch(error){
                      console.log(error);
                      alertTop("danger", "Session expired, please refresh");
                  }
              }, "GET", null);

*/