function(elem){
    console.log(elem);
    var uniqueName = elem.getAttribute("modal-name");
    var b64Content = elem.getAttribute("additional-info");
    var parts = b64Content.split("|");
    var name = atob(parts[0]);
    var fullPath = atob(parts[1]);
    var host = atob(parts[2]);
    httpGetAsync(mythic_endpoint + "/filebrowserobj/permissions/bypath", (response)=>{
        var rows = [];
        var row_style = "";
        var cell_style = {"hidden": "text-align:center",
                            "type":"text-align:center"};
        var header = "Permissions for " + name;
        var output = "";
        try {
            var data = JSON.parse(response);
            var permissionList = JSON.parse(data['permissions']);
            for(var i = 0; i < permissionList.length; i++)
            {
                rows.push({"account": permissionList[i]['account'],
                            "rights": permissionList[i]['rights'],
                            "type": permissionList[i]['type'],
                            //    "type": files['type'],
                                "row-style": row_style,
                                "cell-style": cell_style
                            });
            }
            if (rows.length == 0) {
                rows.push({"account": "No permission data to show.",
                            "rights": "",
                            "type": "",
                            "row-style": row_style,
                            "cell-style": cell_style});
            }
            var uniqueNameId = '#' + uniqueName;
            var modalBody = uniqueNameId + '_body';
            var modalTitle = uniqueNameId + '_title';
            output = support_scripts['apollo_create_table']([{"name":"account", "size":"4em"},{"name":"rights", "size":"4em"},{"name":"type", "size":"2em"}], rows);
        } catch (err) {
            console.error("Error in show_permission_additional_info_modal.js: " + err);
            output = response;
        }
        $(modalBody).html(output);
        $(modalTitle).html(header);
        /*var content = elem.getAttribute("additional-info");
        var uniqueNameId = '#' + uniqueName;
        var modalBody = uniqueNameId + '_body';
        $(modalBody).html(content);
        $(modalBody + ' > pre:last').css("word-wrap", "break-word");
        $(modalBody + ' > pre:last').css("white-space", "pre-wrap");*/
        $(uniqueNameId).modal('show');    
    }, "POST", {"host": host, "full_path": fullPath});
}