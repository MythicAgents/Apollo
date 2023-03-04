function(elem){
    console.log(elem);
    var rows = [];
    var uniqueName = elem.getAttribute("modal-name");
    // var content = elem.getAttribute("additional-info");
    var b64Content = elem.getAttribute("additional-info");
    var additionalInfo = JSON.parse(atob(b64Content));
    var copyProcess = '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy process path to clipboard" additional-info=' + btoa(additionalInfo['file_path']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i>';
    var copyIntegrity = '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy integrity level path to clipboard" additional-info=' + btoa(additionalInfo['integrity_level']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i>';
    var copyCommandLine = '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy command line to clipboard" additional-info=' + btoa(additionalInfo['command_line']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i>';
    var copySession = '<i class="fas fa fa-clipboard" data-toggle="tooltip" title="Copy session to clipboard" additional-info=' + btoa(additionalInfo['session']) + ' style="cursor: pointer;" onclick=support_scripts[\"apollo_copy_additional_info_to_clipboard\"](this)></i>';
    var row_style = "";
     var cell_style = {"value": "white-space: normal;"};
    rows.push({"": copyIntegrity, "name": "Integrity Level", "value": additionalInfo['integrity_level'], "row-style": row_style, "cell-style": cell_style});
    rows.push({"": copyProcess, "name": "Process Path", "value": additionalInfo["file_path"], "row-style": row_style, "cell-style": cell_style});
    rows.push({"": copyCommandLine, "name": "Command Line", "value": additionalInfo["command_line"], "row-style": row_style, "cell-style": cell_style});
    rows.push({"": copySession, "name": "Desktop Session", "value": additionalInfo["session"], "row-style": row_style, "cell-style": cell_style});
    
    var output = support_scripts['apollo_create_table']([{"name":"", "size":"2em"},{"name":"name", "size":"10em"},{"name":"value", "size":"30em"}], rows);

    var uniqueNameId = '#' + uniqueName;
    var modalBody = uniqueNameId + '_body';
    var modalTitle = uniqueNameId + '_title';
    var header = "Additional Details on " + additionalInfo['name'] + " (PID: " + additionalInfo['pid'] + ")";
    $(modalBody).html(output);
    $(modalTitle).html(header);
    $(modalBody + ' > pre:last').css("word-wrap", "break-word");
    $(modalBody + ' > pre:last').css("white-space", "pre-wrap");
    $(uniqueNameId).modal('show');
}