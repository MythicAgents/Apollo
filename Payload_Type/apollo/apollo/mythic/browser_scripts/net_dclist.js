function(task, responses){
  if(task.status.includes("error")){
      const combined = responses.reduce( (prev, cur) => {
          return prev + cur;
      }, "");
      return {'plaintext': combined};
  }else if(responses.length > 0){
      let file = {};
      let data = "";
      let rows = [];
      let tableTitle = "Domain Controllers";
      
      let headers = [
          {"plaintext": "shares", "type": "button", "startIcon": "list", "cellStyle": {}, "width": 100},
          {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
          {"plaintext": "domain", "type": "string", "cellStyle": {}, "fillWidth": true},
          {"plaintext": "forest", "type": "string", "cellStyle": {}, "fillWidth": true},
          {"plaintext": "ip", "type": "string", "cellStyle": {}, "fillWidth": true},
          {"plaintext": "os", "type": "string", "cellStyle": {}, "fillWidth": true},
      ];
      for(let i = 0; i < responses.length; i++)
      {
          try{
              data = JSON.parse(responses[i]);
          }catch(error){
              console.log(error);
             const combined = responses.reduce( (prev, cur) => {
                  return prev + cur;
              }, "");
              return {'plaintext': combined};
          }
          
          for(let j = 0; j < data.length; j++){
              let jinfo = data[j];
              let nameField = {"plaintext": jinfo["computer_name"], "copyIcon": true, "cellStyle": {}};
              if (jinfo["global_catalog"]) {
                // "endIcon": "database", "endIconHoverText": "Global Catalog",
                nameField["endIcon"] = "database";
                nameField["endIconHoverText"] = "Global Catalog";
              }
              let row = {
                  // If process name is BAD, then highlight red.
                  "rowStyle": {},
                  "shares": {"button": {
                      "name": "shares",
                      "type": "task",
                      "ui_feature": "net_shares",
                      "parameters": jinfo["computer_name"],
                      "cellStyle": {},
                  }},
                  "name": nameField,
                  "domain": {"plaintext": jinfo["domain"], "cellStyle": {}},
                  "forest": {"plaintext": jinfo["forest"], "cellStyle": {}},
                  "ip": {"plaintext": jinfo["ip_address"], "copyIcon": true, "cellStyle": {}},
                  "os": {"plaintext": jinfo["os_version"], "cellStyle": {}}
              };
              rows.push(row);
          }
      }
      return {"table":[{
          "headers": headers,
          "rows": rows,
          "title": tableTitle,
      }]};
  }else{
      // this means we shouldn't have any output
      return {"plaintext": "Not response yet from agent..."}
  }
}