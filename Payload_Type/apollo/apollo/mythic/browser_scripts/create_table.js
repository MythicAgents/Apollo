function(headers, data){
  let output = "<table style='width:100%;color:white' class='table-striped border border-dark shadow table-dark table-condensed'>";
  output += "<tr>";

  for(let i = 0; i < headers.length; i++){
    output += "<th style='white-space: nowrap;overflow: hidden;text-overflow: ellipsis;background-color:#393485;color:white;height:40px;text-align:left;padding:0px 0px 0px 20px;width:" + headers[i]['size'] + ";max-width:"+headers[i]['size']+"' onclick=\"sort_table(this)\">" + headers[i]['name'].toUpperCase() + "</th>";
  }
  output += "</tr>";
  for(let i = 0; i < data.length; i++){
    output += "<tr style='text-align:left;" + data[i]['row-style'] + "'>";
    for(let j = 0; j < headers.length; j++){
     if(data[i]['cell-style'].hasOwnProperty(headers[j]["name"])){
      output += "<td onmouseover='this.style.overflow=\"visible\";' onmouseout='this.style.overflow=\"hidden\";' style='padding:0px 0px 0px 20px;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;" + data[i]['cell-style'][headers[j]['name']] + "'>" + data[i][headers[j]['name']] + "</td>";  
      // output += "<td onmouseover='this.style.overflow=\"visible\";' onmouseout='this.style.overflow=\"hidden\";' style='padding:0px 0px 0px 20px;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;max-width:" + headers[j]['size'] + ";" +"width:" + headers[j]['size'] + ";" + data[i]['cell-style'][headers[j]['name']] + "'>" + data[i][headers[j]['name']] + "</td>";
     }
     else{
      output += "<td onmouseover='this.style.overflow=\"visible\";' onmouseout='this.style.overflow=\"hidden\";' style='padding:0px 0px 0px 20px;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;'>" + data[i][headers[j]['name']] + "</td>";  
      // output += "<td onmouseover='this.style.overflow=\"visible\";' onmouseout='this.style.overflow=\"hidden\";' style='padding:0px 0px 0px 20px;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;max-width:" + headers[j]['size'] + ";" +"width:"+ headers[j]['size']+"'>" + data[i][headers[j]['name']] + "</td>";
     }
    }
    output += "</tr>";
  }
  output += "</table>";
  return output;
}