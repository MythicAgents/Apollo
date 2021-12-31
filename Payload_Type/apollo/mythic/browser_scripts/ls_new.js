function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        // let folder = {
        //             backgroundColor: "rgb(248, 240, 120)",
        //             color: "black"
        //         };
        var archiveFormats = [".a",".ar",".cpio",".shar",".LBR",".lbr",".mar",".sbx",".tar",".bz2",".F",".gz",".lz",".lz4",".lzma",".lzo",".rz",".sfark",".sz",".?Q?",".?Z?",".xz",".z",".Z",".zst",".??",".7z",".s7z",".ace",".afa",".alz",".apk",".arc",".arc",".arj",".b1",".b6z",".ba",".bh",".cab",".car",".cfs",".cpt",".dar",".dd",".dgc",".ear",".gca",".ha",".hki",".ice",".jar",".kgb",".lzh",".lzx",".pak",".pak",".parti",".paq6",".pea",".pim",".pit",".qda",".rar",".rk",".sda",".sea",".sen",".sfx",".shk",".sit",".sitx",".sqx",".tar",".tbz2",".uc",".uca",".uha",".war",".wim",".xar",".xp3",".yz1",".zip",".zoo",".zpaq",".zz",".ecc",".ecsbx",".par",".par2",".rev"];
        var diskImages = [".dmg", ".iso", ".vmdk"];
        var wordDocs = [".doc", ".docx", ".dotm", ".dot", ".wbk", ".docm", ".dotx", ".docb"];
        var excelDocs = [".csv",".xls", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlmx", ".xlmt"];
        var powerPoint = [".ppt", ".pptx", ".potx", ".ppsx", ".thmx", ".pot", ".pps"];
        var pdfExt = [".pdf"];
        var dbExt = [".db", ".sql", ".psql"];
        var keyFiles = [".pem", ".ppk", ".cer", ".pvk", ".pfx"];
        var codeFiles = [".config", ".ps1", ".psm1", ".psd1", ".vbs", ".js", ".py", ".pl", ".rb", ".go", ".xml", ".html", ".css", ".sh", ".bash", ".yaml", ".yml", ".c", ".cpp", ".h", ".hpp", ".cs", ".sln", ".csproj"];
        var imageFiles = [".2000",".ani",".anim",".apng",".art",".avif",".bmp",".bpg",".bsave",".cal",".cin",".cpc",".cpt",".cur",".dds",".dpx",".ecw",".ep",".exr",".fits",".flic",".flif",".fpx",".gif",".hdr",".hdri",".hevc",".icer",".icns",".ico",".ics",".ilbm",".it",".jbig",".jbig2",".jng",".jpeg",".jpeg",".jpeg",".jpeg",".jpeg",".jpeg",".jpeg",".jpeg",".kra",".logluv",".ls",".miff",".mng",".nrrd",".pam",".pbm",".pcx",".pgf",".pgm",".pictor",".png",".pnm",".ppm",".psb",".psd",".psp",".qtvr",".ras",".rgbe",".sgi",".tga",".tiff",".tiff",".tiff",".tiff",".ufo",".ufp",".wbmp",".webp",".xbm",".xcf",".xl",".xpm",".xr",".xs",".xt",".xwd"];
        let file = {};
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "actions", "type": "button", "cellStyle": {}, "width": 14},
            {"plaintext": "Task", "type": "button", "cellStyle": {}, "width": 10},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "size", "type": "size", "cellStyle": {}},
            {"plaintext": "owner", "type": "string", "cellStyle": {}},
            {"plaintext": "creation date", "type": "string", "cellStyle": {}},
            {"plaintext": "last modified", "type": "string", "cellStyle": {}},
            {"plaintext": "last accessed", "type": "string", "cellStyle": {}},
        ];
        let tableHeader = "";
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
            let ls_path = "";
            if(data["parent_path"] === "/"){
                ls_path = data["parent_path"] + data["name"];
            }else{
                ls_path = data["parent_path"] + "\\" + data["name"];
            }
            tableHeader = "Contents of " + ls_path;
            for(let j = 0; j < data["files"].length; j++){
                let finfo = data["files"][j];
                let buttonSettings = {};
                let startIcon = "";
                let startIconHoverText = "";
                let startIconColor = "";
                if (finfo["is_file"]) {
                    var fileExt = "." + finfo['name'].split(".").slice(-1)[0].toLowerCase();
                    if (archiveFormats.includes(fileExt)) {
                        startIcon = 'archive';
                        startIconHoverText = "Archive File";
                        startIconColor = "goldenrod";
                    } else if (diskImages.includes(fileExt)) {
                        startIcon = 'diskimage';
                        startIconHoverText = "Disk Image";
                        startIconColor = "goldenrod";
                    } else if (wordDocs.includes(fileExt)) {
                        startIcon = 'word';
                        startIconHoverText = "Microsoft Word Document";
                        startIconColor = "cornflowerblue";
                    } else if (excelDocs.includes(fileExt)){
                        startIcon = 'excel';
                        startIconHoverText = "Microsoft Excel Document";
                        startIconColor = "darkseagreen";
                    } else if (powerPoint.includes(fileExt)) {
                        startIcon = 'powerpoint';
                        startIconHoverText = "Microsoft PowerPoint Document";
                        startIconColor = "indianred";
                    } else if (pdfExt.includes(fileExt)){
                        startIcon = 'pdf';
                        startIconHoverText = "Adobe Acrobat PDF";
                        startIconColor = "orangered";
                    } else if (dbExt.includes(fileExt)) {
                        startIcon = 'database';
                        startIconHoverText = "Database File Format";
                    } else if (keyFiles.includes(fileExt)) {
                        startIcon = 'key';
                        startIconHoverText = "Key Credential Material";
                    } else if (codeFiles.includes(fileExt)) {
                        startIcon = 'code';
                        startIconHoverText = "Source Code";
                        startIconColor = "rgb(25,142,117)";
                    } else if (imageFiles.includes(fileExt)) {
                        startIcon = "image";
                        startIconHoverText = "Image File";
                    }
                    buttonSettings = {
                        "button": {
                            "name": "cat",
                            "type": "task",
                            "ui_feature": "cat",
                            "parameters": finfo["full_name"],
                        },
                        "cellStyle": {},
                    }
                } else {
                    startIcon = "openFolder";
                    startIconHoverText = "Directory";
                    startIconColor = "rgb(241,226,0)";
                    buttonSettings = {"button": {
                        "name": "ls",
                        "type": "task",
                        "ui_feature": "file_browser:list",
                        "parameters": finfo["full_name"],
                        "startIcon": "list",
                        },
                        "cellStyle": {},
                    }
                }
                let row = {
                    "rowStyle": {}, //data["files"][j]["is_file"] ? file:  folder,
                    "actions": {
                        "button": {
                        "startIcon": "list",
                        "name": "Actions",
                        "type": "menu",
                        "value": [
                            {
                                "name": "Extended Attributes",
                                "type": "dictionary",
                                "value": {"Extended Attributes": finfo["extended_attributes"]},
                                "leftColumnTitle": "Extended Attributes",
                                "rightColumnTitle": "Values",
                                "title": "Viewing Extended Attributes for " + finfo["name"],
                                "startIcon": "list"
                            },
                            {
                                "name": "Access Control Entries",
                                "type": "dictionary",
                                "value": {"acls": finfo["permissions"]},
                                "leftColumnTitle": "acls",
                                "rightColumnTitle": "Values",
                                "title": "Viewing Acess Control Lists for " + data["files"][j]["name"],
                                "startIcon": "list",
                            },
                            {
                                "name": "Download",
                                "type": "task",
                                "disabled": !finfo["is_file"],
                                "ui_feature": "file_browser:download",
                                "parameters": finfo["full_name"],
                                "startIcon": "download"
                            },
                            {
                                "name": "Delete",
                                "type": "task",
                                "ui_feature": "file_browser:remove",
                                "parameters": finfo["full_name"],
                                "startIcon": "delete"
                            },
                        ]
                    }},
                    "Task": buttonSettings,
                    "name": {
                        "plaintext": data["files"][j]["name"],
                        "cellStyle": {},
                        "startIcon": startIcon,
                        "startIconHoverText": startIconHoverText,
                        "startIconColor": startIconColor
                    },
                    "size": {"plaintext": data["files"][j]["size"], "cellStyle": {}},
                    "owner": {"plaintext": data["files"][j]["owner"], "cellStyle": {}},
                    "creation date": {"plaintext": data["files"][j]["creation_date"], "cellStyle": {}},
                    "last modified": {"plaintext": data["files"][j]["modify_time"], "cellStyle": {}},
                    "last accessed": {"plaintext": data["files"][j]["access_time"], "cellStyle": {}},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": tableHeader,
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}