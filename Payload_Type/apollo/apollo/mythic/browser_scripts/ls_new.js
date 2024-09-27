function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        // Known file types
        const FileType = Object.freeze({
            ARCHIVE: 'archive',
            DISKIMAGE: 'diskimage',
            WORD: 'word',
            EXCEL: 'excel',
            POWERPOINT: 'powerpoint',
            PDF: 'pdf',
            DATABASE: 'db',
            KEYMATERIAL: 'keymaterial',
            SOURCECODE: 'sourcecode',
            IMAGE: 'image'
        });

        // Mappings for file extensions to file types
        const fileExtensionMappings = new Map([
            // Archive file extensions
            [".a", FileType.ARCHIVE],
            [".ar", FileType.ARCHIVE],
            [".cpio", FileType.ARCHIVE],
            [".shar", FileType.ARCHIVE],
            [".LBR", FileType.ARCHIVE],
            [".lbr", FileType.ARCHIVE],
            [".mar", FileType.ARCHIVE],
            [".sbx", FileType.ARCHIVE],
            [".tar", FileType.ARCHIVE],
            [".bz2", FileType.ARCHIVE],
            [".F", FileType.ARCHIVE],
            [".gz", FileType.ARCHIVE],
            [".lz", FileType.ARCHIVE],
            [".lz4", FileType.ARCHIVE],
            [".lzma", FileType.ARCHIVE],
            [".lzo", FileType.ARCHIVE],
            [".rz", FileType.ARCHIVE],
            [".sfark", FileType.ARCHIVE],
            [".sz", FileType.ARCHIVE],
            [".?Q?", FileType.ARCHIVE],
            [".?Z?", FileType.ARCHIVE],
            [".xz", FileType.ARCHIVE],
            [".z", FileType.ARCHIVE],
            [".Z", FileType.ARCHIVE],
            [".zst", FileType.ARCHIVE],
            [".??", FileType.ARCHIVE],
            [".7z", FileType.ARCHIVE],
            [".s7z", FileType.ARCHIVE],
            [".ace", FileType.ARCHIVE],
            [".afa", FileType.ARCHIVE],
            [".alz", FileType.ARCHIVE],
            [".apk", FileType.ARCHIVE],
            [".arc", FileType.ARCHIVE],
            [".arc", FileType.ARCHIVE],
            [".arj", FileType.ARCHIVE],
            [".b1", FileType.ARCHIVE],
            [".b6z", FileType.ARCHIVE],
            [".ba", FileType.ARCHIVE],
            [".bh", FileType.ARCHIVE],
            [".cab", FileType.ARCHIVE],
            [".car", FileType.ARCHIVE],
            [".cfs", FileType.ARCHIVE],
            [".cpt", FileType.ARCHIVE],
            [".dar", FileType.ARCHIVE],
            [".dd", FileType.ARCHIVE],
            [".dgc", FileType.ARCHIVE],
            [".ear", FileType.ARCHIVE],
            [".gca", FileType.ARCHIVE],
            [".ha", FileType.ARCHIVE],
            [".hki", FileType.ARCHIVE],
            [".ice", FileType.ARCHIVE],
            [".jar", FileType.ARCHIVE],
            [".kgb", FileType.ARCHIVE],
            [".lzh", FileType.ARCHIVE],
            [".lzx", FileType.ARCHIVE],
            [".pak", FileType.ARCHIVE],
            [".pak", FileType.ARCHIVE],
            [".parti", FileType.ARCHIVE],
            [".paq6", FileType.ARCHIVE],
            [".pea", FileType.ARCHIVE],
            [".pim", FileType.ARCHIVE],
            [".pit", FileType.ARCHIVE],
            [".qda", FileType.ARCHIVE],
            [".rar", FileType.ARCHIVE],
            [".rk", FileType.ARCHIVE],
            [".sda", FileType.ARCHIVE],
            [".sea", FileType.ARCHIVE],
            [".sen", FileType.ARCHIVE],
            [".sfx", FileType.ARCHIVE],
            [".shk", FileType.ARCHIVE],
            [".sit", FileType.ARCHIVE],
            [".sitx", FileType.ARCHIVE],
            [".sqx", FileType.ARCHIVE],
            [".tar", FileType.ARCHIVE],
            [".tbz2", FileType.ARCHIVE],
            [".uc", FileType.ARCHIVE],
            [".uca", FileType.ARCHIVE],
            [".uha", FileType.ARCHIVE],
            [".war", FileType.ARCHIVE],
            [".wim", FileType.ARCHIVE],
            [".xar", FileType.ARCHIVE],
            [".xp3", FileType.ARCHIVE],
            [".yz1", FileType.ARCHIVE],
            [".zip", FileType.ARCHIVE],
            [".zoo", FileType.ARCHIVE],
            [".zpaq", FileType.ARCHIVE],
            [".zz", FileType.ARCHIVE],
            [".ecc", FileType.ARCHIVE],
            [".ecsbx", FileType.ARCHIVE],
            [".par", FileType.ARCHIVE],
            [".par2", FileType.ARCHIVE],
            [".rev", FileType.ARCHIVE],

            // Disk image file extensions
            [".dmg", FileType.DISKIMAGE],
            [".iso", FileType.DISKIMAGE],
            [".vmdk", FileType.DISKIMAGE],

            // Word documents
            [".doc", FileType.WORD],
            [".docx", FileType.WORD],
            [".dotm", FileType.WORD],
            [".dot", FileType.WORD],
            [".wbk", FileType.WORD],
            [".docm", FileType.WORD],
            [".dotx", FileType.WORD],
            [".docb", FileType.WORD],

            // Excel documents
            [".csv", FileType.EXCEL],
            [".xls", FileType.EXCEL],
            [".xlsx", FileType.EXCEL],
            [".xlsm", FileType.EXCEL],
            [".xltx", FileType.EXCEL],
            [".xltm", FileType.EXCEL],
            [".xlmx", FileType.EXCEL],
            [".xlmt", FileType.EXCEL],

            // Powerpoint documents
            [".ppt", FileType.POWERPOINT],
            [".pptx", FileType.POWERPOINT],
            [".potx", FileType.POWERPOINT],
            [".ppsx", FileType.POWERPOINT],
            [".thmx", FileType.POWERPOINT],
            [".pot", FileType.POWERPOINT],
            [".pps", FileType.POWERPOINT],

            // PDF documents
            [".pdf", FileType.PDF],

            // Database files
            [".db", FileType.DATABASE],
            [".sql", FileType.DATABASE],
            [".psql", FileType.DATABASE],

            // Key files
            [".pem", FileType.KEYMATERIAL],
            [".ppk", FileType.KEYMATERIAL],
            [".cer", FileType.KEYMATERIAL],
            [".pvk", FileType.KEYMATERIAL],
            [".pfx", FileType.KEYMATERIAL],

            // Source code files
           [".config", FileType.SOURCECODE],
           [".ps1", FileType.SOURCECODE],
           [".psm1", FileType.SOURCECODE],
           [".psd1", FileType.SOURCECODE],
           [".vbs", FileType.SOURCECODE],
           [".js", FileType.SOURCECODE],
           [".py", FileType.SOURCECODE],
           [".pl", FileType.SOURCECODE],
           [".rb", FileType.SOURCECODE],
           [".go", FileType.SOURCECODE],
           [".xml", FileType.SOURCECODE],
           [".html", FileType.SOURCECODE],
           [".css", FileType.SOURCECODE],
           [".sh", FileType.SOURCECODE],
           [".bash", FileType.SOURCECODE],
           [".yaml", FileType.SOURCECODE],
           [".yml", FileType.SOURCECODE],
           [".c", FileType.SOURCECODE],
           [".cpp", FileType.SOURCECODE],
           [".h", FileType.SOURCECODE],
           [".hpp", FileType.SOURCECODE],
           [".cs", FileType.SOURCECODE],
           [".sln", FileType.SOURCECODE],
           [".csproj", FileType.SOURCECODE],

            // Image files
           [".2000", FileType.IMAGE],
           [".ani", FileType.IMAGE],
           [".anim", FileType.IMAGE],
           [".apng", FileType.IMAGE],
           [".art", FileType.IMAGE],
           [".avif", FileType.IMAGE],
           [".bmp", FileType.IMAGE],
           [".bpg", FileType.IMAGE],
           [".bsave", FileType.IMAGE],
           [".cal", FileType.IMAGE],
           [".cin", FileType.IMAGE],
           [".cpc", FileType.IMAGE],
           [".cpt", FileType.IMAGE],
           [".cur", FileType.IMAGE],
           [".dds", FileType.IMAGE],
           [".dpx", FileType.IMAGE],
           [".ecw", FileType.IMAGE],
           [".ep", FileType.IMAGE],
           [".exr", FileType.IMAGE],
           [".fits", FileType.IMAGE],
           [".flic", FileType.IMAGE],
           [".flif", FileType.IMAGE],
           [".fpx", FileType.IMAGE],
           [".gif", FileType.IMAGE],
           [".hdr", FileType.IMAGE],
           [".hdri", FileType.IMAGE],
           [".hevc", FileType.IMAGE],
           [".icer", FileType.IMAGE],
           [".icns", FileType.IMAGE],
           [".ico", FileType.IMAGE],
           [".ics", FileType.IMAGE],
           [".ilbm", FileType.IMAGE],
           [".it", FileType.IMAGE],
           [".jbig", FileType.IMAGE],
           [".jbig2", FileType.IMAGE],
           [".jng", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".jpeg", FileType.IMAGE],
           [".kra", FileType.IMAGE],
           [".logluv", FileType.IMAGE],
           [".ls", FileType.IMAGE],
           [".miff", FileType.IMAGE],
           [".mng", FileType.IMAGE],
           [".nrrd", FileType.IMAGE],
           [".pam", FileType.IMAGE],
           [".pbm", FileType.IMAGE],
           [".pcx", FileType.IMAGE],
           [".pgf", FileType.IMAGE],
           [".pgm", FileType.IMAGE],
           [".pictor", FileType.IMAGE],
           [".png", FileType.IMAGE],
           [".pnm", FileType.IMAGE],
           [".ppm", FileType.IMAGE],
           [".psb", FileType.IMAGE],
           [".psd", FileType.IMAGE],
           [".psp", FileType.IMAGE],
           [".qtvr", FileType.IMAGE],
           [".ras", FileType.IMAGE],
           [".rgbe", FileType.IMAGE],
           [".sgi", FileType.IMAGE],
           [".tga", FileType.IMAGE],
           [".tiff", FileType.IMAGE],
           [".tiff", FileType.IMAGE],
           [".tiff", FileType.IMAGE],
           [".tiff", FileType.IMAGE],
           [".ufo", FileType.IMAGE],
           [".ufp", FileType.IMAGE],
           [".wbmp", FileType.IMAGE],
           [".webp", FileType.IMAGE],
           [".xbm", FileType.IMAGE],
           [".xcf", FileType.IMAGE],
           [".xl", FileType.IMAGE],
           [".xpm", FileType.IMAGE],
           [".xr", FileType.IMAGE],
           [".xs", FileType.IMAGE],
           [".xt", FileType.IMAGE],
           [".xwd", FileType.IMAGE],
        ]);

        // Mappings for file type to list entry styling
        const fileStyleMap = new Map([
            [FileType.ARCHIVE, {
                startIcon: "archive",
                startIconHoverText: "Archive File",
                startIconColor: "goldenrod",
            }],
            [FileType.DISKIMAGE, {
                startIcon: "diskimage",
                startIconHoverText: "Disk Image",
                startIconColor: "goldenrod",
            }],
            [FileType.WORD, {
                startIcon: "word",
                startIconHoverText: "Microsoft Word Document",
                startIconColor: "cornflowerblue",
            }],
            [FileType.EXCEL, {
                startIcon: 'excel',
                startIconHoverText: "Microsoft Excel Document",
                startIconColor: "darkseagreen",
            }],
            [FileType.POWERPOINT, {
                startIcon: 'powerpoint',
                startIconHoverText: "Microsoft PowerPoint Document",
                startIconColor: "indianred",
            }],
            [FileType.PDF, {
                startIcon: "pdf",
                startIconHoverText: "Adobe Acrobat PDF",
                startIconColor: "orangered",
            }],
            [FileType.DATABASE, {
                startIcon: 'database',
                startIconHoverText: "Database File Format",
            }],
            [FileType.KEYMATERIAL, {
                startIcon: 'key',
                startIconHoverText: "Key Credential Material",
            }],
            [FileType.SOURCECODE, {
                startIcon: 'code',
                startIconHoverText: "Source Code",
                startIconColor: "rgb(25,142,117)",
            }],
            [FileType.IMAGE, {
                startIcon: "image",
                startIconHoverText: "Image File",
            }]
        ]);

        let lookupEntryStyling = function(entry) {
            if (entry["is_file"]) {
                let fileExtension = "." + entry["name"].split(".").slice(-1)[0];
                let fileCategory = fileExtensionMappings.get(fileExtension);

                let defaultStyling = {
                    startIcon: "",
                    startIconHoverText: "",
                    startIconColor: "",
                };

                if (fileCategory !== undefined) {
                    return { ...defaultStyling, ...fileStyleMap.get(fileCategory) };
                } else {
                    return defaultStyling;
                }
            } else {
                return {
                    startIcon: "openFolder",
                    startIconHoverText: "Directory",
                    startIconColor: "rgb(241,226,0)",
                }
            }
        };

        let entrySubTaskAction = function(data, entry) {
            if (entry["is_file"]) {
                // TODO: Rewrite this to always pass the UNC path to the cat command.
                // Need to make sure the cat command is capable of handling UNC paths.
                let cat_parameters = "";
                if (entry["full_name"].includes(":")) {
                    cat_parameters = entry["full_name"];
                } else {
                    cat_parameters = "\\\\" + data["host"] + "\\" + entry["full_name"];
                }

                return {
                    name: "cat",
                    type: "task",
                    ui_feature: "cat",
                    parameters: cat_parameters,
                }
            } else {
                return {
                    name: "ls",
                    type: "task",
                    ui_feature: "file_browser:list",
                    startIcon: "list",
                    parameters: {
                            host: data["host"],
                            full_path: entry["full_name"],
                        }
                }
            }
        };

        let formattedResponse = {
            headers: [
                {
                    plaintext: "actions",
                    type: "button",
                    cellStyle: {},
                    width: 120,
                    disableSort: true,
                },
                {
                    plaintext: "Task",
                    type: "button",
                    cellStyle: {},
                    width: 70,
                    disableSort: true,
                },
                {
                    plaintext: "name",
                    type: "string",
                    fillWidth: true,
                    cellStyle: {},
                },
                {
                    plaintext: "size",
                    type: "size",
                    width: 100,
                    cellStyle: {},
                },
                {
                    plaintext: "owner",
                    type: "string",
                    fillWidth: true,
                    cellStyle: {},
                },
                {
                    plaintext: "created",
                    type: "string",
                    fillWidth: true,
                    cellStyle: {},
                },
                {
                    plaintext: "last modified",
                    type: "string",
                    fillWidth: true,
                    cellStyle: {},
                },
                {
                    plaintext: "last accessed",
                    type: "string",
                    fillWidth: true,
                    cellStyle: {},
                },
            ],
            title: "",
            rows: [],
        };



        let createFormattedRow = function(data, entry) {
            let entryStyling = lookupEntryStyling(entry);
            return {
                rowStyle: {},
                name: {
                    plaintext: entry["name"],
                    cellStyle: {},
                    startIcon: entryStyling.startIcon,
                    startIconHoverText: entryStyling.startIconHoverText,
                    startIconColor: entryStyling.startIconColor,
                },
                size: {
                    plaintext: entry["size"],
                    cellStyle: {},
                },
                owner: {
                    plaintext: entry["owner"],
                    cellStyle: {},
                },
                "created": {
                    plaintext: new Date(entry["creation_date"]).toLocaleString(),
                    cellStyle: {},
                },
                "last modified": {
                    plaintext: new Date(entry["modify_time"]).toLocaleString(),
                    cellStyle: {},
                },
                "last accessed": {
                    plaintext: new Date(entry["access_time"]).toLocaleString(),
                    cellStyle: {},
                },
                Task: {
                    button: entrySubTaskAction(data, entry),
                    cellStyle: {},
                },
                actions: {
                    button: {
                        startIcon: "list",
                        name: "Actions",
                        type: "menu",
                        value: [
                            {
                                name: "Extended Attributes",
                                title: "Viewing Extended Attributes for " + entry["name"],
                                type: "dictionary",
                                leftColumnTitle: "Extended Attributes",
                                rightColumnTitle: "Values",
                                startIcon: "list",
                                value: {
                                    "Extended Attributes": entry["extended_attributes"],
                                },
                            },
                            {
                                name: "Access Control Entries",
                                type: "table",
                                title: "Viewing Acess Control Lists for " + entry["name"],
                                leftColumnTitle: "acls",
                                rightColumnTitle: "Values",
                                startIcon: "list",
                                value: {
                                    headers: [
                                        {
                                            plaintext: "account",
                                            width: 400,
                                            type: "string",
                                        },
                                        {
                                            plaintext: "type",
                                            type: "string",
                                        },
                                        {
                                            plaintext: "rights",
                                            type: "string",
                                        },
                                        {
                                            plaintext: "inherited",
                                            type: "string",
                                        },
                                    ],
                                    rows: entry["permissions"].map((permValue) => ({
                                        account: {
                                            plaintext: permValue["account"],
                                        },
                                        type: {
                                            plaintext: permValue["type"],
                                        },
                                        rights: {
                                            plaintext: permValue["rights"],
                                        },
                                        inherited: {
                                            plaintext: permValue["is_inherited"].toString(),
                                        }
                                    })),
                                },
                            },
                            {
                                name: "Download",
                                type: "task",
                                disabled: !entry["is_file"],
                                startIcon: "download",
                                ui_feature: "file_browser:download",
                                parameters: {
                                        host: data["host"],
                                        full_path: entry["full_name"],
                                    }
                                ,
                            },
                            {
                                name: "Delete",
                                type: "task",
                                startIcon: "delete",
                                ui_feature: "file_browser:remove",
                                getConfirmation: true,
                                parameters: {
                                        host: data["host"],
                                        full_path: entry["full_name"],
                                    }
                                ,
                            },
                        ]
                    }
                }
            }
        };

        for (let i = 0; i < responses.length; i++) {
            let data = {};
            try {
                data = JSON.parse(responses[i]);
            } catch(error) {
                console.log(error);
               const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }

            let ls_path = "";
            if(data["parent_path"] === ""){
                ls_path = data["name"];
            }
            else if(data["parent_path"].endsWith("\\")){
                ls_path = data["parent_path"] + data["name"];
            }else{
                ls_path = data["parent_path"] + "\\" + data["name"];
            }

            //formattedResponse.title = "Contents of " + ls_path;

            if (data["is_file"]) {
                data["full_name"] = ls_path;
                formattedResponse.rows.push(createFormattedRow(data, data));
            } else {
                console.log("Length: " + data["files"].length);
                formattedResponse.rows = formattedResponse.rows.concat(
                    data["files"].map((entry) => createFormattedRow(data, entry))
                );
            }
        }

        return {table: [formattedResponse]};
    } else {
        return {"plaintext": "No response yet from agent..."}
    }
}
