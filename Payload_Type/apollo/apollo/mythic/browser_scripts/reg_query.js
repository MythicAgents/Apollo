function(task, responses){
    const rows = [];
    const messages = [];
    let sawBrowser = false;
    const joinPath = (parent, name) => parent ? parent.replace(/\\+$/, "") + "\\" + name : name;
    const queryPath = path => {
        const parts = path.split("\\");
        const hive = parts.shift().replace(/:$/, "");
        return hive + ":\\" + parts.join("\\");
    };
    const addRow = (entry, parentPath) => {
        const metadata = entry.metadata || {};
        const isKey = entry.can_have_children === true;
        const value = metadata.value == null ? "" : String(metadata.value);
        const path = isKey ? joinPath(parentPath, entry.name) : parentPath;
        rows.push({
            "rowStyle": {},
            "query": {"button": {
                "name": "query",
                "type": "task",
                "startIcon": "list",
                "disabled": !isKey,
                "ui_feature": "reg_query",
                "parameters": queryPath(path),
                "cellStyle": {},
            }},
            "name": {"plaintext": entry.name, "cellStyle": {}},
            "type": {"plaintext": metadata.type || (isKey ? "key" : ""), "cellStyle": {}},
            "value": {"plaintext": value, "copyIcon": !isKey && value.length > 0, "cellStyle": {}},
        });
    };

    for (const response of responses) {
        if (!response || !response.trim()) {
            continue;
        }
        let data;
        try {
            data = JSON.parse(response);
        } catch (error) {
            messages.push(response);
            continue;
        }
        if (!data || data.browser_name !== "registry_browser" || !Array.isArray(data.entries)) {
            messages.push(response);
            continue;
        }
        sawBrowser = true;
        for (const entry of data.entries) {
            const parentPath = entry.parent_path || "";
            if (Array.isArray(entry.children)) {
                const path = joinPath(parentPath, entry.name);
                for (const child of entry.children) {
                    addRow(child, path);
                }
            } else {
                addRow(entry, parentPath);
            }
        }
    }

    if ((task.status || "").includes("error")) {
        return {"plaintext": messages.join("") || "Registry query failed."};
    }
    if (messages.length > 0) {
        return {"plaintext": messages.join("")};
    }
    if (!sawBrowser) {
        return {"plaintext": "No response yet from agent..."};
    }
    return {"table": [{
        "headers": [
            {"plaintext": "query", "type": "button", "cellStyle": {}, "width": 120, "disableSort": true},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "type", "type": "string", "cellStyle": {}, "width": 100},
            {"plaintext": "value", "type": "string", "cellStyle": {}, "fillWidth": true},
        ],
        "rows": rows,
        "title": task.display_params,
    }]};
}
