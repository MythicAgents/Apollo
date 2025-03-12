function(task, responses) {
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => {
            return prev + cur;
        }, "");
        return { 'plaintext': combined };
    }
    if (responses.length > 0) {
        let rows = [];
        let data = [];
        let headers = [
            { "plaintext": "client", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "service", "type": "string", "cellStyle": {}, "fillWidth": true },
            { "plaintext": "Mythic Store", "type": "string", "cellStyle": {}, width: 170 },
            { "plaintext": "Ticket", "type": "string", "fillWidth": true}
        ];
        try {
            data = JSON.parse(responses[0]);
        } catch (error) {
            console.log(error);
            const combined = responses.reduce((prev, cur) => {
                return prev + cur;
            }, "");
            return { 'plaintext': combined };
        }
        let jinfo = data;
        let row = {
            "client": { "plaintext": jinfo["client_fullname"], "cellStyle": {}, copyIcon: true },
            "service": { "plaintext": jinfo["service_fullname"], "cellStyle": {}, copyIcon: true },
            "Ticket": {"plaintext": jinfo["ticket"], copyIcon: true},
            "Mythic Store": {
                "startIcon": responses.length >= 2 && responses[1].includes("Added credential") ? "check" : responses.length >=2 && responses[1].includes("Failed") ? "x" : "",
                "startIconColor": responses.length >= 2 && responses[1].includes("Added credential") ? "success" : responses.length >=2 && responses[1].includes("Failed") ? "error" : "",
            }
        };
        rows.push(row);

        return {
            "table": [{
                "headers": headers,
                "rows": rows,
                "title": "Extracted Kerberos Tickets",
            }]
        };
    }

    // this means we shouldn't have any output
    return { "plaintext": "Not response yet from agent..." }

}
