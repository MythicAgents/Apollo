function(task, responses){
    var s = "<pre>";
    for(let i = 0; i < responses.length; i++)
    {
        try {
            var results = JSON.parse(responses[i]['response']);
            if (Array.isArray(results)) {
                console.log("unmanaged_injection.js: Response was an array!");
                console.log(results);
                for(let y = 0; y < results.length; y++)
                {
                    s += results[y] + "\n";
                }
            } else {
                console.log("unmanaged_injection.js: Response was not an array.");
                console.log(results);
                s += results + "\n";
            }
        } catch (err) {
            console.error("Error in unmanaged injection: " + err);
            console.log(responses[i]['response']);
            s += responses[i]['response'] + "\n";
        }
    }
    s += "</pre>";
    return s;
}