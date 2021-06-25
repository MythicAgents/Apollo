function(integrityLevel){
    switch(integrityLevel)
    {
        case "S-1-16-0":
        {
            return "UNTRUSTED_MANDATORY_LEVEL";
        }
        case "S-1-16-4096":
        {
            return "LOW_MANDATORY_LEVEL";
        }
        case "S-1-16-8192":
        {
            return "MEDIUM_MANDATORY_LEVEL";
        }
        case "S-1-16-8448":
        {
            return "MEDIUM_PLUS_MANDATORY_LEVEL";
        }
        case "S-1-16-12288":
        {
            return "HIGH_MANDATORY_LEVEL";
        }
        case "S-1-16-16384":
        {
            return "SYSTEM_MANDATORY_LEVEL";
        }
        case "S-1-16-20480":
        {
            return "PROTECTED_PROCESS_MANDATORY_LEVEL";
        }
        case "S-1-16-28672":
        {
            return "SECURE_PROCESS_MANDATORY_LEVEL";
        }
        default:
            return ""
    }
}