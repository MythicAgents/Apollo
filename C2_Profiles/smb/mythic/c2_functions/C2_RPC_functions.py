from mythic_c2_container.MythicRPC import *
import sys
import json
from pathlib import Path
import netifaces

# request is a dictionary: {"action": func_name, "message": "the input",  "task_id": task id num}
# must return an RPCResponse() object and set .status to an instance of RPCStatus and response to str of message
async def test(request):
    response = RPCResponse()
    response.status = RPCStatus.Success
    response.response = "hello"
    resp = await MythicRPC().execute("create_event_message", message="Test message", warning=False)
    return response


# The opsec function is called when a payload is created as a check to see if the parameters supplied are good
# The input for "request" is a dictionary of:
# {
#   "action": "opsec",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def opsec(request):
    # if request["parameters"]["callback_host"] == "https://domain.com":
    #     return {"status": "error", "error": "Callback Host is set to default of https://domain.com!\n"}
    # if request["parameters"]["callback_host"].count(":") == 2:
    #     return {"status": "error", "error": f"Callback Host specifies a port ({request['parameters']['callback_host']})! This should be omitted and specified in the Callback Port parameter.\n"}
    # if "https" in request["parameters"]["callback_host"] and request["parameters"]["callback_port"] not in ["443", "8443", "7443"]:
    #     return {"status": "success", "message": f"Mismatch in callback host: HTTPS specified, but port {request['parameters']['callback_port']}, is not standard HTTPS port\n"}
    return {"status": "success", "message": "Basic OPSEC Check Passed\n"}


# The config_check function is called when a payload is created as a check to see if the parameters supplied
#   to the agent match up with what's in the C2 profile
# The input for "request" is a dictionary of:
# {
#   "action": "config_check",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
#
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def config_check(request):
    try:
        # with open("../c2_code/config.json") as f:
        #     config = json.load(f)
        #     possible_ports = []
        #     for inst in config["instances"]:
        #         possible_ports.append({"port": inst["port"], "use_ssl": inst["use_ssl"]})
        #         if str(inst["port"]) == str(request["parameters"]["callback_port"]):
        #             if "https" in request["parameters"]["callback_host"] and not inst["use_ssl"]:
        #                 message = f"C2 Profile container is configured to NOT use SSL on port {inst['port']}, but the callback host for the agent is using https, {request['parameters']['callback_host']}.\n\n"
        #                 message += "This means there should be the following connectivity for success:\n"
        #                 message += f"Agent via SSL to {request['parameters']['callback_host']} on port {inst['port']}, then redirection to C2 Profile container WITHOUT SSL on port {inst['port']}"
        #                 return {"status": "error", "error": message}
        #             elif "https" not in request["parameters"]["callback_host"] and inst["use_ssl"]:
        #                 message = f"C2 Profile container is configured to use SSL on port {inst['port']}, but the callback host for the agent is using http, {request['parameters']['callback_host']}.\n\n"
        #                 message += "This means there should be the following connectivity for success:\n"
        #                 message += f"Agent via NO SSL to {request['parameters']['callback_host']} on port {inst['port']}, then redirection to C2 Profile container WITH SSL on port {inst['port']}"
        #                 return {"status": "error", "error": message}
        #             else:
        #                 message = f"C2 Profile container and agent configuration match port, {inst['port']}, and SSL expectations.\n"
        #                 return {"status": "success", "message": message}
        #     message = f"Failed to find port, {request['parameters']['callback_port']}, in C2 Profile configuration\n"
        #     message += f"This could indicate the use of a redirector, or a mismatch in expected connectivity.\n\n"
        #     message += f"This means there should be the following connectivity for success:\n"
        #     if "https" in request["parameters"]["callback_host"]:
        #         message += f"Agent via HTTPS on port {request['parameters']['callback_port']} to {request['parameters']['callback_host']} (should be a redirector).\n"
        #     else:
        #         message += f"Agent via HTTP on port {request['parameters']['callback_port']} to {request['parameters']['callback_host']} (should be a redirector).\n"
        #     if len(possible_ports) == 1:
        #         message += f"Redirector then forwards request to C2 Profile container on port, {possible_ports[0]['port']}, {'WITH SSL' if possible_ports[0]['use_ssl'] else 'WITHOUT SSL'}"
        #     else:
        #         message += f"Redirector then forwards request to C2 Profile container on one of the following ports: {json.dumps(possible_ports)}\n"
        #     if "https" in request["parameters"]["callback_host"]:
        #         message += f"\nAlternatively, this might mean that you want to do SSL but are not using SSL within your C2 Profile container.\n"
        #         message += f"To add SSL to your C2 profile:\n"
        #         message += f"\t1. Go to the C2 Profile page\n"
        #         message += f"\t2. Click configure for the http profile\n"
        #         message += f"\t3. Change 'use_ssl' to 'true' and make sure the port is {request['parameters']['callback_port']}\n"
        #         message += f"\t4. Click to stop the profile and then start it again\n"
        return {"status": "success", "message": "gogo"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# The redirect_rules function is called on demand by an operator to generate redirection rules for a specific payload
# The input for "request" is a dictionary of:
# {
#   "action": "redirect_rules",
#   "parameters": {
#       "param_name": "param_value",
#       "param_name2: "param_value2",
#   }
# }
# This function should return one of two things:
#   For success: {"status": "success", "message": "your success message here" }
#   For error: {"status": "error", "error": "your error message here" }
async def redirect_rules(request):
    output = "mod_rewrite rules generated from @AndrewChiles' project https://github.com/threatexpress/mythic2modrewrite:\n"
    # Get User-Agent
    errors = ""
    ua = ''
    uris = []
    if "headers" in request['parameters']:
        for header in request['parameters']["headers"]:
            if header["key"] == "User-Agent":
                ua = header["value"]
    else:
        errors += "[!] User-Agent Not Found\n"
    # Get all profile URIs
    if "get_uri" in request['parameters']:
        uris.append("/" + request['parameters']["get_uri"])
    else:
        errors += "[!] No GET URI found\n"
    if "post_uri" in request['parameters']:
        uris.append("/" + request['parameters']["post_uri"])
    else:
        errors += "[!] No POST URI found\n"
    # Create UA in modrewrite syntax. No regex needed in UA string matching, but () characters must be escaped
    ua_string = ua.replace('(', '\(').replace(')', '\)')
    # Create URI string in modrewrite syntax. "*" are needed in regex to support GET and uri-append parameters on the URI
    uris_string = ".*|".join(uris) + ".*"
    try:
        interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        c2_rewrite_template = """RewriteRule ^.*$ "{c2server}%{{REQUEST_URI}}" [P,L]"""
        c2_rewrite_output = []
        with open("../c2_code/config.json") as f:
            config = json.load(f)
            for inst in config["instances"]:
                c2_rewrite_output.append(c2_rewrite_template.format(
                    c2server=f"https://{address}:{inst['port']}" if inst["use_ssl"] else f"http://{address}:{inst['port']}"
                ))
    except Exception as e:
        errors += "[!] Failed to get C2 Profile container IP address. Replace 'c2server' in HTACCESS rules with correct IP\n"
        c2_rewrite_output = ["""RewriteRule ^.*$ "{c2server}%{{REQUEST_URI}}" [P,L]"""]
    htaccess_template = '''
########################################
## .htaccess START
RewriteEngine On
## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Logic: If a requested URI AND the User-Agent matches, proxy the connection to the Teamserver
## Consider adding other HTTP checks to fine tune the check.  (HTTP Cookie, HTTP Referer, HTTP Query String, etc)
## Refer to http://httpd.apache.org/docs/current/mod/mod_rewrite.html
## Only allow GET and POST methods to pass to the C2 server
RewriteCond %{{REQUEST_METHOD}} ^(GET|POST) [NC]
## Profile URIs
RewriteCond %{{REQUEST_URI}} ^({uris})$
## Profile UserAgent
RewriteCond %{{HTTP_USER_AGENT}} "{ua}"
{c2servers}
## Redirect all other traffic here
RewriteRule ^.*$ {redirect}/? [L,R=302]
## .htaccess END
########################################
    '''
    htaccess = htaccess_template.format(uris=uris_string, ua=ua_string, c2servers="\n".join(c2_rewrite_output), redirect="redirect")
    output += "\tReplace 'redirect' with the http(s) address of where non-matching traffic should go, ex: https://redirect.com\n"
    output += f"\n{htaccess}"
    if errors != "":
        return {"status": "error", "error": errors}
    else:
        return {"status": "success", "message": output}