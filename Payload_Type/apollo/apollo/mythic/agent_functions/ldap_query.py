from mythic_container.MythicCommandBase import *
from mythic_container.MythicGoRPC.send_mythic_rpc_handle_agent_message_json import *
import json


class LdapQueryArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="query",
                cli_name="query",
                display_name="LDAP Query",
                type=ParameterType.String,
                description="The query to issue",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                    )
                ],
                default_value="",),
            CommandParameter(
                name="base",
                cli_name="base",
                display_name="LDAP Search Base",
                type=ParameterType.String,
                description="The ldap search base",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=1,
                    )
                ],
                default_value="",),
            CommandParameter(
                name="attributes",
                cli_name="attributes",
                display_name="Specific attributes to return",
                type=ParameterType.Array,
                description="Which attributes to return on matching entries",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=3,
                    )
                ],
                default_value=[],),
            CommandParameter(
                name="limit",
                cli_name="limit",
                display_name="Limit results",
                type=ParameterType.Number,
                description="Limit the number of results. 0 means don't limit",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=4,
                    )
                ],
                default_value=100,),
            CommandParameter(
                name="scope",
                cli_name="scope",
                display_name="Search Scope",
                type=ParameterType.ChooseOne,
                choices=["subtree", "onelevel", "base"],
                description="LDAP search scope",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=5,
                    )
                ],
                default_value="subtree",),
        ]


    async def parse_arguments(self):
        if self.command_line[0] == "{":
            data = json.loads(self.command_line)
            if "full_path" in data:
                metadata = data.get("metadata", {})
                if isinstance(metadata, list):
                    metadata = {x["Key"]: x["Value"] for x in metadata if "Key" in x and "Value" in x}
                file_dn = data.get("file", "")
                file_dn = file_dn.strip().strip('"') if isinstance(file_dn, str) else ""
                if file_dn.lower().startswith("ldap://"):
                    file_dn = file_dn[7:]
                file_dn_pieces = [x.strip() for x in file_dn.split(",") if x.strip()]
                path_remainder = ""
                path_value = data.get("path", "")
                if isinstance(path_value, str) and path_value and data["full_path"].startswith(path_value + ","):
                    path_remainder = data["full_path"][len(path_value) + 1:]
                path_remainder_pieces = [x.strip() for x in path_remainder.split(",") if x.strip()]
                dn = data.get("display_path") or metadata.get("target_dn") or metadata.get("distinguishedname") or metadata.get("DistinguishedName")
                if not dn and len(file_dn_pieces) > 1 and all("=" in x for x in file_dn_pieces):
                    dn = file_dn
                if not dn and len(path_remainder_pieces) > 1 and all("=" in x for x in path_remainder_pieces):
                    dn = path_remainder
                dn = dn or data["full_path"]
                if dn.lower().startswith("ldap://"):
                    dn = dn[7:]
                if dn == data["full_path"]:
                    dn_pieces = [x.strip() for x in dn.split(",") if x.strip()]
                    host_pieces = [x.strip() for x in data.get("host", "").split(",") if x.strip()]
                    lower_dn_pieces = [x.lower() for x in dn_pieces]
                    lower_host_pieces = [x.lower() for x in host_pieces]
                    lower_reversed_host_pieces = list(reversed(lower_host_pieces))
                    if len(host_pieces) > 0 and lower_dn_pieces[-len(host_pieces):] == lower_host_pieces:
                        dn = ",".join(dn_pieces)
                    elif len(host_pieces) > 0 and lower_dn_pieces[:len(host_pieces)] == lower_host_pieces:
                        dn = ",".join(list(reversed(dn_pieces[len(host_pieces):])) + host_pieces)
                    elif len(host_pieces) > 0 and lower_dn_pieces[:len(host_pieces)] == lower_reversed_host_pieces:
                        dn = ",".join(list(reversed(dn_pieces[len(host_pieces):])) + host_pieces)
                    elif len(host_pieces) > 0:
                        dn = ",".join(list(reversed(dn_pieces)) + host_pieces)
                    elif len(dn_pieces) > 0 and dn_pieces[0].lower().startswith("dc="):
                        dn = ",".join(reversed(dn_pieces))
                query = data["query"].strip().strip('"') if "query" in data and data["query"] else "(objectClass=*)"
                query_pieces = [x.strip() for x in query.split(",") if x.strip()]
                if not query.startswith("(") and len(query_pieces) > 0 and all("=" in x for x in query_pieces):
                    dn = query[7:] if query.lower().startswith("ldap://") else query
                    query = "(objectClass=*)"
                dn = ",".join([
                    "DC={}".format(piece.split("=", 1)[1].strip().upper())
                    if "=" in piece and piece.split("=", 1)[0].strip().lower() == "dc"
                    else piece.strip()
                    for piece in dn.split(",")
                    if piece.strip()
                ])
                self.add_arg("base", dn)
                self.add_arg("query", query)
                raw_attributes = data["attributes"] if "attributes" in data else ""
                if isinstance(raw_attributes, list):
                    search_attributes = raw_attributes
                else:
                    search_attributes = [x.strip() for x in raw_attributes.split(",") if x.strip()]
                if len(search_attributes) == 0:
                    search_attributes = ["cn", "samaccountname", "description", "member", "memberOf", "objectclass", "distinguishedname"]
                self.add_arg("attributes", search_attributes)
                self.add_arg("limit", data["limit"] if "limit" in data else 100)
                self.add_arg("scope", data["scope"] if "scope" in data else "onelevel")
                return
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Invalid command line arguments")


class LdapQuery(CommandBase):
    cmd = "ldap_query"
    needs_admin = False
    help_cmd = "ldap_query [key]"
    description = "Query ldap"
    version = 2
    author = "@its_a_feature_"
    argument_class = LdapQueryArguments
    attackmapping = []
    supported_ui_features = ["ldap_query", "ldap_browser:list"]
    #browser_script = BrowserScript(script_name="reg_query", author="@djhohnstein", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_arg("base") == taskData.Callback.Host:
            taskData.args.add_arg("base", "")
        response.DisplayParams = "-Query {}".format(taskData.args.get_arg("query"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
