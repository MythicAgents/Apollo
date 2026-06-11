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
                dn = metadata.get("distinguishedname", metadata.get("DistinguishedName", data.get("display_path", data["full_path"])))
                if dn.startswith("LDAP://"):
                    dn = dn[7:]
                if dn == data["full_path"]:
                    dn_pieces = [x.strip() for x in dn.split(",") if x.strip()]
                    if len(dn_pieces) > 0 and dn_pieces[0].lower().startswith("dc="):
                        dn = ",".join(reversed(dn_pieces))
                self.add_arg("base", dn)
                self.add_arg("query", data["query"] if "query" in data and data["query"] else "(objectClass=*)")
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
