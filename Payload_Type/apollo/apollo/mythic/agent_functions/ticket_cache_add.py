from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
from impacket.krb5.ccache import CCache
from datetime import datetime


class ticket_cache_addArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="base64ticket",
                cli_name="b64ticket",
                display_name="b64ticket",
                type=ParameterType.String,
                description="A base64 encoded kerberos ticket value that will be loaded into the current logon session",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                        group_name="Add New Ticket"
                    ),
                ]),
            CommandParameter(
                name="existingTicket",
                cli_name="existingTicket",
                display_name="Existing Ticket",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["ticket"],
                description="An existing ticket from Mythic's credential store",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                        group_name="Use Existing Ticket"
                    ),
                ]),
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="luid",
                type=ParameterType.String,
                description="From an elevated context a LUID may be provided to target a specific session to add tickets to.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                        group_name="Add New Ticket"
                    ),
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                        group_name="Use Existing Ticket"
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)


class ticket_cache_addCommand(CommandBase):
    cmd = "ticket_cache_add"
    needs_admin = False
    help_cmd = "ticket_cache_add [b64Ticket] [luid]"
    description = "Add a kerberos ticket to the current luid, or if elevated and a luid is provided load the ticket into that logon session instead. This modifies the tickets in the current logon session."
    version = 2
    author = "@drago-qcc"
    supported_ui_features = ["apollo:ticket_cache_add"]
    argument_class = ticket_cache_addArguments
    attackmapping = []
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID,Success=True)
        current_group_name = taskData.args.get_parameter_group_name()
        if current_group_name == "Use Existing Ticket":
            credentialData = taskData.args.get_arg("existingTicket")
            taskData.args.remove_arg("existingTicket")
            taskData.args.add_arg("base64ticket", credentialData["credential"], parameter_group_info=[ParameterGroupInfo(group_name=current_group_name)])

        base64Ticket = taskData.args.get_arg("base64ticket")
        ccache = CCache()
        ccache.fromKRBCRED(base64.b64decode(base64Ticket))
        #ccache.credentials[0].__getitem__('client').prettyPrint()  # user@domain
        #ccache.credentials[0].__getitem__('server').prettyPrint()  # krbtgt/domain@domain
        #datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()
        #datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()
        #datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()
        formattedComment = f"Service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}\n"
        formattedComment += f"Start: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()}\n"
        formattedComment += f"End: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()}\n"
        formattedComment += f"Renew: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()}\n"
        if current_group_name == "Add New Ticket":
            resp = await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
                TaskID=taskData.Task.ID,
                Credentials=[
                    MythicRPCCredentialData(
                        credential_type="ticket",
                        credential=taskData.args.get_arg("base64ticket"),
                        account=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8'),
                        realm=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8').split("@")[1],
                        comment=formattedComment,
                    )
                ]
            ))
        response.DisplayParams = f" client: {ccache.credentials[0].__getitem__('client').prettyPrint().decode('utf-8')}"
        response.DisplayParams += f", service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}"
        luid = taskData.args.get_arg("luid")
        if luid is not None and luid != "":
            response.DisplayParams += f" -luid {luid}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
