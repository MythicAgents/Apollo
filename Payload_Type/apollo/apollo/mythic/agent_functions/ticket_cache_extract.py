from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import sys
import base64
from impacket.krb5.ccache import CCache
from datetime import datetime


class ticket_cache_extractArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
             CommandParameter(
            name="service",
            cli_name="service",
            display_name="service",
            type=ParameterType.String,
            description="Service to extract a ticket for, use krbtgt to get the TGT from the session, otherwise use the service name (ex. ldap, cifs, host)",
            parameter_group_info=[
                ParameterGroupInfo(
                    required=True,
                    ui_position=1,
                ),
            ]),
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="luid",
                type=ParameterType.String,
                description="From an elevated context a LUID may be provided to target a specific session to enumerate tickets.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                    ),
                ]),
        ]

    async def parse_arguments(self):
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)
        pass


async def parse_credentials(task: PTTaskCompletionFunctionMessage, ) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(
        Success=True, TaskStatus="success", Completed=True
    )
    responses = await SendMythicRPCResponseSearch(
        MythicRPCResponseSearchMessage(TaskID=task.TaskData.Task.ID)
    )
    #logger.info(responses.Responses)
    for output in responses.Responses:
        try:
            ticket_out = json.loads(str(output.Response))
            ccache = CCache()
            ccache.fromKRBCRED(base64.b64decode(ticket_out['ticket']))
            formattedComment = f"Service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}\n"
            formattedComment += f"Start: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()}\n"
            formattedComment += f"End: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()}\n"
            formattedComment += f"Renew: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()}\n"
            resp = await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
                TaskID=task.TaskData.Task.ID,
                Credentials=[
                    MythicRPCCredentialData(
                        credential_type="ticket",
                        credential=ticket_out['ticket'],
                        account=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8'),
                        realm=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8').split("@")[1],
                        comment=formattedComment,
                    )
                ]
            ))
            if resp.Success:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.TaskData.Task.ID,
                    Response=f"\nAdded credential to Mythic for {ccache.credentials[0].__getitem__('client').prettyPrint().decode('utf-8')}".encode()
                ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.TaskData.Task.ID,
                    Response=f"\nFailed to add to Mythic's credential store:\n{resp.Error}".encode()
                ))
        except Exception as e:
            logger.error(e)
    return response


class ticket_cache_extractCommand(CommandBase):
    cmd = "ticket_cache_extract"
    needs_admin = False
    help_cmd = "ticket_cache_extract [service] [luid]"
    description = "extract a ticket for the provided service name from the current or specified luid"
    version = 2
    author = "@drago-qcc"
    supported_ui_features = ["apollo:ticket_cache_extract"]
    argument_class = ticket_cache_extractArguments
    attackmapping = []
    attributes = CommandAttributes(
        suggested_command=True
    )
    completion_functions = {"parse_credentials": parse_credentials}
    browser_script = BrowserScript(
        script_name="ticket_cache_extract", author="@its_a_feature_", for_new_ui=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse( TaskID=taskData.Task.ID,Success=True)
        response.CompletionFunctionName = "parse_credentials"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
