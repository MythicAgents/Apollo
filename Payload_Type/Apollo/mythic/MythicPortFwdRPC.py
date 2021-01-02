from MythicBaseRPC import *


class MythicPortFwdRPCResponse(RPCResponse):
    def __init__(self, rportfwd: RPCResponse):
        super().__init__(rportfwd._raw_resp)


class MythicPortFwdRPC(MythicBaseRPC):
    async def start_rportfwd(self, port: int,rport: int,rip: str) -> MythicPortFwdRPCResponse:
        resp = await self.call(
            {
                "action": "control_rportfwd",
                "task_id": self.task_id,
                "start": True,
                "port": port,
                "rport": rport,
                "rip":rip,
            }
        )
        return MythicPortFwdRPCResponse(resp)

    async def stop_rportfwd(self, port: int) -> MythicPortFwdRPCResponse:
        resp = await self.call(
            {
                "action": "control_rportfwd",
                "stop": True,
                "task_id": self.task_id,
                "port": port,
            }
        )
        return MythicPortFwdRPCResponse(resp)

    async def list_rportfwd(self) -> MythicPortFwdRPCResponse:
        resp = await self.call(
            {
                "action": "control_rportfwd",
                "list": True,
                "task_id": self.task_id,
            }
        )
        return MythicPortFwdRPCResponse(resp)

    async def flush_rportfwd(self) -> MythicPortFwdRPCResponse:
        resp = await self.call(
            {
                "action": "control_rportfwd",
                "flush": True,
                "task_id": self.task_id,
            }
        )
        return MythicPortFwdRPCResponse(resp)
