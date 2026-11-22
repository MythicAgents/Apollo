"""dcsync credential registration (Apollo #201 and #109).

Run inside the Apollo service image, from Payload_Type/apollo:

    docker run --rm --entrypoint "" -v "$PWD":/src:ro -w /src <apollo image> \
        /venv/bin/python -m unittest discover -s tests -v

Only the RabbitMQ transport, mythic_container.RabbitmqConnection.SendRPCDictMessage, is faked. The mythic_container
message classes, their to_json() bodies and the base64 response decoding are the real library code.

Fixtures (tests/fixtures/dcsync/*.json) hold the task's response chunks in ResponseID order. The *_recorded ones are
sanitized recordings of real dcsync tasks; the *_synthetic ones follow the mimikatz output format and cover shapes
with no recording (/all, Primary:CLEARTEXT).
"""
import asyncio
import base64
import json
import os
import unittest
from unittest import mock

import mythic_container
from mythic_container.MythicCommandBase import PTTaskCompletionFunctionMessage

from apollo.mythic.agent_functions import dcsync

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "dcsync")
TASK_ID = 4242
DISPLAY_ID = 17

# Mythic 4 rejects a credential with no account, realm or identity
# (mythic-docker/src/rabbitmq/credential_store.go, UpsertCredential).
MYTHIC_EMPTY_IDENTITY_ERROR = "must supply an account, realm, or credential identity"


def load_chunks(name):
    with open(os.path.join(FIXTURES, name + ".json")) as fh:
        return json.load(fh)["chunks"]


class FakeMythicTransport:
    """Answers the two RPC queues the completion function uses, the way Mythic 4 does."""

    def __init__(self, chunks, search_error=None, create_error=None):
        self.chunks = chunks
        self.search_error = search_error
        self.create_error = create_error
        self.create_bodies = []

    async def SendRPCDictMessage(self, queue, body, **kwargs):
        body = json.loads(json.dumps(body))  # what crosses the wire
        if queue == "mythic_rpc_response_search":
            if self.search_error:
                return {"success": False, "error": self.search_error}
            rows = [
                {"response_id": i + 1, "response": base64.b64encode(c.encode()).decode(), "task_id": body["task_id"]}
                for i, c in enumerate(self.chunks)
            ]
            rows.reverse()  # Mythic returns responses ORDER BY id DESC
            return {"success": True, "error": "", "responses": rows}
        if queue == "mythic_rpc_credential_create":
            self.create_bodies.append(body)
            if self.create_error:
                return {"success": False, "error": self.create_error}
            for cred in body["credentials"]:
                if not cred.get("account") and not cred.get("realm"):
                    return {"success": False, "error": MYTHIC_EMPTY_IDENTITY_ERROR}
            return {"success": True, "error": ""}
        raise AssertionError("unexpected RPC queue: " + queue)

    def rows(self):
        return sorted(
            (c["credential_type"], c["account"], c["realm"], c["credential"])
            for b in self.create_bodies
            for c in b["credentials"]
        )

    def credentials(self):
        return [c for b in self.create_bodies for c in b["credentials"]]


def completion_message():
    task = {
        "id": TASK_ID,
        "display_id": DISPLAY_ID,
        "command_name": "dcsync",
        "params": "{}",
        "original_params": "",
        "tasking_location": "command_line",
        "parameter_group_name": "Default",
    }
    return PTTaskCompletionFunctionMessage(
        args=dcsync.DcSyncArguments,
        task={"task": task, "callback": {}, "payload": {}},
        function_name="parse_credentials_dcsync",
    )


def run_completion(fake):
    with mock.patch.object(mythic_container.RabbitmqConnection, "SendRPCDictMessage", fake.SendRPCDictMessage):
        return asyncio.run(dcsync.parse_credentials_dcsync(completion_message()))


def label_values(text, labels):
    values = set()
    for line in text.replace("\r\n", "\n").split("\n"):
        for label in labels:
            if line.startswith(label):
                values.add(line.split(":", 1)[1].strip())
    return values


class DcSyncCredentialRegistrationTests(unittest.TestCase):
    def assertSuccess(self, response):
        self.assertTrue(response.Success)
        self.assertEqual(response.TaskStatus, "success")
        self.assertTrue(response.Completed)

    def assertOneCreateForTask(self, fake):
        self.assertEqual(len(fake.create_bodies), 1)
        self.assertEqual(fake.create_bodies[0]["task_id"], TASK_ID)

    def test_recorded_user_output_registers_hash_and_current_aes_keys(self):
        fake = FakeMythicTransport(load_chunks("user_recorded"))
        response = run_completion(fake)
        self.assertSuccess(response)
        self.assertOneCreateForTask(fake)
        realm = "gjacekhogxbxo.jqskz"
        self.assertEqual(fake.rows(), sorted([
            ("hash", "ifqfcg", realm, "ef805c249bc931efcac024b88c63f702"),
            ("key", "ifqfcg", realm, "1c35ccae30582536ffef6ea44805e752eef21d8f3bf3be2b3c2d341013d7452a"),
            ("key", "ifqfcg", realm, "488feb870d2499eca83bcd6524b60ffb"),
        ]))
        comments = {c["credential"]: c["comment"] for c in fake.credentials()}
        self.assertIn("Hash NTLM", comments["ef805c249bc931efcac024b88c63f702"])
        self.assertIn("aes256_hmac", comments["1c35ccae30582536ffef6ea44805e752eef21d8f3bf3be2b3c2d341013d7452a"])
        self.assertIn("aes128_hmac", comments["488feb870d2499eca83bcd6524b60ffb"])

    def test_recorded_trust_account_registers_current_keys_only(self):
        fake = FakeMythicTransport(load_chunks("trust_account_old_keys_recorded"))
        response = run_completion(fake)
        self.assertSuccess(response)
        self.assertOneCreateForTask(fake)
        realm = "gjacekhogxbxo.jqskz"
        self.assertEqual(fake.rows(), sorted([
            ("hash", "DEQNP$", realm, "783ab7b1f22527a5cf05c3545781626e"),
            ("key", "DEQNP$", realm, "4b5df5d9ccf062aed6e76a01120a7b2125866b3031e7623102ebe321f6027f02"),
            ("key", "DEQNP$", realm, "76ff4468aae67c74770d1ebe8fad540b"),
        ]))

    def test_rows_survive_chunk_splits_inside_credential_lines_and_lf_endings(self):
        text = "".join(load_chunks("user_recorded"))
        expected = FakeMythicTransport(load_chunks("user_recorded"))
        run_completion(expected)
        cuts = sorted([
            text.index("Hash NTLM: ") + 15,
            text.index("* Primary:Kerberos-Newer-Keys *") + 12,
            text.index("aes256_hmac") + 40,
        ])
        resplit = [text[:cuts[0]], text[cuts[0]:cuts[1]], text[cuts[1]:cuts[2]], text[cuts[2]:]]
        for name, chunks in (("resplit", resplit), ("lf", [c.replace("\r\n", "\n") for c in resplit])):
            with self.subTest(name):
                fake = FakeMythicTransport(chunks)
                self.assertSuccess(run_completion(fake))
                self.assertEqual(fake.rows(), expected.rows())
                self.assertEqual(len(fake.rows()), 3)

    def test_synthetic_all_output_registers_each_account_without_carry_over(self):
        chunks = load_chunks("all_synthetic")
        fake = FakeMythicTransport(chunks)
        self.assertSuccess(run_completion(fake))
        self.assertOneCreateForTask(fake)
        self.assertEqual(fake.rows(), sorted([
            ("hash", "alice", "example.test", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
            ("hash", "WS01$", "example.test", "f9e8d7c6b5a4938271605f4e3d2c1b0a"),
        ]))

    def test_synthetic_cleartext_is_registered_verbatim_and_service_and_old_keys_are_not(self):
        fake = FakeMythicTransport(load_chunks("cleartext_synthetic"))
        self.assertSuccess(run_completion(fake))
        self.assertOneCreateForTask(fake)
        self.assertEqual(fake.rows(), sorted([
            ("hash", "carol", "example.test", "00112233445566778899aabbccddeeff"),
            ("key", "carol", "example.test", "1" * 64),
            ("key", "carol", "example.test", "2" * 32),
            ("plaintext", "carol", "example.test", "Correct Horse : Battery:Staple"),
        ]))

    def test_no_values_from_non_credential_lines_are_registered(self):
        labels = ("Object RDN", "Account Type", "User Account Control", "Object Security ID", "Object Relative ID",
                  "    Default Salt", "    Random Value", "Recovery Password", "    ntlm-", "    lm  -")
        for name in ("user_recorded", "trust_account_old_keys_recorded", "all_synthetic", "cleartext_synthetic"):
            with self.subTest(name):
                chunks = load_chunks(name)
                fake = FakeMythicTransport(chunks)
                run_completion(fake)
                rejected = label_values("".join(chunks), labels)
                current_hashes = label_values("".join(chunks), ("  Hash NTLM",))
                rejected -= current_hashes  # history entry 0 repeats the current hash
                for cred in fake.credentials():
                    self.assertNotIn(cred["credential"], rejected)
                    self.assertNotIn(cred["realm"], rejected)

    def test_recorded_error_output_completes_as_success_without_rpc(self):
        fake = FakeMythicTransport(load_chunks("no_account_error_recorded"))
        response = run_completion(fake)
        self.assertSuccess(response)
        self.assertEqual(fake.create_bodies, [])

    def test_malformed_values_are_skipped(self):
        text = "\r\n".join([
            "[DC] 'example.test' will be the domain",
            "",
            "Object RDN           : dave",
            "",
            "** SAM ACCOUNT **",
            "",
            "SAM Username         : dave",
            "",
            "Credentials:",
            "  Hash NTLM: 0011223344556677889900aabbccddee0",
            "",
            "Supplemental Credentials:",
            "* Primary:Kerberos-Newer-Keys *",
            "    Credentials",
            "      aes256_hmac       (4096) : 1234",
            "      aes128_hmac       (4096) : zz112233445566778899aabbccddeeff",
            "",
            "* Primary:CLEARTEXT *",
            "    ",
            "",
        ])
        fake = FakeMythicTransport([text])
        self.assertSuccess(run_completion(fake))
        self.assertEqual(fake.create_bodies, [])

    def test_rejected_create_raises_with_mythics_error_text(self):
        fake = FakeMythicTransport(load_chunks("user_recorded"), create_error="sql: no rows in result set")
        with self.assertRaises(Exception) as ctx:
            run_completion(fake)
        self.assertIn("sql: no rows in result set", str(ctx.exception))

    def test_failed_response_search_raises_with_its_error_text(self):
        fake = FakeMythicTransport([], search_error="Failed to fetch task for MythicRPCResponseSearch")
        with self.assertRaises(Exception) as ctx:
            run_completion(fake)
        self.assertIn("Failed to fetch task for MythicRPCResponseSearch", str(ctx.exception))
        self.assertEqual(fake.create_bodies, [])

    def test_tasking_arguments_are_unchanged(self):
        cases = (
            ({"domain": "example.test", "user": "carol", "dc": "dc01.example.test"},
             "/domain:example.test /dc:dc01.example.test /user:carol"),
            ({"domain": "example.test"}, "/domain:example.test /all"),
        )
        for params, expected in cases:
            with self.subTest(expected):
                args = dcsync.DcSyncArguments(command_line=json.dumps(params))
                asyncio.run(args.parse_arguments())
                self.assertEqual(args.get_arg("arguments"), expected)
        self.assertEqual(dcsync.DcSyncCommand.completion_functions,
                         {"parse_credentials_dcsync": dcsync.parse_credentials_dcsync})


if __name__ == "__main__":
    unittest.main()
