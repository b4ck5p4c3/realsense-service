from collections.abc import Callable
from threading import Thread
from queue import Queue
from dataclasses import dataclass
from enum import Enum
import logging
import rsid_py
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature


class SignatureCallback(rsid_py.SignatureCallback):
    def __init__(self, host_private_key, device_public_key):
        super().__init__()
        self._host_private_key = host_private_key
        self._device_public_key = device_public_key

    def sign(self, buffer: bytes) -> bytes:
        r, s = utils.decode_dss_signature(
            self._host_private_key.sign(buffer, ec.ECDSA(hashes.SHA256()))
        )
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, buffer: bytes, signature: bytes) -> bool:
        if self._device_public_key is None:
            return

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            self._device_public_key.verify(
                utils.encode_dss_signature(r, s), buffer, ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


class RealsenseBusyError(Exception):
    pass


class RealsenseTaskType(Enum):
    ENROLL = 1
    REMOVE = 2


@dataclass
class RealsenseTask:
    type: RealsenseTaskType
    user_id: str


def load_host_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_device_public_key(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError(f"{path}: expected a P-256 (secp256r1) public key")
    return key


class RealsenseWorker:
    users: set[str]
    is_busy: bool
    thread: Thread
    task_queue: Queue[RealsenseTask]
    task_result_queue: Queue[(bool, str)]
    logger: logging.Logger
    authenticator: rsid_py.FaceAuthenticator

    def __init__(
        self,
        port: str,
        host_private_key_path: str,
        device_public_key_path: str,
        on_auth_callback: Callable[[str], None],
    ):
        self.logger = logging.getLogger("realsense.worker")
        self.users = set()
        self.is_busy = False
        self.thread = Thread(target=self.main_thread)
        self.task_queue = Queue()
        self.task_result_queue = Queue()
        self.is_busy = False
        self.port = port
        self.on_auth_callback = on_auth_callback
        self.host_private_key = load_host_private_key(host_private_key_path)
        self.device_public_key = load_device_public_key(device_public_key_path)
        pass

    def main_thread(self) -> None:
        while True:
            try:
                self.is_busy = False
                self.authenticator = rsid_py.FaceAuthenticator(
                    SignatureCallback(self.host_private_key, self.device_public_key),
                    rsid_py.DeviceType.F45x,
                    self.port,
                )
                self.users = set(self.authenticator.query_user_ids())
                self.logger.info(f"Started, loaded {len(self.users)} users")
                while True:

                    def auth_on_result(result: rsid_py.AuthenticateStatus, user_id: str | None):
                        if result == rsid_py.AuthenticateStatus.Success:
                            self.on_auth_callback(user_id)
                            self.logger.info(f"User {user_id} authenticated")
                        if self.task_queue.empty():
                            return
                        self.authenticator.cancel()

                    self.authenticator.authenticate_loop(on_result=auth_on_result)
                    task = self.task_queue.get()
                    if task is None:
                        break
                    match task.type:
                        case RealsenseTaskType.REMOVE:
                            if task.user_id in self.users:
                                self.users.remove(task.user_id)
                                self.authenticator.remove_user(task.user_id)
                                self.task_result_queue.put((True, None))
                            else:
                                self.task_result_queue.put((False, None))
                            self.logger.info(f"User {task.user_id} removed")
                            self.is_busy = False
                        case RealsenseTaskType.ENROLL:
                            if task.user_id in self.users:
                                self.task_result_queue.put((True, "AlreadyEnrolled"))
                                self.logger.info(f"User {task.user_id} already enrolled")
                            else:
                                enroll_result = None

                                def on_result(result):
                                    nonlocal enroll_result
                                    enroll_result = result

                                self.authenticator.enroll(
                                    user_id=task.user_id, on_result=on_result
                                )
                                if enroll_result == rsid_py.EnrollStatus.Success:
                                    self.users.add(task.user_id)
                                    self.task_result_queue.put((True, str(enroll_result)))
                                    self.logger.info(
                                        f"User {task.user_id} enrolled successfully"
                                    )
                                else:
                                    self.task_result_queue.put((False, str(enroll_result)))
                                    self.logger.info(
                                        f"User {task.user_id} enroll failed: {enroll_result}"
                                    )
                            self.is_busy = False
                            pass
                self.authenticator.disconnect()
                self.logger.info("Stopped")
            except Exception as e:
                self.logger.fatal(e)
                pass

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.task_queue.put(None)
        self.thread.join()

    def enroll(self, user_id: str) -> tuple[bool, str]:
        if self.is_busy:
            raise RealsenseBusyError()
        self.is_busy = True

        self.task_queue.put(RealsenseTask(RealsenseTaskType.ENROLL, user_id))
        return self.task_result_queue.get(timeout=20)

    def remove(self, user_id: str) -> bool:
        if self.is_busy:
            raise RealsenseBusyError()
        self.is_busy = True

        self.task_queue.put(RealsenseTask(RealsenseTaskType.REMOVE, user_id))
        return self.task_result_queue.get(timeout=20)[0]

    def get_users(self) -> set[str]:
        return self.users

    def is_enrolled(self, user_id: str) -> bool:
        return user_id in self.users
