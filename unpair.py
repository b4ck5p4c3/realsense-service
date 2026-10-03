from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import rsid_py
from dotenv import load_dotenv
import os


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


def load_host_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_device_pubkey(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError(f"{path}: expected a P-256 (secp256r1) public key")
    return key


load_dotenv()

REALSENSE_PORT = os.getenv("REALSENSE_PORT")
REALSENSE_HOST_PRIVATE_KEY_PATH = os.getenv("REALSENSE_HOST_PRIVATE_KEY_PATH")
REALSENSE_DEVICE_PUBLIC_KEY_PATH = os.getenv("REALSENSE_DEVICE_PUBLIC_KEY_PATH")

if REALSENSE_PORT is None:
    raise ValueError("No REALSENSE_PORT is provided")

if REALSENSE_HOST_PRIVATE_KEY_PATH is None:
    raise ValueError("No REALSENSE_HOST_PRIVATE_KEY_PATH is provided")

with rsid_py.FaceAuthenticator(
    SignatureCallback(
        load_host_key(REALSENSE_HOST_PRIVATE_KEY_PATH),
        (
            load_device_pubkey(REALSENSE_DEVICE_PUBLIC_KEY_PATH)
            if REALSENSE_DEVICE_PUBLIC_KEY_PATH is not None
            else None
        ),
    ),
    rsid_py.DeviceType.F45x,
    REALSENSE_PORT,
) as fa:
    fa.unpair()

    print("Unpaired")
