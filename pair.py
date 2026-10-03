from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
import rsid_py
from dotenv import load_dotenv
import os

load_dotenv()

REALSENSE_PORT = os.getenv("REALSENSE_PORT")

if REALSENSE_PORT is None:
    raise ValueError("No REALSENSE_PORT is provided")

key = ec.generate_private_key(ec.SECP256R1())
print("Host private key:")
print(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
)

n = key.public_key().public_numbers()
host_pubkey = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
r, s = utils.decode_dss_signature(key.sign(host_pubkey, ec.ECDSA(hashes.SHA256())))
host_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

with rsid_py.FaceAuthenticator(rsid_py.DeviceType.F45x, REALSENSE_PORT) as fa:
    device_pubkey = fa.pair(host_pubkey, host_sig)

    def pubkey_from_bytes(xy: bytes):
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(xy[:32], "big"),
            int.from_bytes(xy[32:], "big"),
            ec.SECP256R1(),
        ).public_key()

    print("Device public key:")
    print(
        pubkey_from_bytes(device_pubkey)
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("ascii")
    )

    print("Paired")
