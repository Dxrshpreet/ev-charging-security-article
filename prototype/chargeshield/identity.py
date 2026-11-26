"""Layer 1: cryptographic identity (small demonstrations).

1. ECDHE key agreement on curve P-256: both sides derive the same secret
   K = abG without ever sending a or b.
2. Signed firmware with ECDSA + SHA-256: a single changed byte makes
   verification fail, so the bootloader refuses tampered firmware.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def ecdhe_demo():
    charger_priv = ec.generate_private_key(ec.SECP256R1())   # secret a
    server_priv = ec.generate_private_key(ec.SECP256R1())    # secret b
    # each side combines its own secret with the other side's public point
    k_charger = charger_priv.exchange(ec.ECDH(), server_priv.public_key())   # a * (bG)
    k_server = server_priv.exchange(ec.ECDH(), charger_priv.public_key())    # b * (aG)
    return k_charger, k_server


def sign_firmware(vendor_priv, firmware: bytes) -> bytes:
    return vendor_priv.sign(firmware, ec.ECDSA(hashes.SHA256()))


def verify_firmware(vendor_pub, firmware: bytes, signature: bytes) -> bool:
    try:
        vendor_pub.verify(signature, firmware, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def firmware_demo():
    vendor_priv = ec.generate_private_key(ec.SECP256R1())
    vendor_pub = vendor_priv.public_key()          # burned into the charger's bootloader
    firmware = b"EVSE firmware v2.4.1 " + bytes(range(256)) * 64
    sig = sign_firmware(vendor_priv, firmware)
    tampered = bytearray(firmware)
    tampered[100] ^= 0x01                          # attacker flips one bit
    return {
        "firmware_bytes": len(firmware),
        "signature_bytes": len(sig),
        "genuine_accepted": verify_firmware(vendor_pub, firmware, sig),
        "tampered_accepted": verify_firmware(vendor_pub, bytes(tampered), sig),
    }
