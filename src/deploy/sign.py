from starknet_py.hash.utils import message_signature

r, s = message_signature(msg_hash=0x4dfd50e2dd60c61e62d2557b763433d867f8fdcd98f62c41458872d122f0ea0, priv_key=0x77516b2052250204f7746bd9ae5ecc9f56a46364b777c8c1b6758d1f23d2413)

print(f"{hex(r)} {hex(s)}")
