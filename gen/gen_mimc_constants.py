from sha3 import keccak_256

SEED = b"mimcsponge"
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
#FIELD_MODULUS = 65535
HEADER = "  (defconst MIMC-CONST:[integer] ["
FOOTER = "])"

def gen_constants():
    yield 0
    x = keccak_256(SEED).digest()

    for _ in range(218):
        x = keccak_256(x).digest()
        yield int.from_bytes(x, "big") % FIELD_MODULUS
    yield 0

output = HEADER  + (",\n" + " "*len(HEADER)).join(map("{:d}".format, gen_constants())) + FOOTER

print(output)
