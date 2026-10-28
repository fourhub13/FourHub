"""
deproto.py - protocolo de rede do Crime Coast (DEObjectData / RSA / RC4).

Tudo aqui foi escrito a partir do codigo decompilado do
Assembly-CSharp-firstpass (DEObjectData, DEBufferWriter/Reader, DEJenkinsHash,
RSA, RC4). Ainda NAO descreve a ordem das mensagens do aperto de mao: isso
esta no ClientSession.cs.

Dependencia: pip install cryptography
"""
import base64
import hashlib
import os
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes  # noqa: F401


# ---------------------------------------------------------------- hash Jenkins
def jenkins(key: str) -> int:
    """DEJenkinsHash.ComputeHash, devolvido como int COM sinal (como no C#)."""
    n = 0
    for ch in key.encode("utf-8"):
        n = (n + ch) & 0xFFFFFFFF
        n = (n + (n << 10)) & 0xFFFFFFFF
        n ^= n >> 6
    n = (n + (n << 3)) & 0xFFFFFFFF
    n ^= n >> 11
    n = (n + (n << 15)) & 0xFFFFFFFF
    return n - (1 << 32) if n >= (1 << 31) else n


# ----------------------------------------------------------------- DEObjectData
class Data:
    """Equivalente do DEObjectData. As chaves sao guardadas como hash Jenkins."""

    def __init__(self):
        self.strings, self.ints, self.floats = {}, {}, {}
        self.longs, self.dicts, self.bytes_ = {}, {}, {}

    # setters/getters por nome (como o jogo)
    def set_string(self, k, v): self.strings[jenkins(k)] = v
    def set_int(self, k, v): self.ints[jenkins(k)] = v
    def set_bool(self, k, v): self.ints[jenkins(k)] = 1 if v else 0
    def set_long(self, k, v): self.longs[jenkins(k)] = v
    def set_float(self, k, v): self.floats[jenkins(k)] = v
    def set_bytes(self, k, v): self.bytes_[jenkins(k)] = bytes(v)
    def set_data(self, k, v): self.dicts[jenkins(k)] = v

    def contains(self, k):
        h = jenkins(k)
        return any(h in d for d in (self.strings, self.ints, self.floats,
                                    self.longs, self.dicts, self.bytes_))

    def get_string(self, k, default=""):
        h = jenkins(k)
        if h in self.strings: return self.strings[h]
        for d in (self.ints, self.floats, self.longs):
            if h in d: return str(d[h])
        return default

    def get_int(self, k, default=0): return self.ints.get(jenkins(k), default)
    def get_long(self, k, default=0):
        h = jenkins(k)
        return self.longs.get(h, self.ints.get(h, default))
    def get_bool(self, k, default=False):
        h = jenkins(k)
        return self.ints[h] == 1 if h in self.ints else default
    def get_float(self, k, default=0.0): return self.floats.get(jenkins(k), default)
    def get_bytes(self, k): return self.bytes_.get(jenkins(k))
    def get_data(self, k): return self.dicts.get(jenkins(k))

    # serializacao (formato V1)
    def to_bytes(self) -> bytes:
        out = bytearray([1])
        self._write(out)
        return bytes(out)

    def _write(self, out: bytearray):
        flag_pos = len(out)
        out.append(0)
        flags = 0
        if self.strings:
            out += struct.pack(">i", len(self.strings)); flags |= 1
            for k, v in self.strings.items():
                out += struct.pack(">i", k)
                if v is None:
                    out += struct.pack(">i", -1)
                else:
                    b = v.encode("utf-8")
                    out += struct.pack(">i", len(b)) + b
        if self.ints:
            big = [(k, v) for k, v in self.ints.items() if not (0 <= v < 256)]
            small = [(k, v) for k, v in self.ints.items() if 0 <= v < 256]
            if big:
                out += struct.pack(">i", len(big)); flags |= 4
                for k, v in big: out += struct.pack(">ii", k, v)
            if small:
                out += struct.pack(">i", len(small)); flags |= 0x40
                for k, v in small: out += struct.pack(">i", k) + bytes([v])
        if self.floats:
            out += struct.pack(">i", len(self.floats)); flags |= 0x10
            for k, v in self.floats.items(): out += struct.pack(">i", k) + struct.pack("<f", v)
        if self.longs:
            out += struct.pack(">i", len(self.longs)); flags |= 8
            for k, v in self.longs.items(): out += struct.pack(">iq", k, v)
        if self.dicts:
            out += struct.pack(">i", len(self.dicts)); flags |= 0x20
            for k, v in self.dicts.items():
                out += struct.pack(">i", k)
                v._write(out)
        if self.bytes_:
            out += struct.pack(">i", len(self.bytes_)); flags |= 0x80
            for k, v in self.bytes_.items():
                out += struct.pack(">ii", k, len(v)) + v
        out[flag_pos] = flags

    @staticmethod
    def from_bytes(b: bytes) -> "Data":
        if not b:
            raise ValueError("bytes vazios")
        if b[0] != 1:
            raise ValueError(f"versao de DEObjectData nao suportada: {b[0]} (so V1)")
        pos = [1]
        return Data._read(b, pos)

    @staticmethod
    def _read(b, pos):
        def i4():
            v = struct.unpack_from(">i", b, pos[0])[0]; pos[0] += 4; return v
        d = Data()
        f = b[pos[0]]; pos[0] += 1
        if f & 1:
            for _ in range(i4()):
                k = i4(); n = i4()
                if n > 0: s = b[pos[0]:pos[0] + n].decode("utf-8"); pos[0] += n
                else: s = "" if n == 0 else None
                d.strings[k] = s
        if f & 4:
            for _ in range(i4()):
                k = i4(); d.ints[k] = i4()
        if f & 0x40:
            for _ in range(i4()):
                k = i4(); d.ints[k] = b[pos[0]]; pos[0] += 1
        if f & 0x10:
            for _ in range(i4()):
                k = i4(); d.floats[k] = struct.unpack_from("<f", b, pos[0])[0]; pos[0] += 4
        if f & 8:
            for _ in range(i4()):
                k = i4(); d.longs[k] = struct.unpack_from(">q", b, pos[0])[0]; pos[0] += 8
        if f & 0x20:
            for _ in range(i4()):
                k = i4(); d.dicts[k] = Data._read(b, pos)
        if f & 0x80:
            for _ in range(i4()):
                k = i4(); n = i4(); d.bytes_[k] = bytes(b[pos[0]:pos[0] + n]); pos[0] += n
        return d


# -------------------------------------------------------------------------- RSA
def _b64(b): return base64.b64encode(b).decode()
def _unb64(s): return base64.b64decode(s)
def _int_bytes(n): return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rsa_generate(bits=1024):
    """Devolve (chave_privada, Data_publico{A:modulo,B:expoente})."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    n = priv.public_key().public_numbers()
    pub = Data()
    pub.set_string("A", _b64(_int_bytes(n.n)))
    pub.set_string("B", _b64(_int_bytes(n.e)))
    return priv, pub


def rsa_public_from_data(pub: Data):
    n = int.from_bytes(_unb64(pub.get_string("A")), "big")
    e = int.from_bytes(_unb64(pub.get_string("B")), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def rsa_encrypt_transferable(data: Data, pub: Data) -> Data:
    """RSA.EncryptToTransferrableData: blocos de 55 bytes, PKCS#1 v1.5,
    cada bloco em bytes sob a chave "0", "1", ..."""
    key = rsa_public_from_data(pub)
    raw = data.to_bytes()
    out = Data()
    for i in range(0, len(raw), 55):
        out.set_bytes(str(i // 55), key.encrypt(raw[i:i + 55], padding.PKCS1v15()))
    return out


def rsa_decrypt_transferable(data: Data, priv) -> Data:
    raw = bytearray()
    i = 0
    while data.contains(str(i)):
        raw += priv.decrypt(data.get_bytes(str(i)), padding.PKCS1v15())
        i += 1
    return Data.from_bytes(bytes(raw))


# -------------------------------------------------------------------------- RC4
VALID_SECRET_CHARS = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()!%")


def create_secret(length: int) -> str:
    return "".join(VALID_SECRET_CHARS[b % 65] for b in os.urandom(length))


class RC4:
    """RC4 do jogo. ATENCAO ao bug herdado: o PrepareKey usa i < 255, entao
    S[255] fica 0 e a posicao 255 nunca entra na mistura inicial. Um RC4
    padrao NAO e compativel."""

    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode("utf-8")
        self.S = [0] * 256
        for i in range(255):
            self.S[i] = i
        num = 0
        for j in range(255):
            num = (num + self.S[j] + key[j % len(key)]) % 256
            self.S[num], self.S[j] = self.S[j], self.S[num]
        self.i = 0
        self.j = 0

    def transform(self, data: bytes) -> bytes:
        S, i, j = self.S, self.i, self.j
        out = bytearray(data)
        for n in range(len(out)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out[n] ^= S[(S[i] + S[j]) % 256]
        self.i, self.j = i, j
        return bytes(out)

    def encode_with_checksum(self, data: Data) -> Data:
        """RC4.EncodeWithChecksum(data, formato V1)."""
        raw = data.to_bytes()
        inner = Data()
        inner.set_bytes("R", raw)
        inner.set_string("h", hashlib.md5(raw).hexdigest().upper())
        out = Data()
        out.set_bytes("d", self.transform(inner.to_bytes()))
        return out

    def decode_with_checksum(self, data: Data) -> Data:
        enc = data.get_bytes("d")
        if not enc:
            raise ValueError("campo d ausente")
        inner = Data.from_bytes(self.transform(enc))
        raw = inner.get_bytes("R")
        if hashlib.md5(raw).hexdigest().upper() != inner.get_string("h"):
            raise ValueError("MD5 nao confere")
        return Data.from_bytes(raw)
