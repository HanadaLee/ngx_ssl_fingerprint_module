#!/usr/bin/env python3
"""Independent wire vectors and reference fingerprints for the C implementation."""
import hashlib
import json
import random
import struct
import subprocess
import sys

def u16(n):
    return struct.pack("!H", n)

def vec(data, width=2):
    return len(data).to_bytes(width, "big") + data

def words(values):
    return b"".join(u16(n) for n in values)

def grease(n):
    return n in range(0x0a0a, 0xfb00, 0x1010)

def clean(values):
    return [n for n in values if not grease(n)]

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "0" * 12

def reference(ciphers, extensions, groups, formats, sigalgs, versions, alpn,
              legacy=0x0303, transport="t"):
    c, e, g, s = map(clean, (ciphers, extensions, groups, sigalgs))
    ja3 = ",".join((str(legacy), "-".join(map(str, c)),
                   "-".join(map(str, e)), "-".join(map(str, g)),
                   "-".join(map(str, formats))))
    version = max(clean(versions), default=0) if versions is not None else legacy
    version = {2:"s2", 0x300:"s3", 0x301:"10", 0x302:"11",
               0x303:"12", 0x304:"13"}.get(version, "00")
    a = "00"
    if alpn:
        first, last = alpn[0][0], alpn[0][-1]
        ascii_alnum = lambda n: 48 <= n <= 57 or 65 <= n <= 90 or 97 <= n <= 122
        a = chr(first) + chr(last) if ascii_alnum(first) and ascii_alnum(last) \
            else alpn[0].hex()[0] + alpn[0].hex()[-1]
    prefix = f"{transport}{version}{'d' if 0 in e else 'i'}{min(len(c),99):02}{min(len(e),99):02}{a}"
    csv = lambda values: ",".join(f"{n:04x}" for n in values)
    def ja4(original):
        b = csv(c if original else sorted(c))
        ce = csv(e if original else sorted(n for n in e if n not in (0,16)))
        if s:
            ce += "_" + csv(s)
        raw = prefix + "_" + b + "_" + ce
        return raw, prefix + "_" + digest(b) + "_" + digest(ce)
    raw, hashed = ja4(False)
    original, original_hash = ja4(True)
    return ["1" if len(c) != len(ciphers) else "0", ja3,
            hashlib.md5(ja3.encode()).hexdigest(), raw, hashed, original, original_hash]

def hello(ciphers=(47,), extensions=(), legacy=0x303, omit_extensions=False):
    body = u16(legacy) + bytes(32) + vec(b"", 1) + vec(words(ciphers)) + vec(b"\0", 1)
    if not omit_extensions:
        body += vec(b"".join(u16(n) + vec(data) for n, data in extensions))
    return b"\1" + len(body).to_bytes(3, "big") + body

cases = []
def add(name, mode="normal", ciphers=(47,), groups=None, formats=None,
        sigalgs=None, versions=None, alpn=None, sni=False, extra=(),
        order=None, legacy=0x303, omit_extensions=False):
    exts = []
    if sni:
        exts.append((0, vec(b"\0" + vec(b"example.test"))))
    if groups is not None:
        exts.append((10, vec(words(groups))))
    if formats is not None:
        exts.append((11, vec(bytes(formats), 1)))
    if sigalgs is not None:
        exts.append((13, vec(words(sigalgs))))
    if versions is not None:
        exts.append((43, vec(words(versions), 1)))
    if alpn is not None:
        exts.append((16, vec(b"".join(vec(p, 1) for p in alpn))))
    exts += list(extra)
    if order is not None:
        exts = sorted(exts, key=lambda e: order.index(e[0]))
    packet = hello(ciphers, exts, legacy, omit_extensions)
    expected = reference(ciphers, [e[0] for e in exts], groups or (), formats or (),
                         sigalgs or (), versions, alpn, legacy,
                         "q" if mode == "http3" else "t")
    if mode in ("disabled", "capture_oom"):
        expected = [None] * 7
    cases.append((name, mode, packet, expected))
    return packet

add("no extensions block", omit_extensions=True)
add("empty extensions block")
add("empty cipher vector", ciphers=())
add("formats without groups", formats=(0,))
add("GREASE-only groups", groups=(0x0a0a,), formats=(0,))
add("GREASE-only ciphers and extensions", ciphers=(0x1a1a,), extra=((0x2a2a,b""),))
add("only SNI", sni=True)
add("only ALPN", alpn=(b"h2",))
add("SNI and ALPN removed only from sorted output", sni=True, alpn=(b"h2",))
add("signature algorithms retain order and remove GREASE",
    sigalgs=(0x0804, 0x0a0a, 0x0403, 0x0601))
add("GREASE-only signature algorithms", sigalgs=(0x3a3a, 0xfafa))
add("empty typed vectors", groups=(), formats=(), sigalgs=(), versions=(), alpn=())
add("maximum point-format vector", formats=tuple(range(255)))
add("unknown and SCSV values retained", ciphers=(0x5600,0xff,0xfe00,47),
    extra=((65000,b"ignored"),(12345,b"opaque")))
for n in range(16):
    code=0x0a0a+n*0x1010
    add(f"GREASE family {n}", ciphers=(code,0x1302,0x1301),
        groups=(code,29), sigalgs=(code,0x0804,0x0403),
        versions=(code,0x303,0x304), extra=((code,b""),))
for value in (b"h2", b"http/1.1", b"h3", b"x", b"H2", b"\0", b"\xab",
              b"\x20\x61", b"0\xab", b"a ", b"01\xab\xcd",
              b"0\xab\xcd1", b"a\0z", b"x"*255):
    add("ALPN "+value.hex(), alpn=(value,b"h2"))
for version in (2, 0x300,0x301,0x302,0x303,0x304,0x9999):
    add(f"version {version}", legacy=version)
for mode in ("http3","noise","replay","disabled","capture_oom","output_oom",
             "digest1","digest2","digest3","digest4"):
    add(mode,mode=mode,groups=(29,23),formats=(0,),
        sigalgs=(0x804,0x403),versions=(0x303,0x304),alpn=(b"h2",),sni=True)
for n in (99,100,128,129,500,32767):
    add(f"cipher count {n}", ciphers=tuple(range(n)))
add("extension count 200", extra=tuple((30000+n,b"") for n in range(200)))
add("large temporary buffer failure", mode="heap_oom", ciphers=tuple(range(500)))
padded = add("large padding is not retained", extra=((21,b" "*50000),))
base = add("first offered version, not negotiated", ciphers=(0x1302,0x1301,47),
           versions=(0x303,0x304),groups=(29,23),formats=(0,),
           sigalgs=(0x804,0x403),alpn=(b"h2",),sni=True)

# Every truncation of a valid record is rejected, including the empty message.
for n in range(len(base)):
    cases.append((f"truncated at {n}", "normal", base[:n], [None]*7))
for code,payload in (
    (10,b"\0"),(10,b"\0\1x"),(10,b"\0\0x"),
    (11,b"\2\0"),(13,b"\0\3abc"),(13,b"\0"),
    (43,b"\2\3"),(43,b"\1\3"),(43,b"\0x"),
    (16,b"\0"),(16,b"\0\2\2x"),(16,b"\0\1\0"),
    (16,b"\0\2\1xextra"),
):
    cases.append((f"invalid vector {code} {payload.hex()}", "normal",
                  hello(extensions=((code,payload),)), [None]*7))
for code,payload in ((0,b""),(10,b"\0\0"),(11,b"\0"),
                     (13,b"\0\0"),(16,b"\0\0"),(43,b"\0")):
    cases.append((f"duplicate parsed extension {code}","normal",
                  hello(extensions=((code,payload),(code,payload))),[None]*7))
cases.append(("odd cipher length","normal",
              base[:39]+b"\0\5"+base[41:],[None]*7))
# Random valid cases use a reference built from inputs, never module output.
rng=random.Random(0x4a4134)
for n in range(300):
    add(f"random valid {n}", ciphers=tuple(rng.randrange(65536) for _ in range(rng.randrange(1,220))),
        groups=tuple(rng.randrange(65536) for _ in range(rng.randrange(10))),
        sigalgs=tuple(rng.randrange(65536) for _ in range(rng.randrange(20))),
        formats=(0,), versions=(0x303,0x304),sni=bool(n%2),
        alpn=(bytes(rng.randrange(256) for _ in range(rng.randrange(1,20))),),
        extra=((60000+n,b"ignored"),))
# Mutations are a sanitizer corpus, not all mutations must be rejected by TLS.
for n in range(500):
    data=bytearray(base)
    for _ in range(rng.randrange(1,5)):
        data[rng.randrange(len(data))]=rng.randrange(256)
    cases.append((f"mutated {n}","normal",bytes(data),None))

payload="".join(mode+" "+packet.hex()+"\n" for _,mode,packet,_ in cases)
run=subprocess.run([sys.argv[1]],input=payload,text=True,capture_output=True)
if run.returncode:
    sys.stderr.write(run.stderr)
    raise SystemExit(f"probe exited {run.returncode}")
lines=run.stdout.splitlines()
assert len(lines)==len(cases), (len(lines),len(cases))
checks=0
for (name,mode,packet,expected),line in zip(cases,lines):
    result=json.loads(line)
    if expected is not None:
        assert result["values"]==expected, (name,result["values"],expected)
        checks+=1
    assert result["lazy"] and result["stable"] and result["heap_live"]==0, (name,result)
    checks+=3
    if mode.startswith("digest") or mode in ("output_oom","heap_oom"):
        assert result["first"]==-1 and result["clean"], (name,result)
        checks+=1
    if name=="large padding is not retained":
        assert result["snapshot"] < 1024, result
        checks+=1
print(f"PASS: {len(cases)} ClientHello cases, {checks} assertions (including allocation/digest failures and stream lifetime)")
