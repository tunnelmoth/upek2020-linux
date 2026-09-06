import usb.core, usb.util, time, os, glob, hashlib, secrets
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES
M=bytes.fromhex("941cf8d63afb0cff1a96531e9b28e5fe07147365e1bac869d4609cc9ad8a8804")
CTR=bytes.fromhex("e38f7cb3")
def sp():
    for dd in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        if open(dd).read().strip()=="147e" and open(os.path.dirname(dd)+"/idProduct").read().strip()=="2020":
            return os.path.basename(os.path.dirname(dd))
def crc16(d):
    c=0
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xffff if c&0x8000 else (c<<1)&0xffff
    return c.to_bytes(2,"little")
def bf(seq,sub,b6,content):
    head=b"Ciao"+bytes([seq,sub,b6,0x28])+(len(content)+2).to_bytes(4,"little")
    return head+content+crc16(head[4:]+content)
def rsa_enc(mod64,e,msg):
    n=int.from_bytes(mod64,"little")
    ps=b""
    while len(ps)<64-3-len(msg):
        x=secrets.token_bytes(1)
        if x!=b"\x00": ps+=x
    return pow(int.from_bytes(b"\x00\x02"+ps+b"\x00"+msg,"big"),e,n).to_bytes(64,"big")
p=sp()
open("/sys/bus/usb/drivers/usb/unbind","w").write(p); time.sleep(0.5)
open("/sys/bus/usb/drivers/usb/bind","w").write(p); time.sleep(1.8)
d=None
for _ in range(25):
    d=usb.core.find(idVendor=0x147e,idProduct=0x2020)
    if d: break
    time.sleep(0.4)
usb.util.claim_interface(d,0)
def rd(t=800):
    try: return bytes(d.read(0x81,512,t))
    except usb.core.USBError: return None
def drain(n=8,t=600):
    o=[]
    for _ in range(n):
        r=rd(t)
        if r is None: break
        o.append(r)
    return o
def wr(h): d.write(0x02,bytes.fromhex(h) if isinstance(h,str) else h,1000)
d.ctrl_transfer(0xc0,0x04,0,0,8,1000); d.ctrl_transfer(0xc0,0x04,0,0,8,1000)
d.ctrl_transfer(0x40,0x0c,0x0100,0x0400,b"\x00",1000); drain(2,400)
devkey=Y=None
for i,f in enumerate(["4369616f04000801005e01000000000d65","4369616f00000728040000000604c0d6",
        "4369616f00100b280800000002040b0000006556","4369616f00200b280800000051040a00000079a5",
        "4369616f00300b28080000000704200000005d11"]):
    wr(f); time.sleep(0.03); r=b"".join(drain(6,600))
    if i==2: j=r.find(bytes.fromhex("030020002000")); devkey=r[j+6:j+6+64]
    if i==4: j=r.find(b'\x07\x14'); Y=r[j+2:j+2+32]
sk=secrets.token_bytes(48)
content=bytes.fromhex("08030100000001000000310000003800000000000000030000000000000060000000")+hashlib.sha256(CTR+M+Y).digest()+rsa_enc(devkey,17,sk)
wr(bf(0,0x40,0x87,content)); time.sleep(0.05)
resp=b"".join(drain(8,800))
ok=resp[12:14]==b'\x08\x13' and resp[14:18]==bytes.fromhex("20000000")
print("frame-11:", "ACCEPTED" if ok else "reject "+resp[12:20].hex())
if not ok: usb.util.release_interface(d,0); exit()
# derive AES channel key
aeskey=hashlib.sha256(bytes.fromhex("62466e8d")+Y+sk+M).digest()[:7]+b"\x00"*9
print("aeskey:", aeskey.hex())
def enc(pt): return AES.new(aeskey,AES.MODE_ECB).encrypt(pt)
def dec(ct): return AES.new(aeskey,AES.MODE_ECB).decrypt(ct)
# send the 0080 channel command (Windows plaintext). content = 00 80 + AES(cmd)
cmd_pt=bytes.fromhex("00000c0405000000446fcef000000003")
frame=bf(0,0x50,0x17,bytes.fromhex("0080")+enc(cmd_pt))
wr(frame); time.sleep(0.05)
r0080=b"".join(drain(8,800))
print("0080 device resp:", r0080.hex())
# decrypt device response payload (after 00 80)
j=r0080.find(bytes.fromhex("0080"),12)
if j>=0:
    ctb=r0080[j+2:]
    # decrypt 16-byte blocks
    plain=b""
    for k in range(0,len(ctb)-15,16):
        plain+=dec(ctb[k:k+16])
    print("decrypted device cmd:", plain.hex())
usb.util.release_interface(d,0)
