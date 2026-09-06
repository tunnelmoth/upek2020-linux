import usb.core, usb.util, time, os, glob, hashlib, secrets
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
def build_frame(seq,sub,b6,content):
    head=b"Ciao"+bytes([seq,sub,b6,0x28])+(len(content)+2).to_bytes(4,"little")
    return head+content+crc16(head[4:]+content)
def rsa_enc(n_be,e,msg):
    n=int.from_bytes(n_be,"big"); k=len(n_be)
    ps=b""
    while len(ps)<k-3-len(msg):
        x=secrets.token_bytes(1)
        if x!=b"\x00": ps+=x
    eb=b"\x00\x02"+ps+b"\x00"+msg
    return pow(int.from_bytes(eb,"big"),e,n).to_bytes(k,"big")
p=sp()
def rebind():
    open("/sys/bus/usb/drivers/usb/unbind","w").write(p); time.sleep(0.5)
    open("/sys/bus/usb/drivers/usb/bind","w").write(p); time.sleep(1.5)
def session():
    d=None
    for _ in range(20):
        d=usb.core.find(idVendor=0x147e,idProduct=0x2020)
        if d is not None: break
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
    return d,wr,drain,devkey,Y
combos=[]
for sklen in (48,32):
    for order in ("rev","asis"):
        for e in (65537,3):
            combos.append((sklen,order,e))
for idx,(sklen,order,e) in enumerate(combos):
    rebind(); d,wr,drain,devkey,Y=session()
    n_be = devkey[::-1] if order=="rev" else devkey
    sk=secrets.token_bytes(sklen)
    ct=rsa_enc(n_be,e,sk)
    payload=hashlib.sha256(CTR+M+Y).digest()+ct
    content=bytes.fromhex("08030100000001000000310000003800000000000000030000000000000060000000")+payload
    wr(build_frame(0,0x40,0x87,content)); time.sleep(0.05)
    resp=b"".join(drain(6,700))
    ok=len(resp)>=18 and resp[12:14]==b'\x08\x13' and resp[14:18]==bytes.fromhex("20000000")
    print("sk=%d order=%s e=%d -> %s %s"%(sklen,order,e,"ACCEPTED!!!" if ok else "reject",resp[12:20].hex()))
    usb.util.release_interface(d,0)
    if ok: print("WIN"); break
