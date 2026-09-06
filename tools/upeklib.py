import usb.core, usb.util, time, os, glob, hashlib, secrets
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES
M=bytes.fromhex("941cf8d63afb0cff1a96531e9b28e5fe07147365e1bac869d4609cc9ad8a8804")
CTR=bytes.fromhex("e38f7cb3")
def _sp():
    for dd in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        if open(dd).read().strip()=="147e" and open(os.path.dirname(dd)+"/idProduct").read().strip()=="2020":
            return os.path.basename(os.path.dirname(dd))
def _crc16(d):
    c=0
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xffff if c&0x8000 else (c<<1)&0xffff
    return c.to_bytes(2,"little")
def _rsa(mod64,e,msg):
    n=int.from_bytes(mod64,"little"); ps=b""
    while len(ps)<64-3-len(msg):
        x=secrets.token_bytes(1)
        if x!=b"\x00": ps+=x
    return pow(int.from_bytes(b"\x00\x02"+ps+b"\x00"+msg,"big"),e,n).to_bytes(64,"big")
class Upek:
    def __init__(self):
        p=_sp()
        open("/sys/bus/usb/drivers/usb/unbind","w").write(p); time.sleep(0.5)
        open("/sys/bus/usb/drivers/usb/bind","w").write(p); time.sleep(1.8)
        d=None
        for _ in range(25):
            d=usb.core.find(idVendor=0x147e,idProduct=0x2020)
            if d: break
            time.sleep(0.4)
        usb.util.claim_interface(d,0); self.d=d; self.sub=0x50
    def _rd(self,t=800):
        try: return bytes(self.d.read(0x81,512,t))
        except usb.core.USBError: return None
    def _drain(self,n=12,t=500):
        o=[]
        for _ in range(n):
            r=self._rd(t)
            if r is None: break
            o.append(r)
        return o
    def _wr(self,h): self.d.write(0x02,bytes.fromhex(h) if isinstance(h,str) else h,1000)
    def _bf(self,seq,sub,b6,content):
        head=b"Ciao"+bytes([seq,sub,b6,0x28])+(len(content)+2).to_bytes(4,"little")
        return head+content+_crc16(head[4:]+content)
    def handshake(self):
        d=self.d
        d.ctrl_transfer(0xc0,0x04,0,0,8,1000); d.ctrl_transfer(0xc0,0x04,0,0,8,1000)
        d.ctrl_transfer(0x40,0x0c,0x0100,0x0400,b"\x00",1000); self._drain(2,400)
        devkey=Y=None
        for i,f in enumerate(["4369616f04000801005e01000000000d65","4369616f00000728040000000604c0d6",
                "4369616f00100b280800000002040b0000006556","4369616f00200b280800000051040a00000079a5",
                "4369616f00300b28080000000704200000005d11"]):
            self._wr(f); time.sleep(0.03); r=b"".join(self._drain(6,600))
            if i==2: j=r.find(bytes.fromhex("030020002000")); devkey=r[j+6:j+6+64]
            if i==4: j=r.find(b'\x07\x14'); Y=r[j+2:j+2+32]
        sk=secrets.token_bytes(48)
        content=bytes.fromhex("08030100000001000000310000003800000000000000030000000000000060000000")+hashlib.sha256(CTR+M+Y).digest()+_rsa(devkey,17,sk)
        self._wr(self._bf(0,0x40,0x87,content)); time.sleep(0.05)
        resp=b"".join(self._drain(8,800))
        assert resp[12:14]==b'\x08\x13', "frame11 rejected: "+resp[12:20].hex()
        aeskey=hashlib.sha256(bytes.fromhex("62466e8d")+Y+sk+M).digest()[:7]+b"\x00"*9
        self.txc=AES.new(aeskey,AES.MODE_CBC,b"\x00"*16)
        self.rxc=AES.new(aeskey,AES.MODE_CBC,b"\x00"*16)
    def cmd(self, payload, tmo=800):
        # payload: bytes, will be zero-padded to 16-multiple, CBC-enc, wrapped in 0080 frame
        pl=payload+b"\x00"*((16-len(payload)%16)%16)
        ct=self.txc.encrypt(pl)
        self._wr(self._bf(0,self.sub,0x17,bytes.fromhex("0080")+ct)); time.sleep(0.05)
        self.sub=(self.sub+0x10)&0xff
        r=b"".join(self._drain(12,tmo))
        j=r.find(bytes.fromhex("0080"),12)
        if j<0: return None,r
        ctb=r[j+2:]; nn=(len(ctb)//16)*16
        return (self.rxc.decrypt(ctb[:nn]) if nn>=16 else b""),r
    def close(self): usb.util.release_interface(self.d,0)
def channel_cmd(code16, param=b""):
    return bytes([0,0])+code16.to_bytes(2,"little")+param
