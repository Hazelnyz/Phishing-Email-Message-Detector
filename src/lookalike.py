"""Offline domain lookalike detection. Never performs DNS or HTTP requests."""
import re
from urllib.parse import urlsplit

BRANDS={"google.com":"google","microsoft.com":"microsoft","paypal.com":"paypal","apple.com":"apple","amazon.com":"amazon","vit.ac.in":"vit","vtop.vit.ac.in":"vtop"}
CONFUSABLE=str.maketrans({"о":"o","а":"a","е":"e","р":"p","с":"c","х":"x","і":"i","ⅼ":"l","０":"0","１":"1"})
MULTI_SUFFIX={"ac.in","co.in","co.uk","com.au","co.jp"}

def registered_domain(host):
    host=(host or "").lower().strip(".")
    bits=host.split(".")
    if len(bits)<2:return host
    suffix=".".join(bits[-2:])
    return ".".join(bits[-3:]) if suffix in MULTI_SUFFIX and len(bits)>=3 else suffix

def _distance(a,b):
    row=list(range(len(b)+1))
    for i,x in enumerate(a,1):
        nxt=[i]
        for j,y in enumerate(b,1):nxt.append(min(nxt[-1]+1,row[j]+1,row[j-1]+(x!=y)))
        row=nxt
    return row[-1]

def inspect_domain(value):
    raw=str(value or '').strip()
    host=urlsplit(raw if '://' in raw else '//'+raw).hostname or raw
    host=host.lower().rstrip('.')
    norm=host.translate(CONFUSABLE)
    reg=registered_domain(norm)
    ascii_brand=reg.encode('idna').decode('ascii') if reg else reg
    flags=[]
    if 'xn--' in host:flags.append('punycode domain')
    if norm!=host:flags.append('Unicode confusable characters')
    for brand,canonical in BRANDS.items():
        brandreg=registered_domain(brand)
        candidate=registered_domain(host)
        if candidate==brandreg: continue
        compact=candidate.replace('.','')
        expected=brandreg.replace('.','')
        if compact and _distance(compact,expected)<=max(1,len(expected)//5):
            flags.append(f'lookalike of {canonical}')
        # A brand name inside a path-like subdomain is a deceptive claim.
        if host.endswith('.'+brandreg) and host!=brandreg:
            flags.append(f'brand used in untrusted subdomain: {canonical}')
    return {"host":host,"registered_domain":reg,"flags":sorted(set(flags)),"suspicious":bool(flags)}
