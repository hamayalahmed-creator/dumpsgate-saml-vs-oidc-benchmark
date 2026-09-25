import base64, datetime as dt, json, statistics, time, uuid, urllib.parse, platform
from copy import deepcopy
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signxml import XMLSigner, XMLVerifier, methods
import jwt, signxml, cryptography, lxml

# ---------- keys ----------
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256()))
key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
cert_pem = cert.public_bytes(serialization.Encoding.PEM)
pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

ISS = "https://idp.example.com"
AUD = "https://app.example.com"
ACS = "https://app.example.com/saml/acs"
def iso(t): return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def user(n_groups):
    return dict(sub="8f14e45f-ceea-467a-9b2c-1a2b3c4d5e6f", email="jane.doe@example.com",
                given_name="Jane", family_name="Doe",
                groups=[f"group-{i:02d}" for i in range(n_groups)])

P = "urn:oasis:names:tc:SAML:2.0:protocol"; A = "urn:oasis:names:tc:SAML:2.0:assertion"
OID = {"email": "urn:oid:0.9.2342.19200300.100.1.3", "given_name": "urn:oid:2.5.4.42",
       "family_name": "urn:oid:2.5.4.4", "groups": "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"}

def saml_response(u):
    rid, aid = "_" + uuid.uuid4().hex, "_" + uuid.uuid4().hex
    req = "_" + uuid.uuid4().hex
    r = etree.Element(f"{{{P}}}Response", nsmap={"samlp": P, "saml": A},
        ID=rid, Version="2.0", IssueInstant=iso(now), Destination=ACS, InResponseTo=req)
    etree.SubElement(r, f"{{{A}}}Issuer").text = ISS
    st = etree.SubElement(r, f"{{{P}}}Status")
    etree.SubElement(st, f"{{{P}}}StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    a = etree.SubElement(r, f"{{{A}}}Assertion", ID=aid, Version="2.0", IssueInstant=iso(now))
    etree.SubElement(a, f"{{{A}}}Issuer").text = ISS
    s = etree.SubElement(a, f"{{{A}}}Subject")
    etree.SubElement(s, f"{{{A}}}NameID", Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent").text = u["sub"]
    sc = etree.SubElement(s, f"{{{A}}}SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    etree.SubElement(sc, f"{{{A}}}SubjectConfirmationData", NotOnOrAfter=iso(now + dt.timedelta(minutes=5)),
                     Recipient=ACS, InResponseTo=req)
    c = etree.SubElement(a, f"{{{A}}}Conditions", NotBefore=iso(now - dt.timedelta(minutes=1)),
                         NotOnOrAfter=iso(now + dt.timedelta(minutes=5)))
    ar = etree.SubElement(c, f"{{{A}}}AudienceRestriction")
    etree.SubElement(ar, f"{{{A}}}Audience").text = AUD
    au = etree.SubElement(a, f"{{{A}}}AuthnStatement", AuthnInstant=iso(now), SessionIndex=aid)
    ac = etree.SubElement(au, f"{{{A}}}AuthnContext")
    etree.SubElement(ac, f"{{{A}}}AuthnContextClassRef").text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    ats = etree.SubElement(a, f"{{{A}}}AttributeStatement")
    for k in ["email", "given_name", "family_name", "groups"]:
        at = etree.SubElement(ats, f"{{{A}}}Attribute", Name=OID[k],
                              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName=k)
        vals = u[k] if isinstance(u[k], list) else [u[k]]
        for v in vals:
            etree.SubElement(at, f"{{{A}}}AttributeValue").text = v
    # sign the assertion (enveloped, RSA-SHA256, exc-c14n, cert in KeyInfo), as most IdPs do
    signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256",
                       digest_algorithm="sha256", c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    signed_a = signer.sign(a, key=key_pem, cert=cert_pem, reference_uri=aid)
    # move signature to after Issuer, per SAML schema
    sig = signed_a.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
    signed_a.remove(sig); signed_a.insert(1, sig)
    r.replace(a, signed_a)
    return etree.tostring(r)

def id_token(u):
    claims = dict(iss=ISS, sub=u["sub"], aud="client-7f3a9c", exp=int((now + dt.timedelta(minutes=60)).timestamp()),
                  iat=int(now.timestamp()), auth_time=int(now.timestamp()), nonce=uuid.uuid4().hex,
                  amr=["pwd"], email=u["email"], email_verified=True, given_name=u["given_name"],
                  family_name=u["family_name"], groups=u["groups"])
    return jwt.encode(claims, key_pem, algorithm="RS256", headers={"kid": "key-2026-01"})

results = {"env": dict(python=platform.python_version(), signxml="4.x" , pyjwt=jwt.__version__,
                       cryptography=cryptography.__version__, lxml=lxml.__version__, cpu=platform.processor() or platform.machine())}

# ---------- Test 1: payload size ----------
size = {}
for n in [3, 20, 100]:
    u = user(n)
    x = saml_response(u)
    b64 = base64.b64encode(x)
    form = urllib.parse.urlencode({"SAMLResponse": b64, "RelayState": "/dashboard"}).encode()
    t = id_token(u)
    size[n] = dict(saml_xml=len(x), saml_b64=len(b64), saml_post_body=len(form), jwt=len(t))
results["size"] = size

# ---------- Test 2: verification latency ----------
u = user(3); x = saml_response(u); t = id_token(u)
def bench(fn, n):
    for _ in range(20): fn()
    ts = []
    for _ in range(n):
        s = time.perf_counter(); fn(); ts.append((time.perf_counter() - s) * 1000)
    return dict(median_ms=round(statistics.median(ts), 3), p95_ms=round(sorted(ts)[int(n * .95)], 3), n=n)
def v_saml():
    doc = etree.fromstring(x)
    a = doc.find(f"{{{A}}}Assertion")
    XMLVerifier().verify(a, x509_cert=cert_pem.decode()).signed_xml
def v_jwt():
    jwt.decode(t, pub_pem, algorithms=["RS256"], audience="client-7f3a9c", issuer=ISS)
results["verify"] = dict(saml=bench(v_saml, 1000), jwt=bench(v_jwt, 5000))

# ---------- Test 3: tamper + unsafe-input rejection ----------
tamper = {}
# SAML: change email after signing
d = etree.fromstring(x)
d.find(f".//{{{A}}}AttributeValue").text = "attacker@example.com"
try:
    XMLVerifier().verify(d.find(f"{{{A}}}Assertion"), x509_cert=cert_pem.decode()); tamper["saml_modified_attr"] = "ACCEPTED"
except Exception as e: tamper["saml_modified_attr"] = f"rejected ({type(e).__name__})"
# SAML: document with DOCTYPE / internal entity
dtd = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]>' + x
try:
    XMLVerifier().verify(dtd, x509_cert=cert_pem.decode()); tamper["saml_doctype"] = "ACCEPTED"
except Exception as e: tamper["saml_doctype"] = f"rejected ({type(e).__name__})"
# JWT: change payload
h, p, s = t.split(".")
pl = json.loads(base64.urlsafe_b64decode(p + "==")); pl["email"] = "attacker@example.com"
p2 = base64.urlsafe_b64encode(json.dumps(pl).encode()).rstrip(b"=").decode()
try:
    jwt.decode(f"{h}.{p2}.{s}", pub_pem, algorithms=["RS256"], audience="client-7f3a9c", issuer=ISS); tamper["jwt_modified_claim"] = "ACCEPTED"
except Exception as e: tamper["jwt_modified_claim"] = f"rejected ({type(e).__name__})"
# JWT: alg=none token
none_tok = jwt.encode(pl, None, algorithm="none")
try:
    jwt.decode(none_tok, pub_pem, algorithms=["RS256"], audience="client-7f3a9c", issuer=ISS); tamper["jwt_alg_none"] = "ACCEPTED"
except Exception as e: tamper["jwt_alg_none"] = f"rejected ({type(e).__name__})"
# JWT: wrong audience
try:
    jwt.decode(t, pub_pem, algorithms=["RS256"], audience="other-client", issuer=ISS); tamper["jwt_wrong_aud"] = "ACCEPTED"
except Exception as e: tamper["jwt_wrong_aud"] = f"rejected ({type(e).__name__})"
# SAML: wrong audience -> signature library does NOT check it
v = XMLVerifier().verify(etree.fromstring(x).find(f"{{{A}}}Assertion"), x509_cert=cert_pem.decode())
aud = v.signed_xml.find(f".//{{{A}}}Audience").text
tamper["saml_wrong_aud_signature_only"] = "signature valid; audience NOT checked by signature library (app must check: expected other-app, got %s)" % aud
results["tamper"] = tamper

# ---------- Test 4: configuration artifacts ----------
M = "urn:oasis:names:tc:SAML:2.0:metadata"; DS = "http://www.w3.org/2000/09/xmldsig#"
cert_b64 = "".join(cert_pem.decode().splitlines()[1:-1])
def metadata(kind):
    ed = etree.Element(f"{{{M}}}EntityDescriptor", nsmap={"md": M, "ds": DS},
                       entityID=AUD if kind == "sp" else ISS)
    if kind == "sp":
        d = etree.SubElement(ed, f"{{{M}}}SPSSODescriptor", AuthnRequestsSigned="true", WantAssertionsSigned="true",
                             protocolSupportEnumeration=P)
    else:
        d = etree.SubElement(ed, f"{{{M}}}IDPSSODescriptor", WantAuthnRequestsSigned="false", protocolSupportEnumeration=P)
    kd = etree.SubElement(d, f"{{{M}}}KeyDescriptor", use="signing")
    ki = etree.SubElement(kd, f"{{{DS}}}KeyInfo"); xd = etree.SubElement(ki, f"{{{DS}}}X509Data")
    etree.SubElement(xd, f"{{{DS}}}X509Certificate").text = cert_b64
    etree.SubElement(d, f"{{{M}}}NameIDFormat").text = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    if kind == "sp":
        etree.SubElement(d, f"{{{M}}}AssertionConsumerService", Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location=ACS, index="0")
    else:
        etree.SubElement(d, f"{{{M}}}SingleSignOnService", Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location=ISS + "/saml/sso")
    return etree.tostring(ed)
sp_md, idp_md = metadata("sp"), metadata("idp")
oidc_client_cfg = {"issuer": ISS, "client_id": "client-7f3a9c", "redirect_uri": "https://app.example.com/callback", "scope": "openid email profile"}
results["config"] = dict(saml_sp_metadata_bytes=len(sp_md), saml_idp_metadata_bytes=len(idp_md),
                         saml_values_to_exchange=["SP entityID", "ACS URL", "SP signing cert (if signed requests)", "IdP entityID", "IdP SSO URL", "IdP signing certificate", "NameID format", "attribute mapping"],
                         oidc_values_to_enter=list(oidc_client_cfg.keys()) + ["client_secret (confidential clients only)"],
                         oidc_client_cfg_bytes=len(json.dumps(oidc_client_cfg)))

json.dump(results, open("results.json", "w"), indent=2)
print(json.dumps(results, indent=2))
open("sample_saml.xml", "wb").write(saml_response(user(3)))
open("sample_idtoken.txt", "w").write(id_token(user(3)))
