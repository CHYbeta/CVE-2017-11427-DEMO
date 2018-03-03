# Copyright (C) 2012 by Dr. Dieter Maurer <dieter@handshake.de>; see 'LICENSE.txt' for details
"""Auxiliary classes to construct signature/encryption templates."""

from lxml.etree import ElementBase, \
     parse as et_parse, fromstring as et_fromstring, XML as et_xml, \
     XMLParser, ElementNamespaceClassLookup, ElementDefaultClassLookup
from dm.xmlsec.binding import DSigNs, dsig, EncNs, enc

# set up our own parser and related `etree` infrastructure
parser = XMLParser()
# apparently, `parser` has a `set_element_class_lookup` but not corresponding `get`
#class_lookup = ElementNamespaceClassLookup(parser.get_element_class_lookup())
class_lookup = ElementNamespaceClassLookup(ElementDefaultClassLookup())
parser.set_element_class_lookup(class_lookup)

Element = parser.makeelement

def SubElement(node, *args, **kw):
  node.append(Element(*args, **kw))

def parse(file, parser=parser): return et_parse(file, parser=parser)
def fromstring(s, parser=parser): return et_fromstring(s, parser=parser)
def XML(s, parser=parser): return et_XML(s, parser=parser)

def mke(tag, *children, **kw):
  e = Element(tag, **kw)
  for c in children: e.append(c)
  return e

def mkse(node, tag, *children, **kw):
  c = mke(tag, *children, **kw)
  node.append(c)
  return c

# Dsig template classes

DSigNsMap = {None:DSigNs}

class _DSigBase(ElementBase):
  NAMESPACE = DSigNs
  PARSER = parser

class _Signature(_DSigBase):
  """auxiliary class representing a signature template."""
  TAG = "Signature"

  def ensureKeyInfo(self, id=None):
    """creates a `KeyInfo` element, if not already present."""
    ki = self.find(dsig("KeyInfo"))
    if ki is None: 
      ki = mke(dsig("KeyInfo"), **(id and dict(Id=id) or {}))
      self[2:2]=[ki]
    return ki

  def addReference(self, digestMethod, id=None, uri=None, type=None):
    ref = Reference(digestMethod, id, uri, type)
    self[0].append(ref)
    return ref

  def addObject(self, id=None, mimeType=None, encoding=None):
    attrib = {}
    if id: attrib["Id"] = id
    if mimeType: attrib["MimeType"] = mimeType
    if encoding: attrib["Encoding"] = encoding
    o = mkse(self, dsig("Object"), attrib=attrib)
    return o

    
def Signature(c14nMethod, signMethod, id=None, nsPrefix=None):
  """`Signature` factory."""
  info = mke(dsig("SignedInfo"))
  mkse(info, dsig("CanonicalizationMethod"), 
             Algorithm=c14nMethod.href
             )
  mkse(info, dsig("SignatureMethod"), Algorithm=signMethod.href)
  attrib = id and dict(Id=id) or None
  nsmap = nsPrefix and {nsPrefix:DSigNs} or DSigNsMap
  return _Signature(info, mke(dsig("SignatureValue")), attrib=attrib, nsmap=nsmap)


class _Reference(_DSigBase):
  TAG = "Reference"

  def addTransform(self, transform):
    ts = self.find(dsig("Transforms"))
    if ts is None:
      ts = mke(dsig("Transforms"))
      self.insert(0, ts)
    return mkse(ts, dsig("Transform"), Algorithm=transform.href)

def Reference(digestMethod, id=None, uri=None, type=None):
    attrib = {}
    if id: attrib["Id"] = id
    if uri: attrib["URI"] = uri
    if type: attrib["Type"] = type
    return mke(
      dsig("Reference"),
      mke(dsig("DigestMethod"), Algorithm=digestMethod.href),
      mke(dsig("DigestValue")),
      attrib=attrib,
      )


class _Object(_DSigBase):
  TAG = "Object"

  def ensureSignProperties(self, id=None):
    sp = self.find(dsig("SignProperties"))
    if sp is None:
      sp = mkse(self, dsig("SignProperties"),
                      attrib = id and dict(Id=id) or None,
                      )
    return sp

  def addSignProperty(self, id=None, target=None):
    attrib = {}
    if id: attrib["Id"] = id
    if target: attrib["Target"] = target
    return mkse(self.ensureSignProperties(),
                      dsig("SignProperties"), attrib=attrib)

  def addManifest(self, id=None):
    attrib = {}
    if id: attrib["Id"] = id
    m = mke(dsig("Manifest"), attrib=attrib)
    self.insert(0, m)
    return m


class _Manifest(_DSigBase):
  TAG = "Manifest"

  def addReference(self, digestMethod, id=None, uri=None, type=None):
    r = Reference(digestMethod, id, uri, type)
    self.insert(0, r)
    return r


class _KeyInfo(_DSigBase):
  TAG = "KeyInfo"
  
  def addKeyName(self, name=None):
    kn = mkse(self, dsig("KeyName"))
    if name is not None: kn.text = name
    return kn
  
  def addKeyValue(self):
    return mkse(self, dsig("KeyValue"))
  
  def addX509Data(self):
    return mkse(self, dsig("X509Data"))

  def addRetrievalMethod(self, uri, type=None):
    attrib = dict(URI=uri)
    if type: attrib["Type"] = type
    return mkse(self, dsig("RetrievalMethod"), attrib=attrib)

  def addEncryptedKey(self, encMethod=None, id=None, type=None, recipient=None):
    e = EncKey(encMethod, id, type, recipient)
    self.append(e)
    return e

  def addXsltStylesheet(self, sheet):
    e = XML(sheet)
    self.append()
    return e

  def addC14NInclNamespaces(self, prefixList=None):
    """add inclusive namespaces for the `ExcC14N` transform.

    *prefixList* is whitespace delimited list of prefixes where `'default` specifies the default prefixes.
    """
    return mkse(
      self,
      mke("{http://www.w3.org/2001/10/xml-exc-c14n#}/InclusiveNamespaces"),
      attrib=prefixList and dict(PrefixList=prefixList) or None
      )

  def addXPath(self, expression, nsmap=None):
    return mkse(self, dsig("XPath"), expression, nsmap=nsmap)

  def addXPath2(self, type, expression, nsmap=None):
    return mkse(
      self,
      mke("{http://www.w3.org/2002/06/xmldsig-filter2}XPath"),
      expression,
      nsmap=nsmap,
      Filter=type
      )





class _Transform(_DSigBase):
  TAG = "Transform"

  def addHmacOutoutLength(self, bitsLen):
    return mkse(self, dsig("HMACOutputLenght"), str(bitsLen))

  def addOAEPparams(self, params):
    # may need to control position
    return mkse(self, enc("OAEPParams"), params.encode("base64"))

class _X509Data(_DSigBase):
  TAG = "X509Data"

  def addIssuerSerial(self):
    return mkse(self, dsig("X509IssuerSerial"))

  def addSubjectName(self):
    return mkse(self, dsig("X509SubjectName"))

  def addSKI(self):
    return mkse(self, dsig("X509SKI"))

  def addCertificate(self):
    return mkse(self, dsig("X509Certificate"))

  def addCRL(self):
    return mkse(self, dsig("X509CRL"))


class _X509IssuerSerial(_DSigBase):
  TAG = "X509IssuerSerial"

  def addIssuerName(self, name=None):
    return mkse(self, dsig("X509IssuerName"),
                      *(name and (name,) or ())
                      )

  def addSerial(self, serial=None):
    return mkse(self, dsig("X509SerialNumber"),
                      *(serial and (serial,) or ())
                      )


# the dsig lookup
dsig_lookup = class_lookup.get_namespace(DSigNs)
for c in (_Signature, _Reference, _Object, _Manifest, _KeyInfo, _Transform,
          _X509Data, _X509IssuerSerial,
          ):
  dsig_lookup[c.TAG] = c


# XMLEnc template classes

EncNsMap = {None:EncNs}

class _EncBase(ElementBase):
  NAMESPACE = EncNs
  PARSER = parser



class _EncType(_EncBase):
  """represents the abstract `EncryptedType`."""
  def ensureKeyInfo(self, id=None):
    ki = self.find(dsig("KeyInfo"))
    if ki is None:
      ki = mke(dsig("KeyInfo"),
                   attrib=id and dict(Id=id) or None,
                   )
      kii = self.find(enc("EncryptionMethod")) is not None and 1 or 0
      self.insert(kii, ki)
    return ki
      
  def ensureEncProperties(self, id=None):
    ep = self.find(enc("EncryptionProperties"))
    if ep is None:
      ep = mkse(self, enc("EncryptionProperties"),
                      attrib=id and dict(Id=id) or None,
                      )
    return ep
      
  def addEncProperty(self, id=None, target=None):
    attrib = {}
    if id: attrib["Id"] = id
    if target: attrib["Target"] = target
    return mkse(self.ensureEncProperties(),
                      enc("EncryptionProperty"), attrib=attrib
                      )

  def ensureCipherValue(self):
    cd = self.find(enc("CipherData"))
    cv = cd.find(enc("CipherValue"))
    if cv is None:
      if len(cd):
        raise ValueError("`CipherData` can only contain a single element")
      cv = mkse(cd, enc("CipherValue"))
    return cv

  def ensureCipherReference(self, uri=None):
    cd = self.find(enc("CipherData"))
    cr = cd.find(enc("CipherReference"))
    if cr is None:
      if len(cd):
        raise ValueError("`CipherData` can only contain a single element")
      cr = mkse(cd, enc("CipherReference"),
                      attrib=uri and dict(URI=uri) or None
                      )
    return cr


class _EncData(_EncType):
  TAG = "EncryptedData"

class _EncKey(_EncType):
  TAG = "EncryptedKey"

  def addDataReference(self, uri=None):
    rl = self.find(enc("ReferenceList"))
    if rl is None:
      rl = mke(self, enc("ReferenceList"))
      self.insert(0, rl)
    return mkse(rl, enc("DataReference"),
                      attrib=uri and dict(URI=uri) or None
                      )

  def addKeyReference(self, uri=None):
    rl = self.find(enc("ReferenceList"))
    if rl is None:
      rl = mke(self, enc("ReferenceList"))
      self.insert(0, rl)
    return mkse(rl, enc("KeyReference"),
                      attrib=uri and dict(URI=uri) or None
                      )


def _EncType_(tag, encMethod=None, id=None, type=None, mimeType=None, encoding=None, recipient=None, nsPrefix=None):
  attrib = {}
  if id: attrib["Id"] = id
  if type: attrib["Type"] = type
  if mimeType: attrib["MimeType"] = mimeTpye
  if encoding: attrib["Encoding"] = encoding
  if recipient: attrib["Recipient"] = recipient
  nsmap = nsPrefix and {nsPrefix:EncNs} or EncNsMap
  et = mke(enc(tag), attrib=attrib, nsmap=nsmap)
  if encMethod:
    mkse(et, enc("EncryptionMethod"), Algorithm=encMethod.href)
  mkse(et, enc("CipherData"))
  return et

def EncData(encMethod=None, id=None, type=None, mimeType=None, encoding=None, nsPrefix=None):
  return _EncType_("EncryptedData", encMethod, id, type, mimeType, encoding, nsPrefix=nsPrefix)

def EncKey(encMethod=None, id=None, type=None, recipient=None, nsPrefix=None):
  return _EncType_("EncryptedKey", encMethod, id, type, None, None, recipient, nsPrefix=nsPrefix)
  
  
class _CipherReference(_EncBase):
  TAG = "CipherReference"

  def addTransform(self, transform):
    ts = self.find(enc("Transforms"))
    if ts is None: ts = mkse(self, enc("Transforms"))
    t = mkse(ts, dsig("Transform"), Algorithm=transform.href)
    return t


# the enc lookup
enc_lookup = class_lookup.get_namespace(EncNs)
for c in (_EncData, _EncKey, _CipherReference):
  enc_lookup[c.TAG] = c
