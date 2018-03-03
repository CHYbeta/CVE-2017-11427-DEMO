This package contains a Cython (http://cython.org/) based bindung
to Aleksey Sanin's XML security library ("http://www.aleksey.com/xmlsec")
to be used together with lxml (http://lxml.de), the most popular Python
binding to the Gnome XML library libxml2 (http://xmlsoft.org).


Installation
============

Installation of this package requires that you have previously installed
`setuptools` (http://pypi.python.org/pypi/setuptools) or an equivalent
package manager.

In addition, you must have installed the development packages for
libxml2 and the XML security library (often called ``libxmlsec1``)
on the operating system level.

The installation will install ``lxml``, if not yet already installed.

This package interfaces with ``lxml`` via its Cython interface
(described in ``etreepublic.pxd``). Some operating system installations
for ``lxml`` lack the respective files. In those cases, you may need to
download an `lxml` source distribution and let the environment
variable ``LXML_HOME`` point to its root.

``xmlsec`` can use different cryptographic engines (currently ``openssl``,
``gnutls`` and ``nss``). By default, this package configures
``xmlsec`` to use its default engine. Should you require a different
engine, you can set the envvar ``XMLSEC_CRYPTO_ENGINE`` to the corresponding
value. In this case, you may need to pass the name of your crypto engine
to the ``initialize`` function.

I have tried installation only on Linux, it may not work on other
platforms.


Important differences with ``xmlsec``
=====================================

Object orientation
------------------

``xmlsec`` is a "C" library. As such, it provides its main functionality
by functions. Most of the functions are primarily associated with 
a special kind of data structure (key, keys manager, signature/encryption
context, template) where the association is expressed in the
function name and the type of its first argument.

This binding uses classes to represent the concepts ``Key``,
``KeysMngr`` (keys manager), ``DSigCtx`` (digital signature context)
and ``EncCtx`` (encryption context) and the module ``tmpl`` to
provide access to templates.

The names (for functions, methods, constants) are usually derived
from the respective ``xmlsec`` names but prefixes determined
by the binding environment are removed and for functions/methods
the first letter is decapitalized. For example, the xmlsec
``xmlSecDSigCtxSign`` function is represented by the ``sign`` method
of the ``DSigCtx`` class. There are some exceptions to the
rule. For example, the xmlsec ``xmlSecCryptoAppDefaultKeysMngrAdoptKey``
function becomes the ``addKey`` method of class ``KeysMngr``
reflecting that we only support "default keys managers" and that
we do not support keys adoption (but copy the key).


Keys
----

``xmlsec`` treats keys as somewhat "volatile" objects: they are normally created
but are then passed over to either a ``KeysMngr`` or a signature/encryption
context which then control the keys lifetime (and validity). This semantics is
a bit difficult to emulate in Python - and I decided not to try.
Instead, I model keys as normal Python objects (with independent
lifetime) **but** copy the encapsulated ``xmlsec`` key whenever
it is passed over to a ``KeysMngr`` or a signature/encryption
context. This has important ramifications: you do not need to worry
about the validity of a key (it is valid as long as you have a handle to it);
however, modifications to a key have no effects on the (copied)
``xmlsec`` key previously passed over to a keys manager or
signature/encryption context. This forces some changes in the
way keys are handled in the standard ``xmlsec`` examples (below).

As a consequence, signature/encryption contexts allow the setting
of a key but you cannot retrieve them again.

Should experience show that this is too confusing or restricting,
I may change the modeling of keys in future versions.


Attribute access
----------------

``xmlsec`` is not completely homogenous with respect to attribute access.
Sometimes, the attribute is accessed directly; other times, there
are "get/set" methods. This binding never uses "get/set" methods but
always properties.


Id suffix suppression
---------------------

``xmlsec`` identifies many objects (transforms, algoritms, key types) by ids
and emphasizes this by appending `Id` to the corresponding names.
In my view, this is an irrelevant implementation detail and I have
suppressed all `Id` suffixes.


Accessing encryption/decryption results
---------------------------------------

``xmlsec`` encryption/decryption can either operate on binary data
or nodes in an XML tree. In the latter case, the tree is modified in place.

With ``lxml``, you do not have direct access to the tree; instead, you
access it via proxy objects referencing nodes in the tree.
There is a good chance that some of those proxy objects get "confused"
when the tree is changed: they can behave surprisingly after the change.

As a consequence, you should avoid accessing a tree after
an encryption/decryption operation via ``lxml`` references you
have set up before the operation. Especially, the reference
to the encrypted/decrypted node (usually) **does not** reflect the result
and you should consider its value as undefined.
If the operation has
operated on the root of the tree, the same applies to the
``lxml`` element tree for the tree.

In order for you to access the operation result in a safe way, the
encryption/decryption methods return it. For ``encryptXml``, the result
is the (``lxml`` reference to the) ``EncryptedData`` node representing
the encrypted part of the tree. If ``decrypt`` results in an XML result
(rather than binary data), then its result specifies the root of
the decrypted subtree (which usually is not the root of the whole tree).
Applying ``getroottree`` to an XML result of ``encryptXml``/``decrypt``
gives a (new) safe reference to the whole tree.

The ``xmlsec`` examples have been modified to reflect this peculiarity
of the ``lxml`` binding.


Failure handling
----------------

As a C library, ``xmlsec`` mostly uses return codes to indicate success/failure
for its functions.
In rare situations, a "status" field needs to be checked as well. 
In Python, we have exceptions. Thus, I change failure handling: any
failure is indicated by an exception. Currently, there are two exception
classes: the base class ``Error`` and a derived class ``VerificationError``.
``Error`` is used whenever the return code of an ``xmlsec`` function
indicates a failure. ``VerificationError`` is used for signature
verification when the ``verify`` call returned an "ok" status but
the status field in the context indicates that the verification failed.



Binding extent
--------------

The binding is by far not complete. It only covers ``Key``,
``KeysMngr`` and signature/encryption context as far as required
either by me or the examples.

It is likely that the binding will become more complete over time.


Documentation
=============

I do not like separate documentation (apart from overviews).
I am a fan of documentation derived automatically from the source -- if
possible available directly inside the Python session.
As a consequence, you can use ``pydoc`` or Python's ``help`` builtin
to get detailed documentation (apart from looking at the source and
reading this overview).


Examples
========

This section shows how the XML security library examples from
http://www.aleksey.com/xmlsec/api/xmlsec-examples.html
look in Python.

For background, please also read
http://www.aleksey.com/xmlsec/api/xmlsec-notes-sign-encrypt.html
and
http://www.aleksey.com/xmlsec/api/xmlsec-notes-verify-decrypt.html


Initialization
--------------

Always ensure that the ``xmlsec`` library is properly initialized.
Otherwise, it fails in dubious ways. All following examples
assume that the code below has been executed.

>>> import dm.xmlsec.binding as xmlsec
>>> xmlsec.initialize()

Some imports used in our examples

>>> from os.path import dirname, basename
>>> from lxml.etree import tostring


We also set up some constants for the examples below.

>>> BASEDIR = dirname(xmlsec.__file__) + "/resources/"



Signing an XML file
-------------------

What is signed actually is a standard XML file containing somewhere
a signature template. The template describes how the signature should
be performed and contains placeholders for the signature parts.
The XML security libraries examples view the complete XML file as
a template. Below is a function which signs such a template.

>>> def sign_file(tmpl_file, key_file):
...     """sign *tmpl_file* with key in *key_file*.
... 
...     *tmpl_file* actually contains an XML document containing a signature
...     template. It can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains the PEM encoded private key. It must be a filename string.
...     """
...     from lxml.etree import parse, tostring
...     doc = parse(tmpl_file)
...     # find signature node
...     node = xmlsec.findNode(doc, xmlsec.dsig("Signature"))
...     dsigCtx = xmlsec.DSigCtx()
...     # Note: we do not provide read access to `dsigCtx.signKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the key name
...     #  before we assign it to `dsigCtx`
...     signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     signKey.name = basename(key_file)
...     # Note: the assignment below effectively copies the key
...     dsigCtx.signKey = signKey
...     dsigCtx.sign(node)
...     return tostring(doc)
... 
>>> signed_file = sign_file(BASEDIR + "sign1-tmpl.xml", BASEDIR + "rsakey.pem")
>>> print signed_file
<!-- 
XML Security Library example: Simple signature template file for sign1 example. 
--><Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>9H/rQr2Axe9hYTV2n/tCp+3UIQQ=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>B5tc2Kz3vc4qcTx810771Nk90qd/5p//SIAd9Ye9SIiU5vKelnvgHSy76rjTvpzE
PszGyWA3H3JOrh/fOHmfoxdCRweuO9eDMhQADem++m55+5HTnT2K5i3IfsAID2Si
EVOi6pGa7tmH1hXIce2uP7zSBjnKUt3nvjbFv8rK9wh7WyXXNASTa5vS8wbcaLKF
FQGVqDVSIzyIYZVnlWPVgeIvpun6nynl4r2Az9KZxlc1Z9JXg1hJV9n6M7leL4pf
O51M3whkD3PnFYgTgScb7qdTSTU7EzgWRmgeq3WXNTxFfXN7xozKSPGRDUj7Q5Xr
oOvoa8PZFwUwJP5A+7RCdw==</SignatureValue>
    <KeyInfo>
	<KeyName>rsakey.pem</KeyName>
    </KeyInfo>
  </Signature>
</Envelope>


Signing a dynamically created template
--------------------------------------

This package does not bind the XML Security library template
functions but implements corresponding functionality directly
via ``lxml``. It is implemented in module ``dm.xmlsec.binding.tmpl``
which sets up a specialized parser, registers enhanced element classes for
the elements occuring in templates and redefines standard `lxml`
infrastructure (``parse``, ``Element``, ``SubElement``, ``fromstring``) to
use this parser. Thus, using the infrastructure provided by module ``tmpl``,
you can create elements or element trees in any way supported
by ``lxml`` and when a [sub]element corresponds to an element in
a template it has additional methods to help in the template
construction.

In addition, the module provides factories (``Signature`` and ``EncData``)
which facilitate the creation of the top level structure of a signature
or encryption template.

>>> def sign_file_create_template(xml_file, key_file):
...     """add signature node to *xml_file* and sign with *key_file*.
... 
...     *xml_file* can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains the PEM encoded private key. It must be a filename string.
...     """
...     # template aware infrastructure
...     from dm.xmlsec.binding.tmpl import parse, Element, SubElement, \
...          fromstring, XML
...     from dm.xmlsec.binding.tmpl import Signature
...     
...     doc = parse(xml_file)
...     signature = Signature(xmlsec.TransformExclC14N,
...                           xmlsec.TransformRsaSha1
...                           )
...     doc.getroot().insert(0, signature)
...     ref = signature.addReference(xmlsec.TransformSha1)
...     ref.addTransform(xmlsec.TransformEnveloped)
...     key_info = signature.ensureKeyInfo()
...     key_info.addKeyName()
...     # now what we already know
...     dsigCtx = xmlsec.DSigCtx()
...     # Note: we do not provide read access to `dsigCtx.signKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the key name
...     #  before we assign it to `dsigCtx`
...     signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     signKey.name = basename(key_file)
...     # Note: the assignment below effectively copies the key
...     dsigCtx.signKey = signKey
...     dsigCtx.sign(signature)
...     return tostring(doc)
... 
>>> print sign_file_create_template(BASEDIR + "sign2-doc.xml", BASEDIR + "rsakey.pem")
<!-- 
XML Security Library example: Original XML doc file for sign2 example. 
--><Envelope xmlns="urn:envelope">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>HjY8ilZAIEM2tBbPn5mYO1ieIX4=</DigestValue></Reference></SignedInfo><SignatureValue>GPl4vqQfQ0+b0a4mpwYXD63WA0XZEbjYvPUrCC5ySocjbnS7eofnLxpgW7AdTnaX
3ws3zj9i184Txm26/pLu/AMQ6ezeMidod6pm5anDlRQq0WCBzxyDJo0SGo7StuFS
kN6vRPLWr6fsnzlWdvYXCf7AXK17ANSskSNzoiQCPFYi2yISCAZlOhle9GSgMe4z
iUjrvdRU9b5zan+yBfloWw3tsRBDqcIm0xDWcUHavcn9wxuX+7QTl+B+Qe6OZJJO
4dM1ESmjhamEFtqSiij20HSUp32AUXiKIeKnFdT4hYuacwEdF5ZXVUQ79pLBxfIR
wlyXAHbqFba/h/Qxe8FMIQ==</SignatureValue><KeyInfo><KeyName>rsakey.pem</KeyName></KeyInfo></Signature><Data>
	Hello, World!
  </Data>
</Envelope>


Signing with an X509 certificate
--------------------------------

>>> def sign_file_with_certificate(xml_file, key_file, cert_file):
...     """sign *xml_file* with *key_file* and include content of *cert_file*.
...     *xml_file* can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains the PEM encoded private key. It must be a filename string.
... 
...     *cert_file* contains a PEM encoded certificate (corresponding to *key_file*),
...     included as `X509Data` in the dynamically created `Signature` template.
...     """
...     # template aware infrastructure
...     from dm.xmlsec.binding.tmpl import parse, Element, SubElement, \
...          fromstring, XML
...     from dm.xmlsec.binding.tmpl import Signature
...     
...     doc = parse(xml_file)
...     signature = Signature(xmlsec.TransformExclC14N,
...                           xmlsec.TransformRsaSha1
...                           )
...     doc.getroot().insert(0, signature)
...     ref = signature.addReference(xmlsec.TransformSha1)
...     ref.addTransform(xmlsec.TransformEnveloped)
...     key_info = signature.ensureKeyInfo()
...     key_info.addKeyName()
...     key_info.addX509Data()
...     # now what we already know
...     dsigCtx = xmlsec.DSigCtx()
...     # Note: we do not provide read access to `dsigCtx.signKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the certificate
...     signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     signKey.loadCert(cert_file, xmlsec.KeyDataFormatPem)
...     # Note: the assignment below effectively copies the key
...     dsigCtx.signKey = signKey
...     dsigCtx.sign(signature)
...     return tostring(doc)
... 
>>> print sign_file_with_certificate(BASEDIR + "sign3-doc.xml", BASEDIR + "rsakey.pem", BASEDIR + "rsacert.pem")
<!-- 
XML Security Library example: Original XML doc file for sign3 example. 
--><Envelope xmlns="urn:envelope">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>HjY8ilZAIEM2tBbPn5mYO1ieIX4=</DigestValue></Reference></SignedInfo><SignatureValue>GPl4vqQfQ0+b0a4mpwYXD63WA0XZEbjYvPUrCC5ySocjbnS7eofnLxpgW7AdTnaX
3ws3zj9i184Txm26/pLu/AMQ6ezeMidod6pm5anDlRQq0WCBzxyDJo0SGo7StuFS
kN6vRPLWr6fsnzlWdvYXCf7AXK17ANSskSNzoiQCPFYi2yISCAZlOhle9GSgMe4z
iUjrvdRU9b5zan+yBfloWw3tsRBDqcIm0xDWcUHavcn9wxuX+7QTl+B+Qe6OZJJO
4dM1ESmjhamEFtqSiij20HSUp32AUXiKIeKnFdT4hYuacwEdF5ZXVUQ79pLBxfIR
wlyXAHbqFba/h/Qxe8FMIQ==</SignatureValue><KeyInfo><KeyName/><X509Data>
<X509Certificate>MIID3zCCAscCCQCsJYoNNCLPzjANBgkqhkiG9w0BAQUFADCBszELMAkGA1UEBhMC
REUxETAPBgNVBAgTCFNhYXJsYW5kMRIwEAYDVQQHEwlFcHBlbGJvcm4xGjAYBgNV
BAoTEWRtLnhtbHNlYy5iaW5kaW5nMSEwHwYDVQQLExhFeGFtcGxlIFJvb3QgQ2Vy
dGlmaWNhdGUxGjAYBgNVBAMTEWRtLnhtbHNlYy5iaW5kaW5nMSIwIAYJKoZIhvcN
AQkBFhNkaWV0ZXJAaGFuZHNoYWtlLmRlMB4XDTEyMDYxNTE0Mzg1NFoXDTMxMDgx
NTE0Mzg1NFowga4xCzAJBgNVBAYTAkRFMREwDwYDVQQIEwhTYWFybGFuZDESMBAG
A1UEBxMJRXBwZWxib3JuMRowGAYDVQQKExFkbS54bWxzZWMuYmluZGluZzEcMBoG
A1UECxMTRXhhbXBsZSBjZXJ0aWZpY2F0ZTEaMBgGA1UEAxMRZG0ueG1sc2VjLmJp
bmRpbmcxIjAgBgkqhkiG9w0BCQEWE2RpZXRlckBoYW5kc2hha2UuZGUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDG2XhPbbMvKvwFRZ68Rk/gAGfz80Jw
sO3Cn/c6Ru99L1cimjFz7V8izjpU1Kz+XbFr89mrNVew4SRAFrrtJrKrEfD2IPMc
+FEOVxtiUaRYcO+jTrMsfI3jpSb3Bnlkd/H90W6713whk4J7DcKJiaVHLZtUm5FP
WABKsiyevzrJvxHVyC4aE0lYzrllVxpKf5xGinwAuY67O7ODAMdFQfvtIkJLp938
mwXONgxmC9LAc6lBXK4ER4XhF9zWGVdgHFK3i7SdqQbRSCg8XRLKDQquOmIZoSF+
aq1sVz2NfZIEiS2rfDgh6PquTR/WXgS3txpcQmq1fG9a72HM4V1fEDUtAgMBAAEw
DQYJKoZIhvcNAQEFBQADggEBACYexrHl0hECRAV66UDmSeIw3V1gBR9tqYE9Q3LP
N0jBZA+hQi1oa5PLqwG3LbIHYRwXLThvBMsUNfsAFLvfMJTbRGan8RqUapEdb3nm
DNZKHG5Sf2bfzIyIb8GnGDLC47sjVK9+ujQuH/xUjiOsf2c5GNJHyibxgq0G1vQq
tf00D3SV9AkRsSeBjV8irNHk1J/SALFdSnycT4rgUbuvEb0b9FPaHJBxkjFbrSnV
AVc9F/lrx5uDFhd+FaRTbQcaQzG0UyyHlEa/kUp7Bclz0KD21Rb7GOglqUGK+UK2
5AvjVnxazsV0DJzTyRVdJ9QiNqOiPzGvMd1cIxPI5NJQEw0=</X509Certificate>
</X509Data></KeyInfo></Signature><Data>
	Hello, World!
  </Data>
</Envelope>


Verifying a signature with a single key
---------------------------------------

>>> def verify_file(xml_file, key_file):
...     """verify signature in *xml_file* with key in *key_file*.
... 
...     *xml_file* contains the signed XML document.
...     It can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains the PEM public key. It must be a filename.
... 
...     An exception is raised when the verification fails.
...     """
...     from lxml.etree import parse
...     doc = parse(xml_file)
...     node = doc.find(".//{%s}Signature" % xmlsec.DSigNs)
...     dsigCtx = xmlsec.DSigCtx()
...     # Note: we do not provide read access to `dsigCtx.signKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the key name
...     #  before we assign it to `dsigCtx`
...     signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     signKey.name = basename(key_file)
...     # Note: the assignment below effectively copies the key
...     dsigCtx.signKey = signKey
...     dsigCtx.verify(node)
... 
>>> from StringIO import StringIO
>>> verify_file(StringIO(signed_file), BASEDIR + "rsapub.pem")



Verifying a signature with a keys manager
-----------------------------------------

>>> def load_keys(*keys):
...     """return `KeysMngr` with *keys*.
... 
...     *keys* is a sequence of filenames containing PEM encoded keys.
...     """
...     mngr = xmlsec.KeysMngr()
...     for k in keys:
...         # must set the key name before we add the key to `mngr`
...         key = xmlsec.Key.load(k, xmlsec.KeyDataFormatPem)
...         key.name = basename(k)
...         # adds a copy of *key*
...         mngr.addKey(key)
...     return mngr
... 
>>> def verify_file_with_keysmngr(xml_file, mngr):
...     """verify *xml_file* with keys manager *mngr*.
... 
...     *xml_file* contains the signed XML document.
...     It can be a file, a filename string or an HTTP/FTP url.
...     """
...     from lxml.etree import parse
...     doc = parse(xml_file)
...     node = doc.find(".//{%s}Signature" % xmlsec.DSigNs)
...     dsigCtx = xmlsec.DSigCtx(mngr)
...     dsigCtx.verify(node)
... 
>>> mngr = load_keys(BASEDIR + "rsapub.pem")
>>> verify_file_with_keysmngr(StringIO(signed_file), mngr)


Verifying a signature with X509 certificates
--------------------------------------------


>>> def load_trusted_certs(*certs):
...     """return keys manager trusting *certs*.
... 
...     *certs* is a sequence of filenames containing PEM encoded certificates
...     """
...     mngr = xmlsec.KeysMngr()
...     for c in certs:
...         mngr.loadCert(c, xmlsec.KeyDataFormatPem, xmlsec.KeyDataTypeTrusted)
...     return mngr
... 
>>> mngr = load_trusted_certs(BASEDIR + "rootcert.pem")
>>> verify_file_with_keysmngr(BASEDIR + "sign3-res.xml", mngr)



Verifying a signature with additional restrictions
--------------------------------------------------

>>> def verify_file_with_restrictions(xml_file, mngr):
...     """like `verify_file_with_keysmanager` but with restricted signature and reference transforms.
...     """
...     from lxml.etree import parse
...     doc = parse(xml_file)
...     node = doc.find(".//{%s}Signature" % xmlsec.DSigNs)
...     dsigCtx = xmlsec.DSigCtx(mngr)
...     for allow in "InclC14N ExclC14N Sha1".split():
...         tid = getattr(xmlsec, "Transform%s" % allow)
...         dsigCtx.enableSignatureTransform(tid)
...         dsigCtx.enableReferenceTransform(tid)
...     dsigCtx.enableSignatureTransform(xmlsec.TransformRsaSha1)
...     dsigCtx.enableReferenceTransform(xmlsec.TransformEnveloped)
...     # thanks to a patch provided by Greg Vishnepolsky, we can know
...     #   also limit the acceptable key data
...     dsigCtx.setEnabledKeyData([xmlsec.KeyDataX509])
...     dsigCtx.verify(node)
... 
>>> # this works
>>> verify_file_with_restrictions(BASEDIR + "verify4-res.xml", mngr)
>>> # this fails
>>> verify_file_with_restrictions(BASEDIR + "verify4-bad-res.xml", mngr)
Traceback (most recent call last):
  ...
Error: ('verifying failed with return value', -1)
>>> # while this works (without the restrictions)
>>> verify_file_with_keysmngr(BASEDIR + "verify4-bad-res.xml", mngr)


Signing and verification of binary data
---------------------------------------

This use case (which I need for SAML2 support) is not directly
supported by ``libxmlsec``. Unlike other examples, the following
example has therefore no correspondence with an example for
``libxmlsec``.

>>> def sign_binary(data, algorithm, key_file):
...     """sign binary *data* with *algorithm*, key in *key_file, and return signature."""
...     dsigCtx = xmlsec.DSigCtx()
...     dsigCtx.signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     return dsigCtx.signBinary(data, algorithm)
... 
>>> def verify_binary(data, algorithm, key_file, signature):
...     """verify *signature* for *data* with *algorithm, key in *key_file*."""
...     dsigCtx = xmlsec.DSigCtx()
...     dsigCtx.signKey = xmlsec.Key.load(key_file, xmlsec.KeyDataFormatPem, None)
...     dsigCtx.verifyBinary(data, algorithm, signature)
... 
>>> bin_data = "123"
>>> 
>>> # sign
... # Note: you cannot use a public rsa key for signing.
... signature = sign_binary(bin_data, xmlsec.TransformRsaSha1, BASEDIR + "rsakey.pem")
>>> 
>>> # verify
... # Note: you cannot use a private rsa key for verification.
... verify_binary(bin_data, xmlsec.TransformRsaSha1, BASEDIR + "rsapub.pem", signature)
>>> 
>>> # failing verification
... verify_binary(bin_data + "1", xmlsec.TransformRsaSha1, BASEDIR + "rsapub.pem", signature)
Traceback (most recent call last):
  ...
dm.xmlsec.binding._xmlsec.VerificationError: Signature verification failed


Encrypting binary data with a template file
-------------------------------------------

>>> def encrypt_data(tmpl_file, key_file, data):
...     """encrypt *data* with key in *key_file* using template in *tmpl_file*.
... 
...     *tmpl_file* actually contains an XML document containing an encryption
...     template. It can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains a triple DES key. It must be a filename string.
...     """
...     from lxml.etree import parse
...     doc = parse(tmpl_file)
...     node = xmlsec.findNode(doc, xmlsec.enc("EncryptedData"))
...     encCtx = xmlsec.EncCtx()
...     # Note: we do not provide read access to `encCtx.encKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the key name
...     #  before we assign it to `dsigCtx`
...     encKey = xmlsec.Key.readBinaryFile(xmlsec.KeyDataDes, key_file)
...     encKey.name = basename(key_file)
...     # Note: the assignment below effectively copies the key
...     encCtx.encKey = encKey
...     encCtx.encryptBinary(node, data)
...     return tostring(doc)
... 
>>> encrypted_data = encrypt_data(BASEDIR + "encrypt1-tmpl.xml", BASEDIR + "deskey.bin", "123")
>>> print encrypted_data
<!-- 
XML Security Library example: Simple encryption template file for encrypt1 example. 
--><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
    <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
	<KeyName>deskey.bin</KeyName>
    </KeyInfo>   
    <CipherData>
	<CipherValue>...</CipherValue>
    </CipherData>
</EncryptedData>



Encrypting xml file with a dynamically created template
-------------------------------------------------------

>>> def encrypt_file_create_template(xml_file, key_file):
...     """encrypt *xml_file* with key in *key_file*, generating the template.
... 
...     *xml_file* contains an XML file content of which should be encrypted.
...     It can be a file, a filename string or an HTTP/FTP url.
...     *key_file* contains a triple DES key. It must be a filename string.
...     """
...     # template aware infrastructure
...     from dm.xmlsec.binding.tmpl import parse, Element, SubElement, \
...          fromstring, XML
...     from dm.xmlsec.binding.tmpl import EncData
...     doc = parse(xml_file)
...     encData = EncData(xmlsec.TransformDes3Cbc, type=xmlsec.TypeEncElement)
...     encData.ensureCipherValue() # target for encryption result
...     keyInfo = encData.ensureKeyInfo()
...     encCtx = xmlsec.EncCtx()
...     encKey = xmlsec.Key.readBinaryFile(xmlsec.KeyDataDes, key_file)
...     # must set the key before the key assignment to `encCtx`
...     encKey.name = key_file
...     encCtx.encKey = encKey
...     ed = encCtx.encryptXml(encData, doc.getroot())
...     return tostring(ed.getroottree())
... 
>>> encrypted_file = encrypt_file_create_template(
...     BASEDIR + "encrypt2-doc.xml",
...     BASEDIR + "deskey.bin"
...     )
>>> print encrypted_file
<!-- 
XML Security Library example: Original XML doc file before encryption (encrypt2 example). 
--><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/><ns0:KeyInfo xmlns:ns0="http://www.w3.org/2000/09/xmldsig#"/><CipherData><CipherValue>...</CipherValue></CipherData></EncryptedData>



Encrypting data with a session key
----------------------------------

>>> def load_rsa_keys(*keys):
...     """return `KeysMngr` with *keys*.
... 
...     *keys* is a sequence of key files (given by their filenames) containing
...     PEM encoded RSA keys
...     """
...     mngr = xmlsec.KeysMngr()
...     for k in keys:
...         key = xmlsec.Key.load(k, xmlsec.KeyDataFormatPem)
...         key.name = basename(k)
...         mngr.addKey(key)
...     return mngr
... 
>>> def encrypt_file_with_session_key(mngr, xml_file, key_name):
...     """encrypt *xml_file* with encrypted session key.
... 
...     The template is dynamically created.
... 
...     The session key is encrypted with a key managed by *mngr* under
...     name *key_name*.
...     """
...     # template aware infrastructure
...     from dm.xmlsec.binding.tmpl import parse, Element, SubElement, \
...          fromstring, XML
...     from dm.xmlsec.binding.tmpl import EncData
...     doc = parse(xml_file)
...     encData = EncData(xmlsec.TransformDes3Cbc, type=xmlsec.TypeEncElement)
...     encData.ensureCipherValue() # target for encryption result
...     keyInfo = encData.ensureKeyInfo()
...     encKey = keyInfo.addEncryptedKey(xmlsec.TransformRsaPkcs1)
...     encKey.ensureCipherValue()
...     encKeyInfo = encKey.ensureKeyInfo()
...     encKeyInfo.addKeyName(key_name)
...     encCtx = xmlsec.EncCtx(mngr)
...     encCtx.encKey = xmlsec.Key.generate(xmlsec.KeyDataDes, 192, xmlsec.KeyDataTypeSession)
...     ed = encCtx.encryptXml(encData, doc.getroot())
...     return tostring(ed.getroottree())
... 
>>> mngr = load_rsa_keys(BASEDIR + "rsakey.pem")
>>> print encrypt_file_with_session_key(
...     mngr,
...     BASEDIR + "encrypt3-doc.xml",
...     "rsakey.pem",
...     )
<!-- 
XML Security Library example: Original XML doc file before encryption (encrypt3 example). 
--><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/><ns0:KeyInfo xmlns:ns0="http://www.w3.org/2000/09/xmldsig#"><EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><ns0:KeyInfo><ns0:KeyName>rsakey.pem</ns0:KeyName></ns0:KeyInfo><CipherData><CipherValue>...</CipherValue></CipherData></EncryptedKey></ns0:KeyInfo><CipherData><CipherValue>...</CipherValue></CipherData></EncryptedData>



Decrypting data with a single key
---------------------------------

>>> def decrypt_file(enc_file, key_file):
...     """decrypt *enc_file* with key in *key_file*.
... 
...     *enc_file* contains the encrypted XML document.
...     It can be a file, a filename string or an HTTP/FTP url.
... 
...     *key_file* contains the triple DES encryption key. It must be a filename.
... 
...     The decrypted data is returned.
...     """
...     from lxml.etree import parse, _Element
...     doc = parse(enc_file)
...     node = xmlsec.findNode(doc, xmlsec.enc("EncryptedData"))
...     encCtx = xmlsec.EncCtx()
...     # Note: we do not provide read access to `encCtx.encKey`.
...     #  Therefore, unlike the `xmlsec` example, we must set the key name
...     #  before we assign it to `dsigCtx`
...     encKey = xmlsec.Key.readBinaryFile(xmlsec.KeyDataDes, key_file)
...     encKey.name = basename(key_file)
...     # Note: the assignment below effectively copies the key
...     encCtx.encKey = encKey
...     dr = encCtx.decrypt(node)
...     if isinstance(dr, _Element):
...         # decrypted xml data
...         return tostring(dr.getroottree())
...     else:
...         # decrypted binary data
...         return dr
... 
>>> decrypt_file(StringIO(encrypted_data), BASEDIR + "deskey.bin")
'123'



Decrypting data with a keys manager
-----------------------------------

>>> def load_des_keys(*keys):
...     """return keys manager with *keys*.
... 
...     *keys* is a sequence a key files (given by their filenames) containing
...     binary des keys.
...     """
...     from os.path import basename
...     mngr = xmlsec.KeysMngr()
...     for k in keys:
...         key = xmlsec.Key.readBinaryFile(xmlsec.KeyDataDes, k)
...         key.name = basename(k)
...         mngr.addKey(key)
...     return mngr
... 
>>> def decrypt_file_with_keys_manager(mngr, enc_file):
...     """decrypt the encrypted *enc_file* by keys managed by *mngr*."""
...     from lxml.etree import parse, _Element
...     doc = parse(enc_file)
...     encData = xmlsec.findNode(doc, xmlsec.enc("EncryptedData"))
...     encCtx = xmlsec.EncCtx(mngr)
...     dr = encCtx.decrypt(encData)
...     if isinstance(dr, _Element):
...         # decrypted XML
...         return tostring(dr.getroottree())
...     else:
...         # decrypted binary data
...         return dr
... 
>>> mngr = load_des_keys(BASEDIR + "deskey.bin")
>>> print decrypt_file_with_keys_manager(mngr, BASEDIR + "encrypt1-res.xml")
Big secret
>>> print decrypt_file_with_keys_manager(mngr, BASEDIR + "encrypt2-res.xml")
<!-- 
XML Security Library example: Encrypted XML file (encrypt2 example). 
--><Envelope xmlns="urn:envelope">
  <Data>
	Hello, World!
  </Data>
</Envelope>


Obtaining error information
---------------------------

``xmlsec`` is quite terse with error information. Its functions return
``-1`` or ``NULL`` on error and that's what you get via the API.
In case of an error, ``xmlsec`` reports information resembling a traceback
via the ``libxml2`` error reporting mechanism. However, ``lxml`` do
not initialize the mechanism and the resulting reports are lost.

Fortunately, ``xmlsec`` allows its error reporting mechanism to
be overridden and this binding does it in a way that you can
customize it. The following example shows how:

>>> def print_errors(filename, line, func, errorObject, errorSubject, reason, msg):
...     # this would give complete but often not very usefull) information
...     # print "%(filename)s:%(line)d(%(func)s) error %(reason)d obj=%(errorObject)s subject=%(errorSubject)s: %(msg)s" % locals()
...     # the following prints if we get something with relation to the application
...     info = []
...     if errorObject != "unknown": info.append("obj=" + errorObject)
...     if errorSubject != "unknown": info.append("subject=" + errorSubject)
...     if msg.strip(): info.append("msg=" + msg)
...     # see `xmlsec`s `errors.h`for the meaning
...     if reason != 1: info.append("errno=%d" % reason)
...     if info:
...         print "%s:%d(%s)" % (filename, line, func), " ".join(info)
... 
>>> xmlsec.set_error_callback(print_errors)

This installs ``print_errors`` as error reporting hook.
We now repeat the example "Verify signature with additional restrictions"
to see what the error report tells us.

>>> verify_file_with_restrictions(BASEDIR + "verify4-bad-res.xml", mngr) # doctest: +SKIP
transforms.c:1546(xmlSecTransformNodeRead) subject=xpath msg=href=http://www.w3.org/TR/1999/REC-xpath-19991116
transforms.c:733(xmlSecTransformCtxNodesListRead) subject=xmlSecTransformNodeRead msg=node=Transform
xmldsig.c:1454(xmlSecDSigReferenceCtxProcessNode) subject=xmlSecTransformCtxNodesListRead msg=node=Transforms
xmldsig.c:804(xmlSecDSigCtxProcessSignedInfoNode) subject=xmlSecDSigReferenceCtxProcessNode msg=node=Reference
xmldsig.c:547(xmlSecDSigCtxProcessSignatureNode) subject=xmlSecDSigCtxProcessSignedInfoNode
xmldsig.c:366(xmlSecDSigCtxVerify) subject=xmlSecDSigCtxSigantureProcessNode
Traceback (most recent call last):
  ...
dm.xmlsec.binding._xmlsec.Error: ('verifying failed with return value', -1)

As before, we get an exception for the failing verification. But, now,
we have in addition the traceback like error information from ``xmlsec``.
With some ingenuity, we can deduce that there is some problem
with the "xpath" transform. Up to us to recognize that we have not
enabled this transform.

As you see, even with the error information, it might be quite difficult
to understand problems. In difficult cases, it might be necessary
to obtain the ``xmlsec`` source code and learn what is happening
in the error context.

Note that the numbers in the error output are source code line numbers.
They depend on the ``xmlsec`` version you have installed and
consequently can be different when you try this code.

If the error information contains ``errno`` (``reason`` at the base
interface), then these numbers refer to the error numbers defined
in the ``errors.h`` of ``libxmlsec``. As this file is a prerequisite
for the installation of this package, it is likely installed on your system
(unlike the ``libxmlsec`` sources). You may be able to guess from the
error name what went wrong, which sometimes avoids downloading
the full sources.



Notes
=====

XML ids
-------

Digital signatures and XML encryption can make use of XML ids. For example,
this is the case for SAML2. XML ids can make problems as XML does not
specify which attributes may contain an id. Newer versions of XML designated
``xml:id`` for this purpose, but older standards (again SAML2 is an
example) does not yet use this but their own id attributes.
As a consequence, the XML processing system (``libxml2`` in our context)
must be informed about which attributes can contain ids.

``libxml2`` knows about ``xml:id`` and if the XML document is
validated against a document type or an XML schema, it uses the information
described there to identify id attributes. If the XML document
is not validated, any id attributes different from ``xml:id``
must be made known by the application through a call to
the ``addIds(node, ids)`` function defined by ``xmlsec``.
``addIds`` visits the children of *node* (probably recursively)
and extends the id map (it maps ids to nodes) of the document of *node*
for each found attribute whose name is listed in *ids* (a list of
attribute names).

Note that the error information provided by ``xmlsec`` in case
of an undeclared id attribute may be difficult to decipher. It will probably
tell you about a problem with an XPointer transform in this case.

Note also that id references may be made indirectly, e.g. via
fragment parts of urls (again, SAML2 is an example). Thus,
when signing, signature verification or encryption/decryption
fails for no apparent reason it may be a good idea to check
whether this might be caused by unknown id attribute information.


History
=======

1.3.3
   Applied patch provided by Robert Frije to make the `nsPrefix` template
   parameter work as expected.

1.3.2
   Workaround for ``buildout`` problem (not honoring version pinning
   for ``setup_requires`` dependencies).

1.3
  Support for digital signatures of binary data

  Improved transform support

1.2
  Greg Vishnepolsky provided support for ``DSigCtx.setEnabledKeyData``.

1.1
  for lxml 3.x

1.0
  for lxml 2.x
