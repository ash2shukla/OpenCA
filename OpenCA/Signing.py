from OpenSSL.crypto import TYPE_RSA
from OpenSSL.crypto import PKey
from OpenSSL.crypto import X509, X509Extension, X509Req
from OpenSSL.crypto import dump_certificate, dump_certificate_request
from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import FILETYPE_PEM

from .model import getDB, Index

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

def generatePrivate(cert_name,password, _size = 2048):
	pk = PKey()
	pk.generate_key(TYPE_RSA, _size)
	pk_gen = pk.to_cryptography_key()
	_PEM = Encoding.PEM
	_TraditionalOpenSSL = PrivateFormat.TraditionalOpenSSL
	_encryption = BestAvailableEncryption(password)
	pvt = pk_gen.private_bytes(_PEM, _TraditionalOpenSSL, _encryption)
	return pk,pvt

def setSubject(subject, subject_dict):

	try:
		subject.C = subject_dict['C']
	except KeyError:
		subject.C = 'IN'

	try:
		subject.ST = subject_dict['ST']
	except KeyError:
		pass

	try:
		subject.L = subject_dict['L']
	except KeyError:
		pass

	try:
		subject.O = subject_dict['O']
	except KeyError:
		pass

	try:
		subject.OU = subject_dict['OU']
	except KeyError:
		pass

	try:
		subject.CN = subject_dict['CN']
	except KeyError:
		pass

	return subject

def create_self_certificate(pk, subject_dict,expiry =10*365*24*60*60):
	cert = X509()
	subject = cert.get_subject()


	subject = setSubject(subject,subject_dict)

	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(expiry)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(pk)

	cert.add_extensions([ X509Extension(b"basicConstraints", True,b"CA:TRUE"),\
						X509Extension(b"keyUsage", True,b"keyCertSign, cRLSign"),\
						X509Extension(b"subjectKeyIdentifier", False, b"hash",subject=cert)])

	cert.sign(pk, 'sha256')

	# dump the certificate in path
	cert_bytes = dump_certificate(FILETYPE_PEM,cert)

	return cert_bytes
