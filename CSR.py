from OpenSSL.crypto import X509, X509Extension, X509Req
from OpenSSL.crypto import dump_certificate, dump_certificate_request
from OpenSSL.crypto import load_certificate, load_privatekey, load_certificate_request
from OpenSSL.crypto import FILETYPE_PEM

from model import getDB, Index
from sqlalchemy.orm import sessionmaker
from Signing import generatePrivate,setSubject
from model import getDB

def createCSR(cert_name, password, subject_dict, _type=None):
	'''
	create A Certificate Signing Request for a CA.

	_type should be set to 'ca' if it is a CSR for an intermediate CA.

	CN MUST be passed.
	'''
	if _type == 'ca':
		pvt_obj,pvt_bytes = generatePrivate(cert_name,_size= 4096, password = password)
	else :
		pvt_obj,pvt_bytes = generatePrivate(cert_name,password=password)

	req = X509Req()
	subject = req.get_subject()
	subject = setSubject(subject, subject_dict)

	req.set_pubkey(pvt_obj)
	req.sign(pvt_obj, "sha256")
	return pvt_bytes, dump_certificate_request(FILETYPE_PEM, req)

def signReqCA(CA_path,CSR_path,password,_type='usr'):
	'''
	Signs the CSR.

	CA_path : path of the directory of CA which will sign the request.

	* DIRECTORY IN CA PATH MUST BE THE ONE GENERATED USING OpenCA *
	'''
	engine = getDB(CA_path)
	Session = sessionmaker(bind = engine)
	session = Session()

	CA_name = CA_path.split('/')[-1]

	# load certifiate of the CA.
	CAcert_bytes = open(CA_path+'/certs/'+CA_name+'.cert.pem','rb').read()
	CAcert = load_certificate(FILETYPE_PEM, CAcert_bytes)

	# load privatekey of the CA.
	CAkey_bytes = open(CA_path+'/private/'+CA_name+'.private.pem','rb').read()
	CAkey = load_privatekey(FILETYPE_PEM, CAkey_bytes, passphrase=bytes(password,'utf-8'))

	# load the CSR.
	CSR_bytes = open(CSR_path,'rb').read()
	CSR = load_certificate_request(FILETYPE_PEM, CSR_bytes)

	if CAcert.get_subject().CN==CSR.get_subject().CN:
		return 'CSR CN cant be same as CA CN.'

	cert = X509()

	cert.set_subject(CSR.get_subject())

	# Get the last serial number and dump it in serial.old
	# Increment the serial number and save it in serial
	# give the incremented serial number here
	serial = open(CA_path+'/serial','rb').read()
	cert.set_serial_number(int(serial))
	open(CA_path+'/serial.old','wb').write(serial)
	open(CA_path+'/serial','wb').write(bytes(str(int(serial)+1),'utf-8'))

	cert.gmtime_adj_notBefore(0)

	if _type == 'ca':
		cert.gmtime_adj_notAfter(5*365*24*60*60)
		cert.add_extensions([ X509Extension(b"basicConstraints", True,b"CA:TRUE, pathlen:0"),\
						X509Extension(b"keyUsage", True,b"keyCertSign, cRLSign"),\
						X509Extension(b"authorityKeyIdentifier", False, "keyid:always, issuer"),\
						X509Extension(b"subjectKeyIdentifier", False, b"hash",subject=cert)])
	elif _type == 'usr':
		cert.gmtime_adj_notAfter(1*365*24*60*60)
		cert.add_extensions([ X509Extension(b"basicConstraints",True,b"CA FALSE"),\
						X509Extension(b"nsCertType",False,b"client, email"),\
						X509Extension(b"nsComment",False, b"Certified Using OpenSSL based OpenCA"),\
						X509Extension(b"subjectKeyIdentifier",False,b"hash"),\
						X509Extension(b"authorityKeyIdentifier",False, b"keyid,issuer"),\
						X509Extension(b"keyUsage",True,b"nonRepudiation, digitalSignature, keyEncipherment"),\
						X509Extension(b"extendedKeyUsage", False, b"clientAuth, emailProtection")])

	elif _type == 'svr':
		cert.gmtime_adj_notAfter(2*365*24*60*30)
		cert.add_extensions([ X509Extension(b"basicConstraints",True,b"CA FALSE"),\
						X509Extension(b"nsCertType",False,b"server"),\
						X509Extension(b"nsComment",False, b"Certified Using OpenSSL based OpenCA"),\
						X509Extension(b"subjectKeyIdentifier",False,b"hash"),\
						X509Extension(b"authorityKeyIdentifier",False, b"keyid,issuer"),\
						X509Extension(b"keyUsage",True,b"nonRepudiation, digitalSignature, keyEncipherment"),\
						X509Extension(b"extendedKeyUsage", False, b"serverAuth")])

	cert.set_issuer(CAcert.get_subject())
	cert.set_pubkey(CSR.get_pubkey())
	cert.sign(CAkey, "sha256")

	# Save the signed certificate's information in the index.db
	clist = []
	for i in cert.get_subject().get_components():
		clist.append(i[0]+b'='+i[1])

	cstring =b'/'.join(clist)
	cstring = b'/'+cstring+b'/'

	IndexObj = Index(expiration_date = cert.get_notAfter(), serial_number_in_hex = str(serial), cert_filename = serial.decode('utf-8')+'.cert.pem', cert_subject = cstring)
	session.add(IndexObj)
	session.commit()

	# save the certificates in newcerts directory of the CA
	cert_bytes =  dump_certificate(FILETYPE_PEM, cert)
	open(CA_path+'/newcerts/'+serial.decode('utf-8')+'.cert.pem','wb').write(cert_bytes)
	return cert_bytes
