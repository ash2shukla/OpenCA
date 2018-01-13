from OpenSSL.crypto import X509, X509Extension, X509Req
from OpenSSL.crypto import dump_certificate, dump_certificate_request
from OpenSSL.crypto import load_certificate, load_privatekey, load_certificate_request
from OpenSSL.crypto import FILETYPE_PEM

from .model import getDB, Index
from sqlalchemy.orm import sessionmaker
from .Signing import generatePrivate,setSubject
from .model import getDB
from .Utils import is_serial_consistent
from .CAExceptions import SerialException, CNException

from os import path

def createCSR(cert_name, password, subject_dict, csr_type='usr'):
	'''
	create A Certificate Signing Request for a CA.

	csr_type should be set to 'ca' if it is a CSR for an intermediate CA.

	CN MUST be passed.
	'''
	if isinstance(password,str):
		password = bytes(password, 'utf-8')

	if csr_type == 'ca':
		pvt_obj,pvt_bytes = generatePrivate(cert_name,_size= 4096, password = password)
	else :
		pvt_obj,pvt_bytes = generatePrivate(cert_name,password=password)

	req = X509Req()
	subject = req.get_subject()
	subject = setSubject(subject, subject_dict)

	req.set_pubkey(pvt_obj)
	req.sign(pvt_obj, "sha256")
	if csr_type == 'usr':
		# If it is a request by user then also create the files in the pwd
		open(path.abspath(cert_name+'.private.pem'),'wb').write(pvt_bytes)
		open(path.abspath(cert_name+'.csr.pem'),'wb').write(dump_certificate_request(FILETYPE_PEM, req))

	return pvt_bytes, dump_certificate_request(FILETYPE_PEM, req)

def signReqCA(CA_path,CSR_path,password,csr_type='usr'):
	'''
	Signs the CSR.
	Returns bytes of (Chain of trust, Issued Certificate) if csr_type == 'ca'
	Returns bytes of (Issued Certificate) if csr_type == 'usr' or 'svr'

	CA_path : path of the directory of CA which will sign the request.

	* DIRECTORY IN CA PATH MUST BE THE ONE GENERATED USING OpenCA *
	'''
	if not is_serial_consistent(CA_path):
		raise SerialException('Serial sequence mismatched, Serial is corrupted')

	engine = getDB(CA_path)
	Session = sessionmaker(bind = engine)
	session = Session()

	CA_name = path.split(CA_path)[1]

	# load certifiate of the CA
	CAcert_bytes = open(path.join(path.abspath(CA_path),'certs',(CA_name+'.cert.pem')),'rb').read()
	CAcert = load_certificate(FILETYPE_PEM, CAcert_bytes)

	password = bytes(password,'utf-8') if isinstance(password,str) else password

	# load privatekey of the CA.
	CAkey_bytes = open(path.join(path.abspath(CA_path),'private',(CA_name+'.private.pem')),'rb').read()
	CAkey = load_privatekey(FILETYPE_PEM, CAkey_bytes, passphrase= password)

	# determine if the request is for a CA
	if csr_type == 'ca':
		SUBCA_name = path.split(CSR_path)[1]
		SUBCA_dir = CSR_path[:]
		CSR_path = path.join(path.abspath(CSR_path),'csr',(SUBCA_name+'.csr.pem'))

	# load the CSR.
	CSR_bytes = open(CSR_path,'rb').read()
	CSR = load_certificate_request(FILETYPE_PEM, CSR_bytes)

	if CAcert.get_subject().CN==CSR.get_subject().CN:
		raise CNException('CN can not be same as parent')

	cert = X509()

	cert.set_subject(CSR.get_subject())

	# Get the last serial number and dump it in serial.old
	# Increment the serial number and save it in serial
	# give the incremented serial number here
	serial = open(path.join(CA_path,'serial'),'rb').read()
	cert.set_serial_number(int(serial))
	open(path.join(CA_path,'serial.old'),'wb').write(serial)
	open(path.join(CA_path,'serial'),'wb').write(bytes(str(int(serial)+1),'utf-8'))

	cert.gmtime_adj_notBefore(0)

	if csr_type == 'ca':
		cert.gmtime_adj_notAfter(5*365*24*60*60)
		cert.add_extensions([ X509Extension(b"basicConstraints", True,b"CA:TRUE, pathlen:0"),\
						X509Extension(b"keyUsage", True,b"keyCertSign, cRLSign"),\
						X509Extension(b"authorityKeyIdentifier", False, b"keyid:always",issuer= CAcert),\
						X509Extension(b"subjectKeyIdentifier", False, b"hash",subject=cert)])
	elif csr_type == 'usr':
		cert.gmtime_adj_notAfter(1*365*24*60*60)
		cert.add_extensions([ X509Extension(b"basicConstraints",True,b"CA:FALSE"),\
						X509Extension(b"nsCertType",False,b"client, email"),\
						X509Extension(b"nsComment",False, b"Certified Using OpenSSL based OpenCA"),\
						X509Extension(b"subjectKeyIdentifier",False,b"hash",subject=cert),\
						X509Extension(b"authorityKeyIdentifier",False, b"keyid", issuer= CAcert),\
						X509Extension(b"keyUsage",True,b"nonRepudiation, digitalSignature, keyEncipherment"),\
						X509Extension(b"extendedKeyUsage", False, b"clientAuth, emailProtection")])

	elif csr_type == 'svr':
		cert.gmtime_adj_notAfter(2*365*24*60*30)
		cert.add_extensions([ X509Extension(b"basicConstraints",True,b"CA:FALSE"),\
						X509Extension(b"nsCertType",False,b"server"),\
						X509Extension(b"nsComment",False, b"Certified Using OpenSSL based OpenCA"),\
						X509Extension(b"subjectKeyIdentifier",False,b"hash",subject=cert),\
						X509Extension(b"authorityKeyIdentifier",False, b"keyid", issuer=CAcert),\
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
	open(path.join(path.abspath(CA_path),'newcerts',(serial.decode('utf-8')+'.cert.pem')),'wb').write(cert_bytes)

	if csr_type == 'ca':
		# If csr_type is 'ca' then save the chain of trust and it's certificate
		if path.exists(path.join(path.abspath(CA_path),'certs',(CA_name+'.chain.pem'))):
			# If CA has a chain then forward that chain further
			CAcert_bytes =  open(path.join(path.abspath(CA_path),'certs',(CA_name+'.chain.pem')),'rb').read()

		open(path.join(path.abspath(SUBCA_dir),'certs',(SUBCA_name+'.cert.pem')),'wb').write(cert_bytes)
		open(path.join(path.abspath(SUBCA_dir),'certs',(SUBCA_name+'.chain.pem')),'wb').write(cert_bytes+CAcert_bytes)
		return (cert_bytes+CAcert_bytes), cert_bytes
	else:
		print('Certificate Produced @ ',path.join(path.abspath(path.split(CSR_path)[0]),'USER.cert.pem'))
		if csr_type == 'usr':
			open(path.join(path.abspath(path.split(CSR_path)[0]),'USER.cert.pem'),'wb').write(cert_bytes)
		elif csr_type == 'svr':
			open(path.join(path.abspath(path.split(CSR_path)[0]),'SERVER.cert.pem'),'wb').write(cert_bytes)
		return cert_bytes
