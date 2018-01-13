from os import mkdir
from .Signing import generatePrivate, create_self_certificate
from .CSR import createCSR, signReqCA
from .model import getDB
from .CAExceptions import PasswordException, SubjectException
from os import path

def _create_root(root_name,subject_dict,password):
	'''
	This should be invoked on the ROOT CA.

	It creates a directory with the crl, certs, newcerts and private folder.
	It also initializes the index.db which stores information about the issued certs by the CA.
	'''
	# Create the ROOT directory
	mkdir(path.abspath(root_name))
	mkdir(path.join(path.abspath(root_name),'crl'))
	mkdir(path.join(path.abspath(root_name),'certs'))
	mkdir(path.join(path.abspath(root_name),'newcerts'))
	mkdir(path.join(path.abspath(root_name),'private'))

	# generate the private key
	pvt_obj,pvt_bytes = generatePrivate(cert_name = root_name, password = password, _size= 4096)

	# write the private key in the private key folder
	pvt_file = open(path.join(path.abspath(root_name),'private',(root_name+".private.pem")),'wb')
	pvt_file.write(pvt_bytes)
	pvt_file.close()

	# create the self signed certificate of the CA as it is ROOT
	cert_bytes = create_self_certificate(pvt_obj,subject_dict)

	# write the certificate in the certs folder
	cert_file = open(path.join(path.abspath(root_name),'certs',(root_name+".cert.pem")),'wb')
	cert_file.write(cert_bytes)
	cert_file.close()

	# create the serial file
	serial = open(path.join(path.abspath(root_name),'serial'),'wb')
	serial.write(b'1000')
	serial.close()

	# create the crl file
	crlnumber = open(path.join(path.abspath(root_name),'crlnumber'),'wb')
	crlnumber.write(b'1000')
	crlnumber.close()

	# create the index DB
	getDB(root_name)

	# other commands should be run from the same directory in future

def _create_intermediate(intermediate_name, subject_dict,password):
	'''
	creates a CSR.

	CN should be given. If no CN is given CN is generated as

	<CA-name>.ca.OpenCA

	Password should be given in bytes. Default is b"DEFAULT"
	'''
	# create a certificate signing request for ROOT CA
	mkdir(path.abspath(intermediate_name))
	mkdir(path.join(path.abspath(intermediate_name),'crl'))
	mkdir(path.join(path.abspath(intermediate_name),'certs'))
	mkdir(path.join(path.abspath(intermediate_name),'newcerts'))
	mkdir(path.join(path.abspath(intermediate_name),'private'))
	mkdir(path.join(path.abspath(intermediate_name),'csr'))

	# cerate the CSR
	pvt_bytes, req_bytes = createCSR(intermediate_name,password, subject_dict, csr_type = 'ca')

	# write the private key in the private key folder
	pvt_file = open(path.join(path.abspath(intermediate_name),'private',(intermediate_name+".private.pem")),'wb')
	pvt_file.write(pvt_bytes)
	pvt_file.close()

	# write the csr in the csr folder
	csr_file = open(path.join(path.abspath(intermediate_name),'csr',(intermediate_name+'.csr.pem')),'wb')
	csr_file.write(req_bytes)
	csr_file.close()

	# create the serial file
	serial = open(path.join(path.abspath(intermediate_name),'serial'),'wb')
	serial.write(b'1000')
	serial.close()

	# create the crl file
	crlnumber = open(path.join(path.abspath(intermediate_name),'crlnumber'),'wb')
	crlnumber.write(b'1000')
	crlnumber.close()

	# create the index DB
	getDB(intermediate_name)

def createCA(ca_type,name,password="DEFAULT",subject_dict={'C':'IN'}):
	'''
	ca_type can be 'root' or 'intermediate'

	if ca_type is root then the ca directory will contain a self signed certificate

	if ca_type is intermediate then ca directory will contain a csr that can be signed by root using signReqCA function

	creates a CA with the given name and password is set for the private key of CA.

	subject_dict should have these values-

		C - Country
		ST - State or Province
		L - Locality
		O - Organization
		OU - Organizational Unit
		CN - Common Name
		(-----------------------------IMPORTANT------------------------)
		Common Names should never be same of any certificate under a CA.
		(--------------------------------------------------------------)

		e.g.
		{'C':'IN','ST':'Open-State','L':'Open-Locality','O':'Open-CA','OU':'Open-Unit','CN':'OpenCA.open.ca'}
	'''

	if len(password) <4:
		raise PasswordException('Password should be at least 4 character long')

	password = bytes(password,'utf-8') if isinstance(password,str) else password

	if 'CN' not in subject_dict.keys():
		raise SubjectException('Please Specify a FQDN e.g. {"CN":"root.OpenCA.lel"} (Should not be same as the parent)')

	if ca_type == 'root':
		_create_root(name,subject_dict,password)
	elif ca_type == 'int':
		_create_intermediate(name,subject_dict,password)
