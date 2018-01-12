from os import mkdir
from Signing import generatePrivate, create_self_certificate
from CSR import createCSR, signReqCA
from model import getDB

def _create_root(root_name,password=b"DEFAULT"):
	'''
	This should be invoked on the ROOT CA.

	It creates a directory with the crl, certs, newcerts and private folder.
	It also initializes the index.db which stores information about the issued certs by the CA.
	'''
	# Create the ROOT directory
	mkdir(root_name)
	mkdir(root_name+'/crl')
	mkdir(root_name+'/certs')
	mkdir(root_name+'/newcerts')
	mkdir(root_name+'/private')

	# generate the private key
	pvt_obj,pvt_bytes = generatePrivate(cert_name = root_name, password = password, _size= 4096)

	# write the private key in the private key folder
	pvt_file = open(root_name+'/private/'+root_name+".private.pem",'wb')
	pvt_file.write(pvt_bytes)
	pvt_file.close()

	# create the self signed certificate of the CA as it is ROOT
	cert_bytes = create_self_certificate(pvt_obj,'ca')

	# write the certificate in the certs folder
	cert_file = open(root_name+'/certs/'+root_name+".cert.pem",'wb')
	cert_file.write(cert_bytes)
	cert_file.close()

	# create the serial file
	serial = open(root_name+'/serial','wb')
	serial.write(b'1000')
	serial.close()

	# create the crl file
	crlnumber = open(root_name+'/crlnumber','wb')
	crlnumber.write(b'1000')
	crlnumber.close()

	# create the index DB
	getDB(root_name+'/')

	# other commands should be run from the same directory in future

def _create_intermediate(intermediate_name, CN=None, password=b"DEFAULT",subject_dict = {'C':'IN'}):
	'''
	creates a CSR.

	CN should be given. If no CN is given CN is generated as

	<CA-name>.ca.OpenCA

	Password should be given in bytes. Default is b"DEFAULT"
	'''
	# create a certificate signing request for ROOT CA
	mkdir(intermediate_name)
	mkdir(intermediate_name+'/crl')
	mkdir(intermediate_name+'/certs')
	mkdir(intermediate_name+'/newcerts')
	mkdir(intermediate_name+'/private')
	mkdir(intermediate_name+'/csr')

	# create the CSR
	if CN == None:
		CN = intermediate_name+'.ca.OpenCA'
	pvt_bytes, req_bytes = createCSR(cert_name = intermediate_name, password = password, _type = 'ca', subject_dict = subject_dict)

	# write the private key in the private key folder
	pvt_file = open(intermediate_name+'/private/'+intermediate_name+".private.pem",'wb')
	pvt_file.write(pvt_bytes)
	pvt_file.close()

	# write the csr in the csr folder
	csr_file = open(intermediate_name+'/csr/'+intermediate_name+'.csr.pem','wb')
	csr_file.write(req_bytes)
	csr_file.close()

	# create the serial file
	serial = open(intermediate_name+'/serial','wb')
	serial.write(b'1000')
	serial.close()

	# create the crl file
	crlnumber = open(intermediate_name+'/crlnumber','wb')
	crlnumber.write(b'1000')
	crlnumber.close()

	# create the index DB
	getDB(intermediate_name+'/')

def createCA(ca_type,name,CN=None,password=b"DEFAULT"):
	'''
	ca_type can be 'root' or 'intermediate'

	if ca_type is root then the ca directory will contain a self signed certificate

	if ca_type is intermediate then ca directory will contain a csr that can be signed by root using signReqCA function

	creates a CA with the given name and password is set for the private key of CA.
	'''
	if ca_type == 'root':
		_create_root(name,password)
	elif ca_type == 'intermediate':
		_create_intermediate(name,CN,password)
