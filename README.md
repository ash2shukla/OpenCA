# OpenCA
A tool based on pyOpenSSL to easily create and manage Certification Authorities.

Install - pip3 install OpenCA

	from OpenCA import createCA, signReqCA, createCSR
	createCA('root','ROOT','root-pass',{'CN':'FQDN_ROOT'})
	createCA('int','INTERMEDIATE','inter-pass',{'CN':'FQDN_INETRMEDIATE'})

	signReqCA('ROOT','INTERMEDIATE','root-pass','ca')

	createCSR('USER','user-pass',{'CN':'FQDN_USER'})
	createCSR('SERVER','server-pass',{'CN':'FQDN_SERVER'})

	signReqCA('INTERMEDIATE','USER.csr.pem','inter-pass','usr')
	signReqCA('INTERMEDIATE','SERVER.csr.pem','inter-pass','svr')

	from OpenCA import Utils
	Utils.verify_chain('ROOT/certs/ROOT.cert.pem',open('INTERMEDIATE/certs/INTERMEDIATE.cert.pem','rb').read()) # True

	Utils.verify_chain('ROOT/certs/ROOT.cert.pem',open('USER.cert.pem','rb').read()) # False
	Utils.verify_chain('ROOT/certs/ROOT.cert.pem',open('SERVER.cert.pem','rb').read()) # False
	Utils.verify_chain('INTERMEDIATE/certs/INTERMEDIATE.cert.pem',open('USER.cert.pem','rb').read()) # False
	Utils.verify_chain('INTERMEDIATE/certs/INTERMEDIATE.cert.pem',open('SERVER.cert.pem','rb').read()) # False

	# End Certificates can only be verified using the chain of trust

	Utils.verify_chain('INTERMEDIATE/certs/ROOT.INTERMEDIATE.chain.pem',open('USER.cert.pem','rb').read()) # True
	Utils.verify_chain('INTERMEDIATE/certs/ROOT.INTERMEDIATE.chain.pem',open('SERVER.cert.pem','rb').read()) # True




create ROOT CA -

	from OpenCA import createCA
	createCA('root','ROOT_NAME','ROOT_PASS', {'CN':'FQDN.Goes.Here'})

create Intermediate CA -

	from OpenCA import createCA, signReqCA

	createCA('int', 'INTERMEDIATE_NAME', 'INT_PASS', {'CN':'FQDN.Should.Not.Be.Same.As.Of.Root.CA'})
	signReqCA('PATH_TO_ROOT_CA_FOLDER','PATH_TO_INTERMEDIATE_CA_FOLDER','ROOT_PASS', csr_type = 'ca' )

signReqCA saves the certificate of Intermediate CA in ROOT CA's *newcerts* directory and enrolls it in index.db.
return value of signReqCA is the certificate bytes of Intermediate CA's generated certificate.

For user or servers -

	Users/server generates a PKey and CSR and hands it over to Intermediate CA.

		from OpenCA import createCSR
		createCSR('User','User_password',{'CN':'USER_FQDN'})

	It will create two files in the current directory -

		1.User.private.pem
		2.User.csr.pem

	create End user certificate on Intermediate CA-

		from OpenCA import signReqCA
		signReqCA('PATH_TO_INTERMEDIATE_CA_FOLDER','PATH_TO_CSR_OF_USER_OR_SERVER','INT_PASS', csr_type = <'usr' or 'svr'> )
