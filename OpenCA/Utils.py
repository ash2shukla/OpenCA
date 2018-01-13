from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from sqlalchemy.orm import sessionmaker
from .model import Index
from sqlalchemy import create_engine

def verify_chain(chain_path, cert_bytes_or_path):
	try:
		# If certificate bytes are passed load the certificate
		cert = load_certificate(FILETYPE_PEM,cert_bytes_or_path)
	except:
		# If certificate path is passed open the certificate and load it's bytes
		cert = load_certificate(FILETYPE_PEM, open(cert_bytes_or_path,'rb').read())

	chain_bytes = open(chain_path,'rb').read()
	parts = chain_bytes.split(b'-----\n-----')
	n_certs = len(parts)

	store = X509Store()
	if n_certs == 1:
		store.add_cert(load_certificate(FILETYPE_PEM,parts[0]))
	else:
		cert_list = []
		store.add_cert(load_certificate(FILETYPE_PEM,(parts[0]+b'-----\n')))
		store.add_cert(load_certificate(FILETYPE_PEM,(b'-----'+parts[-1])))
		for i in parts[1:-1]:
			store.add_cert(load_certificate(FILETYPE_PEM,(b'-----'+i+b'-----\n')))

	store_ctx = X509StoreContext(store, cert)
	try:
		if store_ctx.verify_certificate() == None:
			return True
	except:
		return False

def get_index(index_path):
	engine = create_engine('sqlite:///'+index_path)
	Session = sessionmaker(engine)
	session = Session()
	print('__________________________________________________________________________')
	print('|status_flag | expiry | revocation | reason | serial | filename | subject|')
	for i in session.query(Index).all():
		print('|',i.status_flag,'|',i.expiration_date,'|',i.revocation_date,'|',i.revocation_reason,'|',i.serial_number_in_hex,'|',i.cert_filename,'|',i.cert_subject,'|')

def find_all_revoked(index_path):
	engine = create_engine('sqlite:///'+index_path)
	Session = sessionmaker(engine)
	session = Session()
	print('__________________________________________________________________________')
	print('|status_flag | expiry | revocation | reason | serial | filename | subject|')
	for i in session.query(Index).filter(Index.status_flag == 'R'):
		print('|',i.status_flag,'|',i.expiration_date,'|',i.revocation_date,'|',i.revocation_reason,'|',i.serial_number_in_hex,'|',i.cert_filename,'|',i.cert_subject,'|')

def is_serial_consistent(CA_dir):
	serial = open(CA_dir+'/serial','rb').read()
	try:
		old = open(CA_dir+'/serial.old','rb').read()
	except FileNotFoundError:
		return True

	if (int(old)+1) == int(serial):
		return True
	else:
		return False
