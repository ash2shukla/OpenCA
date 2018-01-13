from OpenSSL.crypto import X509Store, X509StoreContext
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from sqlalchemy.orm import sessionmaker
from .model import Index
from sqlalchemy import create_engine


def verify_chain(chain_path, cert_bytes):
	chain = load_certificate(FILETYPE_PEM, open(chain_path,'rb').read())
	cert = load_certificate(FILETYPE_PEM, cert_bytes)
	store = X509Store()
	store.add_cert(chain)
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
	old = open(CA_dir+'/serial.old','rb').read()

	if (int(old)+1) == int(serial):
		return True
	else:
		return False
