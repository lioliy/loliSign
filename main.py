from loli_h import *

email = ""  # Your Email
passwd = ""  # Your PassWord

info = loli_h().login(email, passwd)
logiin_headers = info[0]
uaid_enc = info[1]
loli_h().sign(logiin_headers, uaid_enc)
