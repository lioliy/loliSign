import base64
import re

import requests

from aes import encrypt as e


class loli_h(object):
    def __init__(self):
        self.headers = {
            "Host": "loli-h.com",
            "Origin": "https://loli-h.com",
            "User-Agent":
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
        }
        self.url = "https://loli-h.com"

    def login(self, email, passwd):
        rs = requests.session()
        rs.headers = self.headers
        r = rs.get(self.url + "/auth/login.php")
        password_regex = re.compile(r'val\(\).*256')
        password_rnd = password_regex.search(r.text)[0].split(", ")[1].replace("\"", "")
        uaid_rnd_regex = re.compile(r"uaid=.*;")
        uaid_rnd = uaid_rnd_regex.search(r.text)
        uaid_enc_regex = re.compile(r"[0-9]{3,}")
        uaid_enc = base64.b64encode(uaid_enc_regex.search(uaid_rnd[0])[0].encode("utf-8"))
        passwd = e(passwd, password_rnd, 256)
        userinfo = {
            "email": email,
            "passwd": passwd,
            "remember_me": "no"
        }

        uaid = {
            "uaid": uaid_enc.decode("utf-8")
        }

        rs.post(self.url + "/auth/_assp.php", data=uaid)
        rs.post(self.url + "/user/_login.php", headers=self.headers, data=userinfo)
        r = rs.get(self.url + "/user/")
        login_headers = r.request.headers
        uaid_rnd = uaid_rnd_regex.search(r.text)
        uaid_enc = base64.b64encode(uaid_enc_regex.search(uaid_rnd[0])[0].encode("utf-8"))
        return login_headers, uaid_enc

    def sign(self, login_headers, uaid_enc):
        uaid = {
            "uaid": uaid_enc.decode("utf-8")
        }
        rs = requests.session()
        rs.headers = login_headers
        rs.post(self.url + "/auth/_assp.php", data=uaid)
        r = rs.post(self.url + "/user/_checkin.php", headers=login_headers)
        rs.get(self.url + "/user/logout.php")
        print(r.text)
