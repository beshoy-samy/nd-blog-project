from string import letters
import random
import hashlib
import hmac
import re

secret = 'this-is-secret-encryption'

def create_secure_cookie_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_cookie_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == create_secure_cookie_val(val):
        return val



def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    hv = make_pw_hash(name, password, salt)
    return h == hv

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def get_userID(self):
        cookie_val = self.request.cookies.get('user_id')
        uID = cookie_val.split('|')[0]
        return uID

def is_loggedIn(self):
        cookie_val = self.request.cookies.get('user_id')
        return cookie_val
