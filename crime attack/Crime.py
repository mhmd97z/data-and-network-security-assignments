import string
import requests
import base64

chars = string.ascii_letters
session = requests.Session()


def req(user):
    session.get('https://pacific-anchorage-60533.herokuapp.com/ce442/?user=' + user)
    flag_b64 = session.cookies.get_dict()['flag']
    if flag_b64.startswith('"'):
        flag_b64 = flag_b64[1:-1]
    ll = len(flag_b64)
    if ll % 4 > 0:
        flag_b64 = flag_b64 + (4-(ll % 4)) * '='
    return base64.b64decode(flag_b64)


def nxt_char(curr_flag):
    resp_len = []
    for char in chars:
        resp_len.append(len(req(curr_flag[-5:] + char)))
    return chars[resp_len.index(min(resp_len))]


flag = 'flag:'
for i in range(10):
    # find next char
    print(".............................................")
    print("Looking for character number %i  " %(i + 1))
    next_character = nxt_char(flag)
    print("Founded: %s " % next_character)
    flag = flag + next_character
    print("Current Flag= %s " % flag)

print("************************************")
print("The complete FLAG is %s" % flag)
print("************************************")
