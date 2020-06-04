import requests
import re
import json
from os import getcwd, path


def get_jwt(my_acct):
    url = "https://users.wix.com/signin"
    session_id = ''
    payload = {
        'originUrl': "https:%2F%2Fwww.wix.com%2Faccount%2Fsites",
        'redirectTo': "https:%2F%2Fwww.wix.com%2Faccount%2Fsites"
    }
    headers = {
        'Accept': '''
                  text/html,
                  application/xhtml+xml,
                  application/xml;q=0.9,
                  image/webp,
                  image/apng,
                  */*;q=0.8,
                  application/signed-exchange;v=b3;q=0.9
                  ''',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
    }
    response = requests.request("GET", url, headers=headers, data=payload)

    val = response.headers.get('set-cookie')
    val_split = val.split(', ')

    for item in val_split:
        if 'wixCIDX' in item:
            session_id = item.split('=')[1].split(';')[0]

    url = "https://users.wix.com/auth/v2/login/"

    payload = 'email={}&password={}&rememberMe=true&ldSessionID={}'.format(
        my_acct['email'],
        my_acct['password'],
        session_id
    )
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'User-Agent': 'PostmanRuntime/7.24.1'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    return response.cookies.get_dict()['wixSession2']


def get_wix_records(base_url, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}".format(base_url)

    payload = {}
    headers = {
        'Cookie': 'wixSession2={}'.format(jwt_header),
        'Accept': 'application/json, text/plain, */*'
    }

    response = requests.request("GET", url, headers=headers, data=payload)

    return json.loads(response.text.encode('utf8'))


def update_record(base_url, u_host, n_value, o_value, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}/records".format(base_url)

    data = {
        "deletions": [
            {
                "recordType": "A",
                "ttl": 1800,
                "hostName": u_host,
                "values": o_value
            }
        ],
        "additions": [
            {
                "recordType": "A",
                "ttl": 1800,
                "hostName": u_host,
                "values": n_value
            }
        ]
    }

    payload = json.dumps(data)

    headers = {
        'Cookie': 'wixSession2={}'.format(jwt_header),
        'Origin': 'https://www.wix.com',
        'Content-Type': 'application/javascript'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    return response.text.encode('utf8')


def create_record(base_url, n_host, n_value, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}/records".format(base_url)

    data = {
        "additions": [
            {
                "recordType": "A",
                "ttl": 1800,
                "hostName": n_host,
                "values": n_value
            }
        ]
    }

    payload = json.dumps(data)

    headers = {
        'Cookie': 'wixSession2={}'.format(jwt_header),
        'Origin': 'https://www.wix.com',
        'Content-Type': 'application/javascript'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    return response.text.encode('utf8')


def get_ip_wmip():
    r = str(requests.get('http://whatismyip.org/my-ip-address').content)
    return re.findall('<a href="/my-ip-address">(.*?)</a>', r, flags=re.DOTALL)[0].strip()


def get_ip_ipchi():
    r = str(requests.get('https://ipchicken.com/').content)
    return re.findall('<b>(.*?)<br>', r, flags=re.DOTALL)[0].strip().replace('\\n', '')


def load_info():
    with open(path.join(getcwd(), 'info.json'), 'r') as f:
        data = json.loads(f.read())
        f.close()
    return data


def write_info(jwt_header):
    data = load_info()
    data['jwtHeader'] = jwt_header
    with open(path.join(getcwd(), 'info.json'), 'w') as f:
        f.write(json.dumps(data))
        f.close()


def get_a_records(data):
    rec_list = []
    for record in data:
        if record['recordType'] == 'A':
            rec_list.append(record)
    return rec_list


def get_sub_recs(data, sub_domains=None):
    if sub_domains is None:
        sub_domains = []

    rec_list = []
    for record in data:
        if record['hostName'] in sub_domains:
            rec_list.append((record['hostName'], record['values']))
            sub_domains.remove(record['hostName'])
    return rec_list, sub_domains


def get_lists(my_acct, base_url, jwt_header, sub_domains):
    recs = get_wix_records(base_url, jwt_header)
    if 'message' in recs:
        jwt_header = get_jwt(my_acct)
        write_info(jwt_header)
        recs = get_wix_records(base_url, jwt_header)
    return get_sub_recs(recs['records'], sub_domains)


def check_ips(u_list, p_ip):
    rec_list = []
    for host, values in u_list:
        for ip in values:
            if ip != p_ip:
                rec_list.append((host, [ip], [p_ip]))
    return rec_list


if __name__ == '__main__':
    info = load_info()
    acct = info['account']
    sub = info['subDomains']
    jwt = info['jwtHeader']
    base = info['baseUrl']
    pub_ip = '{}'.format(get_ip_ipchi())

    update_list, create_list = get_lists(acct, base, jwt, sub)
    update_list = check_ips(update_list, pub_ip)

    i = 0
    while i <= len(create_list)-1:
        create_list[i] = (create_list[i], [pub_ip])
        i += 1

    for host, old_value, new_value in update_list:
        update_record(base, host, new_value, old_value, jwt)

    for host, new_value in create_list:
        create_record(base, host, new_value, jwt)
