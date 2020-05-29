from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
import re
import json
from os import getcwd, path


def get_jwt():
    opt = Options()
    opt.headless = True
    driver = webdriver.Firefox(options=opt)
    driver.get(
        "https://users.wix.com/signin?originUrl=https:%2F%2Fwww.wix.com%2Faccount%2Fsites&redirectTo=https:%2F%2Fwww.wix.com%2Faccount%2Fsites&overrideLocale=en"
    )

    email_elm = driver.find_element_by_id('input_0')
    email_elm.clear()
    email_elm.send_keys('support@aphid.io')
    pwd_elm = driver.find_element_by_id('input_1')
    pwd_elm.clear()
    pwd_elm.send_keys('z8dY#p1@')
    pwd_elm.send_keys(Keys.RETURN)
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "root"))
        )
        header = driver.get_cookie('wixSession2')['value']
    finally:
        driver.quit()

    return header


def get_wix_records(bas_url, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}".format(base)

    payload = {}
    headers = {
        'Cookie': 'wixSession2={}'.format(jwt_header),
        'Accept': 'application/json, text/plain, */*'
    }

    response = requests.request("GET", url, headers=headers, data=payload)

    return json.loads(response.text.encode('utf8'))


def update_record(bas_url, u_host, n_value, o_value, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}/records".format(base)

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


def create_record(bas_url, n_host, n_value, jwt_header):
    url = "https://www.wix.com/_api/premium-dns/v1/zones/{}/records".format(base)

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
    get_ip = lambda html: re.findall('<a href="/my-ip-address">(.*?)</a>', html, flags=re.DOTALL)[0].strip()
    return get_ip(r)


def get_ip_ipchi():
    r = str(requests.get('https://ipchicken.com/').content)
    get_ip = lambda html: re.findall('<b>(.*?)<br>', html, flags=re.DOTALL)[0].strip().replace('\\n', '')
    return get_ip(r)


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


def get_lists(base_url, jwt_header, sub_domains):
    recs = get_wix_records(base_url, jwt_header)
    if 'message' in recs:
        jwt_header = get_jwt()
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

    update_list, create_list = get_lists(base, jwt, sub)
    update_list = check_ips(update_list, pub_ip)

    i = 0
    while i <= len(create_list)-1:
        create_list[i] = (create_list[i], [pub_ip])
        i += 1

    for host, old_value, new_value in update_list:
        update_record(base, host, new_value, old_value, jwt)

    for host, new_value in create_list:
        create_record(base, host, new_value, jwt)
