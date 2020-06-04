# Wix Dynamic DNS
A project to create tools that automatically update A name records on Wix to mimic DDNS.

To get started rename example_info.json to info.json

cd into your project directory

Install dependencies
```shell script
$ pip install -f requirements.txt
```

Then replace all the place holders in brackets e.g. `[WIX_USERNAME]`

In order to run cd to your project directory and run 
```shell script
$ python WixDDNs.py
```

In this project we verify our JWT is valid then using https://www.wix.com/_api/premium-dns/v1/zones/[AppID] we set the appropriate A records for subdomains listed in info.json

we use https://users.wix.com/signin to get a session ID then https://users.wix.com/auth/v2/login/ to get a JWT to use with https://www.wix.com/_api/premium-dns/v1/zones/[AppID]

If the code does not run sign in and out of you Wix account in a browser this should reset the counter for the recaptcha.
