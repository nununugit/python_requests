import mechanize
import re

def sqli():
    return 0

def detect_authentication_avoidance(url,pattern_data,email):
    #認証回避(Authentication avoidance)
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)
    found_names = re.findall(r'\((.*)=\)',str(request))
    for found_name in found_names:
        if('password' in found_name or 'pass' in found_name ):
            request[found_name] = str(pattern_data)
        if('mail' in found_name or 'email' in found_name ):
            request[found_name] = str(email)
    response = request.submit()
    res_data = str(response.read())
    return res_data

def detect_sql_injection():
    return 0
