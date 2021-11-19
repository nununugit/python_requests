import mechanize
import chardet
import re

def oscommandi():
    return 0

def detect_os_command_injection(url,pattern_data):
    #OSCOMMANDI(os_command_injection)
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)
    found_names = re.findall(r'\((.*)=\)',str(request))
    for found_name in found_names:
        if('mail' in found_name):
            request[found_name] = str(pattern_data)
    response = request.submit()
    res_data = str(response.read())
    return res_data