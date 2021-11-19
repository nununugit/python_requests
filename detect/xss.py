import mechanize
import chardet
import re

def xss():
    return 0

def detect_cross_site_scripting(url,pattern_data):
    #XSS(cross_site_scripting)
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