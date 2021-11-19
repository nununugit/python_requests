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
    request.form.set_all_readonly(False) 
    found_names = re.findall(r'\((.*)=\)',str(request))
    for found_name in found_names:
        request[found_name] = pattern_data
        # if(request.find_control(found_name).readonly == True):
        #     request.find_control(found_name).readonly = False # allow changing .value of control foo 
    response = request.submit()
    res_data = str(response.read())
    return res_data