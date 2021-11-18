import mechanize
import chardet

def detect_authentication_avoidance(url,pattern_data,email):
    #認証回避(Authentication avoidance)
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)
    request["email"] = str(email)
    request["password"] = str(pattern_data)
    response = request.submit()
    res_data = str(response.read())
    return res_data

def detect_sql_injection():
    return 0
