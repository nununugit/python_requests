# -*- coding: utf-8 -*-
import mechanize
import datetime
import chardet
import difflib
from detect.detect_sqli import detect_authentication_avoidance
from detect.detect_sqli import detect_sql_injection

def main():
    # url = input("Enter the full url: ")
    url = 'http://192.168.56.101/login.php'
    normal_res_data = detect_authentication_avoidance(url,True)
    attack_res_data = detect_authentication_avoidance(url,False)

    aa_flag = diff(normal_res_data,attack_res_data)
    #ファイル出力処理
    now = datetime.datetime.now()
    to_file = './logs/data_{}.txt'
    to_file = to_file.format(now)

    data_file = open(to_file, 'x')
    data_file.write(str(aa_flag))
    data_file.close()

def diff(a,b):
    return (a==b)

if __name__ == '__main__':
    main()
    