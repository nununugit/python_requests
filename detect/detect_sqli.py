# -*- coding: utf-8 -*-
import mechanize
import chardet
import csv

def detect_authentication_avoidance(url,n_flag):
    #認証回避(Authentication avoidance)
    attack_no = 1
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)

    request["email"] = "a@a"
    request["password"] = "postcard"
    if(n_flag == True):
        request["password"] = "password"
    response = request.submit()
    res_data = str(response.read())
    return res_data

def detect_sql_injection():
    return 0