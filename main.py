from os import link
import mechanize
import datetime
import difflib
from urllib.request import urlopen
from bs4 import BeautifulSoup
import requests
from detect.sqli import detect_authentication_avoidance
from detect.sqli import detect_sql_injection
from detect.xss import detect_cross_site_scripting

def main():
    url = input("Enter the full url: ")
    # base_url = 'http://192.168.56.101/'
    
    #存在する可能性の高いURLを取得
    links = getLinks(base_url)
    # print(links)

    #書き出しファイル作成
    now = datetime.datetime.now()
    to_file = './logs/data_{}.txt'
    to_file = to_file.format(now)
    data_file = open(to_file, 'x', encoding='shift_jis')
    for link in links:
        #パスを合体
        url = base_url + link 
        print(url)
        
        #inputtagの有無を確認
        r = requests.get(url)
        contents = BeautifulSoup(r.text, 'html.parser')
        get_input = contents.find_all("input")


        if('login' in str(link) or 'logon' in str(link)):
            #sqlinjectionのパターンを定義
            pattern_file = open('detect/attack_patterns/sqli.txt', 'r')
            sqli_patterns = pattern_file.readlines()

            #emailのパターンを定義
            pattern_file = open('detect/normal_patterns/emails.txt', 'r')
            emails = pattern_file.readlines()

            #攻撃ではないパターンを定義
            pattern_file = open('detect/normal_patterns/passwords.txt', 'r')
            passwords = pattern_file.readlines()

            #通常のリクエスト
            print('normal requests')
            
            #通常のリクエストレスポンスを変数に格納
            for password in passwords:
                for email in emails:
                    #改行コードを含ませない
                    password = password.replace("\n", "")
                    email = email.replace("\n", "")
                    print('input email:'+email+'\t input password '+ password)
                    normal_res_data = detect_authentication_avoidance(url,password,email)

            #攻撃コードパターンを総当たり
            print('attack requests')

            for sqli_pattern in sqli_patterns:
                for email in emails:
                    #改行コードを含ませない
                    sqli_pattern = sqli_pattern.replace("\n", "")
                    email = email.replace("\n", "")
                    
                    #認証回避を検知
                    attack_res_data = detect_authentication_avoidance(url,sqli_pattern,email)
                    
                    #responceの差分があるかどうかを表示
                    diff = check_diff(normal_res_data,attack_res_data)
                    print('input email:'+email+'\t input password '+ sqli_pattern)
                    if(diff <= 1):
                        print('攻撃成功の可能性あり')
                        data_file.write('input email:'+email+'\t input password '+ sqli_pattern+'\n')
                        data_file.write('responce difference:'+str(diff)+'\n')
                        data_file.write(attack_res_data+'\n')
        if(get_input):
            print('normal requests')
            #sqlinjectionのパターンを定義
            pattern_file = open('detect/attack_patterns/xss.txt', 'r')
            xss_patterns = pattern_file.readlines()

            #攻撃ではないパターンを定義
            pattern_file = open('detect/normal_patterns/requests.txt', 'r')
            normal_requests = pattern_file.readlines()

            for normal_request in normal_requests:
                #改行コードを含ませない
                normal_request = normal_request.replace("\n", "")
                print('input request '+ normal_request)
                normal_res_data = detect_cross_site_scripting(url,normal_request)

            print('attack requests')
            for xss_pattern in xss_patterns:
                #改行コードを含ませない
                xss_pattern = xss_pattern.replace("\n", "")
                print('input request '+ xss_pattern)
                attack_res_data = detect_cross_site_scripting(url,xss_pattern)
                diff = check_diff(normal_res_data,attack_res_data)
                if(diff <= 1):
                    print('攻撃成功の可能性あり')
                    data_file.write('input request:'+ xss_pattern +'\n')
                    data_file.write('responce difference:'+str(diff)+'\n')
                    data_file.write(attack_res_data+'\n')
    data_file.close()
#2変数の違いを返す関数
def check_diff(str1,str2):
    s = difflib.SequenceMatcher(None, str1, str2).ratio()
    return s

#URLを取得する関数
def getLinks(base_url):
    r = requests.get(base_url)
    contents = BeautifulSoup(r.text, 'html.parser')
    get_a = contents.find_all("a")
    alinks = []
    for i in range(len(get_a)):
        try:
            link_ = get_a[i].get("href")
            alinks.append(link_)
        except:
            pass
    return set(alinks)

if __name__ == '__main__':
    main()
