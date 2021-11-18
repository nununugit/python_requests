import mechanize
import datetime
import chardet
import difflib
from detect.sqli import detect_authentication_avoidance
from detect.sqli import detect_sql_injection

def main():
    # url = input("Enter the full url: ")
    url = 'http://192.168.56.101/login.php'


    #ファイル出力処理
    now = datetime.datetime.now()
    to_file = './logs/data_{}.txt'
    to_file = to_file.format(now)

    #sqlinjectionのパターンを定義
    pattern_file = open('detect/attack_patterns/sqli.txt', 'r')
    sqli_patterns = pattern_file.readlines()

    #emailのパターンを定義
    pattern_file = open('detect/normal_patterns/emails.txt', 'r')
    emails = pattern_file.readlines()

    #攻撃ではないパターンを定義
    pattern_file = open('detect/normal_patterns/passwords.txt', 'r')
    passwords = pattern_file.readlines()

    #ファイル書き出し
    data_file = open(to_file, 'x', encoding='shift_jis')
    #攻撃コードパターンを総当たり
    print('attack requests')
    for sqli_pattern in sqli_patterns:
        for email in emails:
            #改行コードを含ませない
            sqli_pattern = sqli_pattern.replace("\n", "")
            email = email.replace("\n", "")

            print('input email:'+email+'\t input password '+ sqli_pattern)
            res_data = detect_authentication_avoidance(url,sqli_pattern,email)
            data_file.write('input email:'+email+'\t input password '+ sqli_pattern+'\n')
            data_file.write(res_data+'\n')
    
    print('normal requests')
    for password in passwords:
        for email in emails:
            #改行コードを含ませない
            password = password.replace("\n", "")
            email = email.replace("\n", "")

            print('input email:'+email+'\t input password '+ password)
            res_data = detect_authentication_avoidance(url,password,email)
            data_file.write('input email:'+email+'\t input password '+ password+'\n')
            data_file.write(res_data+'\n')
    data_file.close()


def diff(a,b):
    return (a==b)

if __name__ == '__main__':
    main()
