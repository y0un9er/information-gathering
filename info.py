# coding=utf-8

import getopt
import os
import re
import socket
import sys
import threading
import time

import requests
from bs4 import BeautifulSoup
from whois import whois


class Info:
    def __init__(self, host):
        self.host = re.findall('(http[s]?://)?([^/:]+)', host)[0][1]
        self.portList = []
        self.lock1 = threading.Lock()
        self.lock2 = threading.Lock()
        self.ip = ''
        self.who = ''
        self.sub = []
        self.exitHost = []
        self.subHost = re.findall('(http[s]?://)?(www.)?([^/:]+)', host)[0][2]
        self.retry = 3

    def getIp(self):
        self.ip = socket.gethostbyname(self.host)
        return self.ip

    def getWhois(self):
        self.who = whois(self.host)

    def subdomain(self, page=20):
        result = []

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
            'referer': "https://cn.bing.com/"
        }

        sess = requests.session()
        sess.get("https://cn.bing.com", headers=headers)

        for i in range(page):
            url = f"https://cn.bing.com/search?q=site%3a{self.subHost}&qs=HS&sp=10&first={i * 10}&FORM=PERE&go=Search"

            response = sess.get(url=url, headers=headers)  # , verify=False)
            html = BeautifulSoup(response.text, "lxml")

            try:
                for h2 in html.find_all('h2'):
                    href = h2.find('a')['href']
                    result.append(re.search('//(.*?)/', href)[1])
            except:
                print(f"bing 反爬, 第 {4 - self.retry} 次重试")
                if self.retry:
                    self.retry -= 1
                    self.subdomain(page)
                else:
                    print('子域名爬取失败')

        self.sub = set(result)

    def portScan(self, port, host=''):
        if not host:
            host = self.host

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        try:
            s.connect((host, port))
            result = host + ':' + str(port)
        except socket.error as e:
            # print(e)
            pass

        s.close()
        if result.strip():
            # print(result)
            self.lock1.acquire()
            self.portList.append(result)
            self.lock1.release()

    def ping(self, c):
        ip = self.getIp().split('.')

        # for i in range(1, 256):
        ip[3] = str(c)
        ip_ = '.'.join(ip)

        recv = os.popen('ping -n 1 ' + ip_).read()

        state = re.search('字节=32', recv)
        if state:
            # print(ip_ + ' is exit')
            self.lock2.acquire()
            self.exitHost.append(ip_)
            self.lock2.release()

    def thread(self, target, start=1, end=5000):
        if end == 5000 and target == self.ping:
            end = 256

        ts = []

        for port in range(start, end):
            ts.append(threading.Thread(target=target, args=(port,)))

        for t in ts:
            t.start()
            # t.join()


def run(host, port_start=1, port_end=5000, c_start=1, c_end=256):
    info = Info(host)
    info.getIp()
    info.getWhois()
    info.subdomain()
    info.thread(info.portScan, start=port_start, end=port_end)
    info.thread(info.ping, start=c_start, end=c_end)

    while threading.active_count() != 1:	# 等待子进程结束
        pass

    with open('./' + info.host + '.html', 'w') as f:
        html = f'''<html>
    <head>
        <!--<meta charset="utf-8">-->
        <title>信息搜集结果</title>
    </head>
    <body>
        <h1 align="center">{info.host}</h1>
        <h2>{info.ip}</h2>
        <hr />
        <h2>Port</h2>
        <table cellspacing="20">
            <tr>
        '''

        flag = 1
        for p in info.portList:
            html += f'\n\t\t\t\t<td><a href={"http://" + p}>{p}</a></td>'

            if flag == 6:
                html += '\n\t\t\t</tr>\n\t\t\t<tr>'
                flag = 0

            flag += 1

        html += '\n\t\t\t</tr>\n\t\t</table>\n\t\t<hr />\n\t\t<h2>WHOIS</h2>\n\t\t<table cellspacing="40">'

        for k, v in dict(info.who).items():
            if not v:
                continue

            if type(v) is list:
                html += f'\n\t\t\t<tr>\n\t\t\t\t<td>{k}</td>'

                for i in v:
                    # print(i, end='\t')
                    # f.write(f'\n\t\t\t\t<td>{i}</td>')
                    html += f'\n\t\t\t\t<td>{i}</td>'
                # print()
                # f.write('\n\t\t\t</tr>')
                html += '\n\t\t\t</tr>'
            else:
                # print(k, v, sep='\t')
                # f.write(f'\n\t\t\t<tr>\n\t\t\t\t<td>{k}</td>\n\t\t\t\t<td>{v}</td></tr>')
                html += f'\n\t\t\t<tr>\n\t\t\t\t<td>{k}</td>\n\t\t\t\t<td>{v}</td></tr>'

        # f.write('\n\t\t</table>\n\t\t<hr />\n\t\t<h2>子域名</h2>')
        html += '\n\t\t</table>\n\t\t<hr />\n\t\t<h2>子域名</h2>\n\t\t<table cellspacing="20">\n\t\t\t<tr>'

        flag = 1
        for s in info.sub:
            href = "http://" + s
            # f.write(f'<a href={href}>{s}</a>')
            html += f'\n\t\t\t\t<td><a href={href}>{s}</a></td>'

            if flag == 6:
                html += '\n\t\t\t</tr>\n\t\t\t<tr>'
                flag = 0

            flag += 1

        html += '\n\t\t\t</tr>\n\t\t</table>\n\t\t<hr />\n\t\t<h2>C段</h2>\n\t\t<table cellspacing="40">\n\t\t\t<tr>'

        flag = 1

        for h in info.exitHost:
            html += f'\n\t\t\t\t<td>{h}</td>'

            if flag == 6:
                html += '\n\t\t\t</tr>\n\t\t\t<tr>'
                flag = 0

            flag += 1
        html += '\n\t\t\t</tr>\n\t\t</table>\n\t</body>\n</html>'

        f.write(html)


def usage():
    usage_info = '''
    ****************************************************************************
    *                               usage                                      *
    ****************************************************************************
          
            -h --help                查看帮助信息
    
            -H --host                设置 host
    
            -p --port         		 设置端口，默认为 1-5000
    
            -c --multiC	             设置C段，默认为 1-256
    
        Example：
            python3 info.py --host=www.baidu.com --port=1-5000 -c 1-256
    
    ****************************************************************************
    '''

    print(usage_info)
    exit()


if __name__ == '__main__':
    if sys.argv[1:]:
        host = ''
        port_start = 1
        port_end = 5000
        c_start = 1
        c_end = 256

        try:
            opts, args = getopt.getopt(sys.argv[1:], 'hH:p:c:',
                                       ['help', 'host=', 'port=', 'multiC='])
        except getopt.GetoptError as e:
            print(str(e))
            usage()

        for a, o in opts:
            if a in ('-h', '--help'):
                usage()
            elif a in ('-H', '--host'):
                host = o
            elif a in ('-p', '--port'):
                port_start = int(o.split('-')[0].strip())
                port_end = int(o.split('-')[1].strip())
            elif a in ('-c', '--multiC'):
                c_start = int(o.split('-')[0].strip())
                c_end = int(o.split('-')[1].strip())
            else:
                assert False, '[*] Unhandled option'

            if port_start > port_end or c_start > c_end or host == '':
                print("\n输入参数有误")
                usage()

        print()
        start_time = time.time()
        print('*' * 10 + '扫描开始, 开始时间：' + time.strftime("%H:%M:%S", time.localtime(start_time)) + '*' * 10)

        run(host, port_start, port_end, c_start, c_end)

        print()
        end_time = time.time()
        print('*' * 10 + '扫描结束, 结束时间：' + time.strftime("%H:%M:%S", time.localtime(end_time)) + '*' * 10)

        print('耗时: ', time.strftime("%M:%S", time.localtime(end_time - start_time)))

    else:
        host = input('请输入 host: ')

        port_start = input('请输入起始端口, 默认为 1: ')
        if port_start == '':
            port_start = 1
        else:
            port_start = int(port_start)

        port_end = input('请输入结束端口, 默认为 5000: ')
        if port_end == '':
            port_end = 5000
        else:
            port_end = int(port_end)

        c_start = input('请输入C段起始ip, 默认为 1: ')
        if c_start == '':
            c_start = 1
        else:
            c_start = int(c_start)

        c_end = input('请输入C段结束ip, 默认为 256: ')
        if c_end == '':
            c_end = 256
        else:
            c_end = int(c_end)

        print()
        start_time = time.time()
        print('*' * 10 + '扫描开始, 开始时间：' + time.strftime("%H:%M:%S", time.localtime(start_time)) + '*' * 10)

        run(host, port_start, port_end, c_start, c_end)

        print()
        end_time = time.time()
        print('*' * 10 + '扫描结束, 结束时间：' + time.strftime("%H:%M:%S", time.localtime(end_time)) + '*' * 10)

        print('耗时: ', time.strftime("%H:%M:%S", time.localtime(end_time - start_time)))
