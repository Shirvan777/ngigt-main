from urllib import request
from django.shortcuts import render,redirect
from django.contrib.auth.models import User,auth
from django.contrib import messages
from .models import WordlistUpload
import dns.resolver
import whois
import socket
import threading
import requests
import pandas as pd
from selenium import webdriver
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from django.http import FileResponse
import time


def index(request):
    x = 'home'
    return render(request,'index.html',{'x':x})

def login(request):
    if request.method == 'POST':
        if 'login' in request.POST:
            login.username = request.POST['username']
            login.password = request.POST['password']

            user = auth.authenticate(username=login.username,password=login.password)
            if user is not None:
                auth.login(request, user)
                time.sleep(5)
                return redirect('index')
            else:
                messages.info(request, 'Username or Password is incorrect')    
                return redirect('login')
        if 'register' in request.POST:
            email = request.POST['email']
            password2 = request.POST['password2']
            reg_password = request.POST['regpassword']
            reg_username = request.POST['regusername']
            if reg_password == password2:
                if User.objects.filter(username=reg_username).exists():
                    messages.info(request, 'Registration is failed. Usarname already in use')
                    return redirect('login')
                elif User.objects.filter(email=email).exists():
                    messages.info(request, 'Registration is failed. Email already in use')
                    return redirect('login')
            else:
                messages.info(request, 'Registration is failed. Passwords must be same') 
                return redirect('login')
            user = User.objects.create_user(username=reg_username,email=email,password=reg_password)    
            user.save()        
            return redirect('login')
    return render(request, 'login.html')


def register(request):
    if request.method == 'POST':
        register.name = request.POST['name']
        register.username = request.POST['username']
        register.email = request.POST['email']
        register.password = request.POST['password']
        register.password2 = request.POST['password2']

        if register.password == register.password2:
            if User.objects.filter(username=register.username).exists():
                messages.info(request, 'Usarname already in use')
                return redirect('register')   
            elif User.objects.filter(email=register.email).exists():
                messages.info(request, 'Email already in use')
                return redirect('register')
        else:
            messages.info(request, 'Passwords must be same') 
            return redirect('register')
        user = User.objects.create_user(username=register.username,email=register.email,password=register.password,first_name = register.name)    
        user.save()        
        return redirect('login')                   
    else:
        return render(request, 'register.html')    


def subdomain_finder(request):    
    def brute(wlist):
        data = ''
        subdomains = []
        with open(wlist, "r") as wordlist:
            for word in wordlist:
                subdomain = word.strip() + "." + subdomain_finder.domain
                try:
                    socket.gethostbyname(subdomain)
                    subdomains.append(subdomain)
                    data += "[+] Discovered subdomain: " +  subdomain + '\n'
                    print(data)
                except:
                    pass
            if not subdomains:
                data += "[-] No subdomains were found.\n"  
            else:
                data += "[+] Total subdomains found:" + str(len(subdomains)) + '\n'
        return data
    
    def subdomain_checker(wordlist):
        data = ''
        subdomains = []
        for word in wordlist.open():
            word = word.decode("utf-8")
            subdomain = word.strip() + "." + subdomain_finder.domain
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
                data += "[+] Discovered subdomain: " +  subdomain + '\n'
                print(data)
            except:
                pass
        if not subdomains:
            data += "[-] No subdomains were found.\n"
        else:
            data += "[+] Total subdomains found:" + str(len(subdomains)) + '\n'
        return data
    x = 'subdomain_finder'
    if request.method == 'POST':
        subdomain_finder.domain = request.POST['search']
        data = ''
        if 'wordlst' in request.POST:
            subdomain_finder.wordlist = request.POST['wordlst']
            match subdomain_finder.wordlist:
                case 'wordlist_1':
                    wlist = 'media/fck.lst'
                    data = brute(wlist)
                case 'wordlist_2':
                    wlist = 'media/47min.txt'
                    data = brute(wlist)
                case 'wordlist_3':
                    wlist = 'media/rus_100min.lst'
                    data = brute(wlist)
            threads = []
            thread = threading.Thread(target=brute, args=(wlist,))
            thread.start()
            threads.append(thread)
            for thread in threads:
                thread.join()

            return render(request,'index.html',{'x':x,'data':data})
        elif 'file' in request.FILES:
            wordlist = request.FILES['file']
            threads = []
            thread = threading.Thread(target=subdomain_checker, args=(wordlist,))
            thread.start()
            threads.append(thread)
            for thread in threads:
                thread.join()
            data = subdomain_checker(wordlist)
        return render(request,'index.html',{'x':x,'data':data})    
    return render(request,'index.html',{'x':x})

def dns_search(request):
    x = 'dns'
    if request.method == "POST":
        record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'SPF','TXT','NAPTR','SRV','CAA']
        dns_search.domain = request.POST['search']
        data = ''
        for records in record_types:
            out = f'\n{records} Records\n' + '-' * 30 + '\n'
            data = data + out 
            try:
                answer = dns.resolver.resolve(dns_search.domain, records)
                for server in answer:   
                    data += server.to_text() + '\n'       
            except:
                data += 'Sorry, no record found\n'
                
        return render(request,'index.html',{'data':data,'x':x})
    return render(request,'index.html',{'x':x})

def whois_search(request):
    x = 'whois'
    data = ''
    if request.method == 'POST':
        s = request.POST['search']
        w = whois.whois(s)
        data += "[+] WHOIS Information data for " + s +'\n\n'
        data += "[+] Registrar:" + str(w.registrar)+'\n\n'
        data += "[+] Creation Date:" + str(w.creation_date)+'\n\n'
        data += "[+] Expiration Date:" + str(w.expiration_date)+'\n\n'
        data += "[+] Update Date:" + str(w.updated_date)+'\n\n'
        data += "[+] Domain Name:" + str(w.domain_name)+'\n\n'
        data += "[+] Registrant Country:" + str(w.country)+'\n\n'
        data += "[+] State:" + str(w.state)+'\n\n'
        data += "[+] City:" + str(w.city)+'\n\n'
        data += "[+] Registrar IANA ID:" + str(w.registrar_id)+'\n\n'
        data += "[+] Organization:" + str(w.org)+'\n\n'
        data += "[+] Registrar Abuse Contact Phone:" + str(w.tech_country)+'\n\n'
        data += "[+] Registrar Abuse Contact Email:" + str(w.tech_country)+'\n\n'
        data += "[+] Name Servers:" + str(w.name_servers)+'\n\n'
        a = w.status
        a = str(a).replace(',','\n')
        data += "[+] Status:" + a+'\n\n'
        data += "[+] Emails:" + str(w.emails)+'\n\n'
    return render(request,'index.html',{'x':x,'data':data})


def netcraft(request):
    x = 'netcraft'
    data = ''
    if request.method == 'POST':
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        netcraft.domain = request.POST['search']
        driver = webdriver.Chrome()
        driver.get("https://sitereport.netcraft.com/?url=" + netcraft.domain)


        wait = WebDriverWait(driver, 30)
        spinner = wait.until(EC.invisibility_of_element_located((By.CLASS_NAME, "loading-spinner")))


        soup = BeautifulSoup(driver.page_source, 'html.parser')

        driver.quit()

        results = pd.read_html(str(soup))
        for table in results:
            for index, row in table.iterrows():
                if row[0] == 'Netcraft Risk Rating':
                    data += (f"{row[0]} - {row[1]}\n").replace('&rdsh;', '').replace('↳ ','')[:28]
                    data += '\n'
                elif row[0] == 'p=reject' or row[0] =='+ (Pass)' or row[0] =='~ (SoftFail)' or row[0] =='Latest Performance':
                    pass
                elif row[0] == 'DNS Security Extensions':
                    data += (f"{row[0]} - {row[1]}\n\n IP Delegation\n").replace('&rdsh;', '').replace('↳ ','')
                elif row[0] == 'SSL' or row[0] == 'JavaScript':
                    data += (f"\n\nSite Technology\n\n{row[0]} - {row[1]}\n").replace('&rdsh;', '').replace('↳ ','')
                else:
                    data += (f"{row[0]} - {row[1]}\n").replace('&rdsh;', '').replace('↳ ','')
    return render(request,'index.html',{'x':x,'data':data})


def logout(request):
    auth.logout(request)
    return redirect('login')


def about_creators(request):
    x = 'about_creators'
    return render(request,'index.html',{'x':x})

def download(request):
    return FileResponse(open('media/ngigt.exe','rb'))


def custom_page_not_found_view(request, exception):
    return render(request, "404.html", {})


def custom_500_error(request):
    return render(request, "500.html", {})