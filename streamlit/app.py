import streamlit as st
from PIL import Image
import pandas as pd
from selenium import webdriver
import json
from io import BytesIO
from urllib.parse import urlparse
import requests
import socket
import re
import torch
import time
import Levenshtein
import urllib.parse
import tldextract
import whois
import tensorflow as tf
from bs4 import BeautifulSoup
from datetime import datetime
import dns.resolver
import threading
from selenium.webdriver.firefox.service import Service
from ultralytics import YOLO
from selenium.webdriver.firefox.options import Options

st.sidebar.title("Thông tin chi tiết")
HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

allbrand_txt = open("streamlit/allbrands.txt", "r")

def __txt_to_list(txt_object):
    list = []
    for line in txt_object:
        list.append(line.strip())
    txt_object.close()
    return list

allbrand = __txt_to_list(allbrand_txt)

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def url_length(url):
    return len(url)

def shortening_service(full_url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      full_url)
    if match:
        return 1
    else:
        return 0

def count_at(base_url):
     return base_url.count('@')

def count_comma(base_url):
     return base_url.count(',')


def count_dollar(base_url):
     return base_url.count('$')

def count_semicolumn(url):
     return url.count(';')

def count_space(base_url):
     return base_url.count(' ')+base_url.count('%20')

def count_and(base_url):
     return base_url.count('&')

def count_double_slash(full_url):
    list=[x.start(0) for x in re.finditer('//', full_url)]
    if list[len(list)-1]>6:
        return 1
    else:
        return 0

def count_slash(full_url):
    return full_url.count('/')

def count_equal(base_url):
    return base_url.count('=')

def count_percentage(base_url):
    return base_url.count('%')

def count_exclamation(base_url):
    return base_url.count('?')

def count_underscore(base_url):
    return base_url.count('_')

def count_hyphens(base_url):
    return base_url.count('-')

def count_dots(hostname):
    return hostname.count('.')

def count_colon(url):
    return url.count(':')

def count_star(url):
    return url.count('*')

def count_or(url):
    return url.count('|')

def path_extension(url_path):
    if url_path.endswith('.txt'):
        return 1
    return 0

def count_http_token(url_path):
    return url_path.count('http')

def https_token(scheme):
    if scheme == 'https':
        return 0
    return 1

def ratio_digits(hostname):
    return len(re.sub("[^0-9]", "", hostname))/len(hostname)

def count_digits(line):
    return len(re.sub("[^0-9]", "", line))

def count_tilde(full_url):
    if full_url.count('~')>0:
        return 1
    return 0

def phish_hints(url_path):
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count

def tld_in_path(tld, path):
    if path.lower().count(tld)>0:
        return 1
    return 0

def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld)>0:
        return 1
    return 0

def tld_in_bad_position(tld, subdomain, path):
    if tld_in_path(tld, path)== 1 or tld_in_subdomain(tld, subdomain)==1:
        return 1
    return 0

def abnormal_subdomain(url):
    if re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))',url):
        return 1
    return 0

def count_redirection(url):
    try:
        global rq
        rq = requests.get(url, timeout=5)
        return len(rq.history)
    except:
        return 0

def count_external_redirection(domain):
    try:
        count = 0
        if len(rq.history) == 0:
            return 0
        else:
            for i, response in enumerate(rq.history,1):
                if domain.lower() not in response.url.lower():
                    count+=1
                return count
    except:
        return 0

def char_repeat(words_raw):

        def __all_same(items):
            return all(x == items[0] for x in items)

        repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
        part = [2, 3, 4, 5]

        for word in words_raw:
            for char_repeat_count in part:
                for i in range(len(word) - char_repeat_count + 1):
                    sub_word = word[i:i + char_repeat_count]
                    if __all_same(sub_word):
                        repeat[str(char_repeat_count)] = repeat[str(char_repeat_count)] + 1
        return  sum(list(repeat.values()))

def punycode(url):
    if url.startswith("http://xn--") or url.startswith("http://xn--"):
        return 1
    else:
        return 0

def domain_in_brand(domain):

    if domain in allbrand:
        return 1
    else:
        return 0


def domain_in_brand1(domain):
    for d in allbrand:
        if len(Levenshtein.editops(domain.lower(), d.lower()))<2:
            return 1
    return 0

def brand_in_path(domain,path):
    for b in allbrand:
        if '.'+b+'.' in path and b not in domain:
           return 1
    return 0

def check_www(words_raw):
        count = 0
        for word in words_raw:
            if not word.find('www') == -1:
                count += 1
        return count

def check_com(words_raw):
        count = 0
        for word in words_raw:
            if not word.find('com') == -1:
                count += 1
        return count

def port(url):
    if re.search("^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)",url):
        return 1
    return 0

def length_word_raw(words_raw):
    return len(words_raw)

def average_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return sum(len(word) for word in words_raw) / len(words_raw)

def longest_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return max(len(word) for word in words_raw)

def shortest_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return min(len(word) for word in words_raw)

def prefix_suffix(url):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0

def count_subdomain(url):
    if len(re.findall("\.", url)) == 1:
        return 1
    elif len(re.findall("\.", url)) == 2:
        return 2
    else:
        return 3

import socket

def statistical_report(url, domain):
    url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
    try:
        ip_address=socket.gethostbyname(domain)
        ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                           '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                           '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                           '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                           '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                           '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
        if url_match or ip_match:
            return 1
        else:
            return 0
    except:
        return 2

suspecious_tlds = ['fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', # Spamhaus
        'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
        'ren', 'mom', 'party', 'review', 'trade', 'accountants',
        'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
        'accountant', 'realtor', 'top', 'christmas', 'gdn', # Shady Top-Level Domains
        'link', # Blue Coat Systems
        'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
        'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au' # statistics
        ]


def suspecious_tld(tld):
   if tld in suspecious_tlds:
       return 1
   return 0

def nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
     return len(Href['internals']) + len(Href['externals']) +\
            len(Link['internals']) + len(Link['externals']) +\
            len(Media['internals']) + len(Media['externals']) +\
            len(Form['internals']) + len(Form['externals']) +\
            len(CSS['internals']) + len(CSS['externals']) +\
            len(Favicon['internals']) + len(Favicon['externals'])


def h_total(Href, Link, Media, Form, CSS, Favicon):
    return nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)

def h_internal(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['internals']) + len(Link['internals']) + len(Media['internals']) +\
           len(Form['internals']) + len(CSS['internals']) + len(Favicon['internals'])


def internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    if total == 0:
        return 0
    else :
        return h_internal(Href, Link, Media, Form, CSS, Favicon)/total


def h_external(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['externals']) + len(Link['externals']) + len(Media['externals']) +\
           len(Form['externals']) + len(CSS['externals']) + len(Favicon['externals'])


def external_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    if total == 0:
        return 0
    else :
        return h_external(Href, Link, Media, Form, CSS, Favicon)/total


def external_css(CSS):
    return len(CSS['externals'])


def h_i_error(Href, Link, Media, Form, CSS, Favicon):
    if h_internal(Href, Link, Media, Form, CSS, Favicon)>10:
        return 0
    count = 0
    for link in Href['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Link['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Media['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Form['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in CSS['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Favicon['internals']:
        try:
            if requests.get("https://" + link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    return count


def internal_redirection(Href, Link, Media, Form, CSS, Favicon,i_error):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if (internals>0):
            return  (internals - i_error)/internals
    return 0

def external_redirection(Href, Link, Media, Form, CSS, Favicon, e_error):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals>0):
            return  (externals - e_error)/externals
    return 0


def h_e_error(Href, Link, Media, Form, CSS, Favicon):
    if h_external(Href, Link, Media, Form, CSS, Favicon)>10:
        return 0
    count = 0
    for link in Href['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Link['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Media['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Form['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in CSS['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    for link in Favicon['externals']:
        try:
            if requests.get(link, timeout =1).status_code >=400:
                count+=1
        except:
            continue
    return count


def external_errors(Href, Link, Media, Form, CSS, Favicon,e_error):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals>0):
            return e_error/externals
    return 0

def login_form(Form):
    p = re.compile('([a-zA-Z0-9\_])+.php')
    if len(Form['externals'])>0 or len(Form['null'])>0:
        return 1
    for form in Form['internals']+Form['externals']:
        if p.match(form) != None :
            return 1
    return 0

def external_favicon(Favicon):
    if len(Favicon['externals'])>0:
        return 1
    return 0

def submitting_to_email(Form):
    for form in Form['internals'] + Form['externals']:
        if "mailto:" in form or "mail()" in form:
            return 1
        else:
            return 0
    return 0

def internal_media(Media):
    total = len(Media['internals']) + len(Media['externals'])
    internals = len(Media['internals'])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0

    return percentile

def external_media(Media):
    total = len(Media['internals']) + len(Media['externals'])
    externals = len(Media['externals'])
    try:
        percentile = externals / float(total) * 100
    except:
        return 0

    return percentile

def empty_title(Title):
    if Title:
        return 0
    return 1

def safe_anchor(Anchor):
    total = len(Anchor['safe']) +  len(Anchor['unsafe'])
    unsafe = len(Anchor['unsafe'])
    try:
        percentile = unsafe / float(total) * 100
    except:
        return 0
    return percentile

def links_in_tags(Link):
    total = len(Link['internals']) +  len(Link['externals'])
    internals = len(Link['internals'])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0
    return percentile

def iframe(IFrame):
    if len(IFrame['invisible'])> 0:
        return 1
    return 0

def popup_window(content):
    if "prompt(" in str(content).lower():
        return 1
    else:
        return 0

def domain_in_title(domain, title):
  try:
    if domain.lower() in title.lower():
        return 0
    return 1
  except:
    return 0

def domain_with_copyright(domain, content):
    try:
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        _copyright = content[m.span()[0]-50:m.span()[0]+50]
        if domain.lower() in _copyright.lower():
            return 0
        else:
            return 1
    except:
        return 0

def domain_registration_length(host):
    try:
        expiration_date = host.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1


def whois_registered_domain(host,domain):
    try:
        hostname = host.domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 0
            return 1
        else:
            if re.search(hostname.lower(), domain):
                return 0
            else:
                return 1
    except:
        return 1


def domain_age(host):
    try:
        creation_date = host.creation_date
        expiration_date = host.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age
    except:
        return -1

def google_index(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        }

        google = "https://www.google.com/search?q=site:" + url + "&hl=en"
        response = requests.get(google, headers=headers, timeout = 3)
        soup = BeautifulSoup(response.content, "html.parser")
        not_indexed = re.compile("did not match any documents")

        if soup(text=not_indexed):
            return 0
        else:
            return 1
    except :
        return 0



def dns_record(domain):
    try:
        nameservers = dns.resolver.resolve(domain,'NS')
        if len(nameservers)>0:
            return 0
        else:
            return 1
    except:
        return 1


def page_rank(result):
    try:
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


def rank(result):
    try:
        result = result['response'][0]['rank']
        if result:
            return int(result)
        else:
            return 0
    except:
        return -1


def domainEnd(host):
    try:
        expiration_date = host.expiration_date
        if isinstance(expiration_date,str):
            try:
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end/30) < 6):
                end = 0
            else:
                end = 1
        return end
    except:
        return -1

def extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

    soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')
    for href in soup.find_all('a', href=True):
        dots = [x.start(0) for x in re.finditer('\.', href['href'])]
        if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
            if "#" in href['href'] or "javascript" in href['href'].lower() or "mailto" in href['href'].lower():
                 Anchor['unsafe'].append(href['href'])
            if not href['href'].startswith('http'):
                if not href['href'].startswith('/'):
                    Href['internals'].append(hostname+'/'+href['href'])
                elif href['href'] in Null_format:
                    Href['null'].append(href['href'])
                else:
                    Href['internals'].append(hostname+href['href'])
        else:
            Href['externals'].append(href['href'])
            Anchor['safe'].append(href['href'])

    # collect all media src tags
    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer('\.', img['src'])]
        if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
            if not img['src'].startswith('http'):
                if not img['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+img['src'])
                elif img['src'] in Null_format:
                    Media['null'].append(img['src'])
                else:
                    Media['internals'].append(hostname+img['src'])
        else:
            Media['externals'].append(img['src'])


    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
        if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
             if not audio['src'].startswith('http'):
                if not audio['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+audio['src'])
                elif audio['src'] in Null_format:
                    Media['null'].append(audio['src'])
                else:
                    Media['internals'].append(hostname+audio['src'])
        else:
            Media['externals'].append(audio['src'])

    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
        if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
             if not embed['src'].startswith('http'):
                if not embed['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+embed['src'])
                elif embed['src'] in Null_format:
                    Media['null'].append(embed['src'])
                else:
                    Media['internals'].append(hostname+embed['src'])
        else:
            Media['externals'].append(embed['src'])

    for i_frame in soup.find_all('iframe', src=True):
        dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
        if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith('http'):
            if not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+i_frame['src'])
                elif i_frame['src'] in Null_format:
                    Media['null'].append(i_frame['src'])
                else:
                    Media['internals'].append(hostname+i_frame['src'])
        else:
            Media['externals'].append(i_frame['src'])


    # collect all link tags
    for link in soup.findAll('link', href=True):
        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    Link['internals'].append(hostname+'/'+link['href'])
                elif link['href'] in Null_format:
                    Link['null'].append(link['href'])
                else:
                    Link['internals'].append(hostname+link['href'])
        else:
            Link['externals'].append(link['href'])

    for script in soup.find_all('script', src=True):
        dots = [x.start(0) for x in re.finditer('\.', script['src'])]
        if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith('http'):
            if not script['src'].startswith('http'):
                if not script['src'].startswith('/'):
                    Link['internals'].append(hostname+'/'+script['src'])
                elif script['src'] in Null_format:
                    Link['null'].append(script['src'])
                else:
                    Link['internals'].append(hostname+script['src'])
        else:
          try:
            Link['externals'].append(script['href'])
          except:
            pass


    # collect all css
    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    CSS['internals'].append(hostname+'/'+link['href'])
                elif link['href'] in Null_format:
                    CSS['null'].append(link['href'])
                else:
                    CSS['internals'].append(hostname+link['href'])
        else:
            CSS['externals'].append(link['href'])

    for style in soup.find_all('style', type='text/css'):
        try:
            start = str(style[0]).index('@import url(')
            end = str(style[0]).index(')')
            css = str(style[0])[start+12:end]
            dots = [x.start(0) for x in re.finditer('\.', css)]
            if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                if not css.startswith('http'):
                    if not css.startswith('/'):
                        CSS['internals'].append(hostname+'/'+css)
                    elif css in Null_format:
                        CSS['null'].append(css)
                    else:
                        CSS['internals'].append(hostname+css)
            else:
                CSS['externals'].append(css)
        except:
            continue

    # collect all form actions
    for form in soup.findAll('form', action=True):
        dots = [x.start(0) for x in re.finditer('\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith('http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname+'/'+form['action'])
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])
                else:
                    Form['internals'].append(hostname+form['action'])
        else:
            Form['externals'].append(form['action'])


    # collect all link tags
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
            if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                if not head.link['href'].startswith('http'):
                    if not head.link['href'].startswith('/'):
                        Favicon['internals'].append(hostname+'/'+head.link['href'])
                    elif head.link['href'] in Null_format:
                        Favicon['null'].append(head.link['href'])
                    else:
                        Favicon['internals'].append(hostname+head.link['href'])
            else:
                Favicon['externals'].append(head.link['href'])

        for head.link in soup.findAll('link', {'href': True, 'rel':True}):
            isicon = False
            if isinstance(head.link['rel'], list):
                for e_rel in head.link['rel']:
                    if (e_rel.endswith('icon')):
                        isicon = True
            else:
                if (head.link['rel'].endswith('icon')):
                    isicon = True

            if isicon:
                 dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                 if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                     if not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('/'):
                            Favicon['internals'].append(hostname+'/'+head.link['href'])
                        elif head.link['href'] in Null_format:
                            Favicon['null'].append(head.link['href'])
                        else:
                            Favicon['internals'].append(hostname+head.link['href'])
                 else:
                     Favicon['externals'].append(head.link['href'])


    # collect i_frame
    for i_frame in soup.find_all('iframe', width=True, height=True, frameborder=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameborder'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, border=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['border'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, style=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['style'] == "border:none;":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)

    # get page title
    try:
        Title = soup.title.string
    except:
        pass

    # get content text
    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text



def extract_features(url):
    def get_domain(url):
      o = urllib.parse.urlsplit(url)
      return o.hostname, tldextract.extract(url).domain, o.path
    def words_raw_extraction(domain, subdomain, path):
        w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
        w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None,raw_words))
        return raw_words, list(filter(None,w_host)), list(filter(None,w_path))

    Href = {'internals':[], 'externals':[], 'null':[]}
    Link = {'internals':[], 'externals':[], 'null':[]}
    Anchor = {'safe':[], 'unsafe':[], 'null':[]}
    Media = {'internals':[], 'externals':[], 'null':[]}
    Form = {'internals':[], 'externals':[], 'null':[]}
    CSS = {'internals':[], 'externals':[], 'null':[]}
    Favicon = {'internals':[], 'externals':[], 'null':[]}
    IFrame = {'visible':[], 'invisible':[], 'null':[]}
    Title =''
    Text= ''
    
    if state:
        content = page
        hostname, domain, path = get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain+'.'+extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix):len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path= words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme
        
        try:
            host = whois.whois(domain)
        except:
            host = ""

        try:
            key = 'c4skc4o8kswocso0og84w4gk44so048k8og44000'
            rank_domain = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
            request = requests.get(rank_domain, headers={'API-OPR':key}, timeout =3)
            result_json = request.json()
        except:
            result_json = ""

        Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text)
        e_error = h_e_error(Href, Link, Media, Form, CSS, Favicon)
        i_error = h_i_error(Href, Link, Media, Form, CSS, Favicon)
        row = [
              # url-based features
              url_length(url),
              url_length(hostname),
              having_ip_address(url),
              count_dots(url),
              count_hyphens(url),
              count_at(url),
              count_exclamation(url),
              count_and(url),
              count_or(url),
              count_equal(url),
              count_underscore(url),
              count_tilde(url),
              count_percentage(url),
              count_slash(url),
              count_star(url),
              count_colon(url),
              count_comma(url),
              count_semicolumn(url),
              count_dollar(url),
              count_space(url),

              check_www(words_raw),
              check_com(words_raw),
              count_double_slash(url),
              count_http_token(path),
              https_token(scheme),

              count_digits(url),
              ratio_digits(hostname),
              punycode(url),
              port(url),
              tld_in_path(tld, path),
              tld_in_subdomain(tld, subdomain),
              abnormal_subdomain(url),
              count_subdomain(url),
              prefix_suffix(url),
              shortening_service(url),


              path_extension(path),
              count_redirection(source_url),
              count_external_redirection(domain),
              length_word_raw(words_raw),
              char_repeat(words_raw),
              shortest_word_length(words_raw),
              shortest_word_length(words_raw_host),
              shortest_word_length(words_raw_path),
              longest_word_length(words_raw),
              longest_word_length(words_raw_host),
              longest_word_length(words_raw_path),
              average_word_length(words_raw),
              average_word_length(words_raw_host),
              average_word_length(words_raw_path),

              phish_hints(url),
              domain_in_brand(extracted_domain.domain),
              brand_in_path(extracted_domain.domain,subdomain),
              brand_in_path(extracted_domain.domain,path),
              suspecious_tld(tld),
              statistical_report(url, domain),


               # # # content-based features
              nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
              internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
              external_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
              external_css(CSS),
              internal_redirection(Href, Link, Media, Form, CSS, Favicon,i_error),
              external_redirection(Href, Link, Media, Form, CSS, Favicon,e_error),
              external_errors(Href, Link, Media, Form, CSS, Favicon,e_error),
              login_form(Form),
              external_favicon(Favicon),
              links_in_tags(Link),
              submitting_to_email(Form),
              internal_media(Media),
              external_media(Media),
            #  # additional content-based features
              iframe(IFrame),
              popup_window(Text),
              safe_anchor(Anchor),
              empty_title(Title),
              domain_in_title(extracted_domain.domain, Title),
              domain_with_copyright(extracted_domain.domain, Text),

            # # # # thirs-party-based features
              whois_registered_domain(host,domain),
              domain_registration_length(host),
              domain_age(host),
              dns_record(domain),
              google_index(url),
              page_rank(result_json),
              rank(result_json),
              domainEnd(host)
        ]
        return row
    else:
        return None

def get_external_domains_with_selenium(url):
    soup = BeautifulSoup(page, 'html.parser')

    parsed_url = urlparse(url)
    base_domain = parsed_url.netloc

    external_domains = set()

    # Duyệt qua tất cả các thẻ <a> trong trang
    for link in soup.find_all('a', href=True):
        href = link['href']
        parsed_href = urlparse(href)
        domain = parsed_href.netloc

        if domain and domain != base_domain:
            external_domains.add(domain)

    return external_domains


def static():
    with st.spinner(f"Đang xử lý Static..."):
        predict_static = ""
        try:
            row = extract_features(url)
            name = ['length_url', 'length_hostname','ip','nb_dots',	'nb_hyphens',	'nb_at',	'nb_qm','nb_and',	'nb_or',	
                                                    'nb_eq',	'nb_underscore',	'nb_tilde'	,'nb_percent'	,'nb_slash'	,'nb_star'	,'nb_colon',	'nb_comma',	'nb_semicolumn',	'nb_dollar'	,
                                                    'nb_space',	'nb_www'	,'nb_com'	,'nb_dslash'	, 'http_in_path'	,'https_token',	'ratio_digits_url'	,'ratio_digits_host',	'punycode',	
                                                    'port'	,'tld_in_path',	'tld_in_subdomain',	'abnormal_subdomain'	,'nb_subdomains'	,'prefix_suffix',	'shortening_service',
                                                    'path_extension','nb_redirection'	,'nb_external_redirection'	,'length_words_raw'	,'char_repeat'	,'shortest_words_raw'	,'shortest_word_host',
                                                    'shortest_word_path'	,'longest_words_raw'	,'longest_word_host',	'longest_word_path'	,'avg_words_raw'	,'avg_word_host'	,'avg_word_path',
                                                    'phish_hints'	,'domain_in_brand'	,'brand_in_subdomain',	'brand_in_path'	,'suspecious_tld'	,'statistical_report','nb_hyperlinks',	
                                                    'ratio_intHyperlinks'	,'ratio_extHyperlinks',	'nb_extCSS',	'ratio_intRedirection',	'ratio_extRedirection'	,
                                                    'ratio_extErrors',	'login_form',	'external_favicon',	'links_in_tags'	,'submit_email'	,'ratio_intMedia'	,'ratio_extMedia',
                                                    'iframe',	'popup_window',	'safe_anchor',	'empty_title',	'domain_in_title',	'domain_with_copyright',	
                                                    'whois_registered_domain',	'domain_registration_length',	'domain_age',	'dns_record',	'google_index',	'page_rank', 'rank', 'domainEnd']
            
            df = pd.DataFrame([row])
            input_dict = [tf.convert_to_tensor([value]) for name, value in  df.items()]
            predictions_static = model_static.predict(input_dict)
            predict_static = predictions_static[0][0]
            st.sidebar.write(f"Phishing: {predict_static*100}%")
            for item1, item2 in zip(row, name):
                st.sidebar.write(f"{item2}: {item1}")
        except:
            pass
        global sta 
        sta = predict_static
        return 



def dynamic():
    with st.spinner(f"Đang xử lý Dynamic..."):
        predict_dynamic=""
        if state:
            try:
                time.sleep(1)
                screenshot = driver.get_screenshot_as_png()
                image = Image.open(BytesIO(screenshot)).convert('RGB')
                global shot 
                shot = image
                image = image.crop((0, 0, 1400, 300))
                results =model_dynamic.predict(image)
                for result in results:
                    label = int(result.boxes.cls)
                    score = result.boxes.conf.item()    
                    print(score)
                    print(label)
                    if score > 0.7:
                        external_domains = get_external_domains_with_selenium(url)
                    
                        label_to_string = {v: k for k, v in class_dict.items()}
                        label = label_to_string[label]
                        domains = len([item for item in external_domains if label in item])
                        if domains ==0:
                            predict_dynamic = 'phishing'
                        else:
                            predict_dynamic = 'legitimate'                
            except:
                pass
        else:
            pass
        global dy
        dy = predict_dynamic
        return 

class_dict  = {'ionos': 0,
 '101domain': 1,
 '2ndswing': 2,
 '4sysops': 3,
 'adp': 4,
 'aol': 5,
 'asb': 6,
 'att': 7,
 'atb': 8,
 'ayso': 9,
 'abbreviation': 10,
 'absa': 11,
 'academia': 12,
 'academiamusical': 13,
 'acquadiparma': 14,
 'adage': 15,
 'adobe': 16,
 'aikido': 17,
 'alaskausa': 18,
 'aldec': 19,
 'alibaba': 20,
 'allegro': 21,
 'allmystery': 22,
 'allpax': 23,
 'amazon': 24,
 'americanexpress': 25,
 'americanvan': 26,
 'americanas': 27,
 'analysicsvidhya': 28,
 'apple': 29,
 'aruba': 30,
 'astratex': 31,
 'australia': 32,
 'autoscout24': 33,
 'bbt': 34,
 'bhtelecom': 35,
 'bt': 36,
 'bzst': 37,
 'sella': 38,
 'safra': 39,
 'bancodechile': 40,
 'bb': 41,
 'bancoestado': 42,
 'bankalhabib': 43,
 'bankofamerica': 44,
 'bmo': 45,
 'bnz': 46,
 'bankofscotland': 47,
 'bankbahamas': 48,
 'bankia': 49,
 'bargainballoons': 50,
 'belivehotels': 51,
 'bedslide': 52,
 'belizebank': 53,
 'bet365': 54,
 'bethpage': 55,
 'bionity': 56,
 'blackberrys': 57,
 'blockchain': 58,
 'bouyguestelecom': 59,
 'byggmax': 60,
 'caf': 61,
 'cbs': 62,
 'cibc': 63,
 'cab': 64,
 'caixabank': 65,
 'caixa': 66,
 'cgd': 67,
 'capsulink': 68,
 'caremax': 69,
 'careerexplorer': 70,
 'cartalk': 71,
 'caterworth': 72,
 'cembra': 73,
 'centurylink': 74,
 'chase': 75,
 'chronopost': 76,
 'clker': 77,
 'clubmap': 78,
 'codeproject': 79,
 'colosus': 80,
 'comcast': 81,
 'cox': 82,
 'credit-agricole': 83,
 'credit-suisse': 84,
 'creditdunord': 85,
 'dcrainmaker': 86,
 'dcu': 87,
 'dgi': 88,
 'dhl': 89,
 'dkwheels': 90,
 'dstype': 91,
 'daum': 92,
 'dealnews': 93,
 'delta': 94,
 'desjardins': 95,
 'telekom': 96,
 'discover': 97,
 'docontherun': 98,
 'docusign': 99,
 'dropbox': 100,
 'dulux': 101,
 'earthlink': 102,
 'eham': 103,
 'elefantszerszam': 104,
 'elegantthemes': 105,
 'emby': 106,
 'emiratesnbd': 107,
 'enel': 108,
 'envestnet': 109,
 'equa': 110,
 'etisalat': 111,
 'fmu': 112,
 'fnb': 113,
 'fsu': 114,
 'facebook': 115,
 'fastcabinetdoors': 116,
 'fibank': 117,
 'floorsdirect': 118,
 'free': 119,
 'thefreedictonary': 120,
 'frontier': 121,
 'gsmarena': 122,
 'geekinterview': 123,
 'geni': 124,
 'giffgaff': 125,
 'gitlab': 126,
 'globalsources': 127,
 'godaddy': 128,
 'google': 129,
 'canada': 130,
 'hsbc': 131,
 'haciserif': 132,
 'havahart': 133,
 'heroeslounge': 134,
 'historical': 135,
 'hutington': 136,
 'ibc': 137,
 'icicibank': 138,
 'ics': 139,
 'ing': 140,
 'irs': 141,
 'iconmeals': 142,
 'iemss': 143,
 'inmoment': 144,
 'instagram': 145,
 'itau': 146,
 'joomla': 147,
 'juno': 148,
 'justice': 149,
 'key': 150,
 'kitt': 151,
 'kiwibank': 152,
 'lbb': 153,
 'laracast': 154,
 'layerlemonade': 155,
 'learnnext': 156,
 'linksys': 157,
 'linkedin': 158,
 'linuxmint': 159,
 'listia': 160,
 'littlerockstore': 161,
 'livejournal': 162,
 'lloydsbank': 163,
 'loudtronix': 164,
 'lovebug': 165,
 'luno': 166,
 'mtb': 167,
 'mbna': 168,
 'mrh': 169,
 'mweb': 170,
 'madeinchina': 171,
 'maersk': 172,
 'manualslib': 173,
 'marketingprofs': 174,
 'marquette': 175,
 'mastercard': 176,
 'match': 177,
 'mcdonalds': 178,
 'mchemist': 179,
 'mephisto': 180,
 'meridian': 181,
 'metalsupply': 182,
 'microsoft': 183,
 'midwestcrowkits': 184,
 'minosa': 185,
 'mobile': 186,
 'monmount': 187,
 'muzbazar': 188,
 'myetherwallet': 189,
 'nab': 190,
 'nbtbank': 191,
 'namecheap': 192,
 'natWest': 193,
 'nbc': 194,
 'nationwide': 195,
 'naver': 196,
 'navyfederal': 197,
 'nedbank': 198,
 'netease': 199,
 'neteller': 200,
 'netflix': 201,
 'new25now': 202,
 'nextpit': 203,
 'nosice-stresni': 204,
 'office365': 205,
 'offshore-energy': 206,
 'onlinepianist': 207,
 'ooredoo': 208,
 'opensuse': 209,
 'openclipart': 210,
 'optica': 211,
 'optus': 212,
 'orange': 213,
 'ourtime': 214,
 'outlook': 215,
 'pgw': 216,
 'pof': 217,
 'pariyatti': 218,
 'partnerize': 219,
 'partnersinbuilding': 220,
 'paypal': 221,
 'payu': 222,
 'payoneer': 223,
 'psu': 224,
 'pharmacy295': 225,
 'pinnaclebank': 226,
 'Pioneerpet': 227,
 'playmeo': 228,
 'postfinance': 229,
 'powr': 230,
 'rbcroyalbank': 231,
 'rackspace': 232,
 'regielive': 233,
 'kpn': 234,
 'runescape': 235,
 'sf': 236,
 'sfr': 237,
 'smbulk': 238,
 'snsbank': 239,
 'sakura': 240,
 'santander': 241,
 'santarms': 242,
 'scotiabank': 243,
 'lojasebocultural': 244,
 'seobook': 245,
 'sharefile': 246,
 'showplaceicon': 247,
 'simplii': 248,
 'skirmshop': 249,
 'sky': 250,
 'sg': 251,
 'solarwinds': 252,
 'songmeanings': 253,
 'sonlight': 254,
 'soul-flower': 255,
 'spark': 256,
 'sparknotes': 257,
 'sparkasse': 258,
 'spectrum': 259,
 'spoj': 260,
 'spotify': 261,
 'square': 262,
 'sc': 263,
 'starmicronics': 264,
 'stargatemidnight': 265,
 'steam': 266,
 'stripe': 267,
 'studentrate': 268,
 'summacash': 269,
 'suntrust': 270,
 'suncorp': 271,
 'superteacherworksheets': 272,
 'post': 273,
 'swisscom': 274,
 'td': 275,
 'tpgtelecom': 276,
 'tsb': 277,
 'talktalk': 278,
 'techviral': 279,
 'telbru': 280,
 'telstra': 281,
 'telus': 282,
 'thejidsawpuzzles': 283,
 'tiberino': 284,
 'tmall': 285,
 'topwristband': 286,
 'torrington': 287,
 'toucharcade': 288,
 'tradeKey': 289,
 'tradeMe': 290,
 'tcbk': 291,
 'truspilot': 292,
 'tyrantcnc': 293,
 'usank': 294,
 'ubs': 295,
 'uph': 296,
 'usaa': 297,
 'uber': 298,
 'unicredit': 299,
 'uol': 300,
 'urssaf': 301,
 'vttl': 302,
 'vanguard': 303,
 'veja': 304,
 'verizon': 305,
 'visa': 306,
 'vitalitymedical': 307,
 'vodafone': 308,
 'vprint': 309,
 'wetransfer': 310,
 'webreus': 311,
 'webgo': 312,
 'webmail': 313,
 'wellsfargo': 314,
 'westpac': 315,
 'whatsapp': 316,
 'wisegeek': 317,
 'wordpress': 318,
 'xfinity': 319,
 'xtrixtv': 320,
 'ylive': 321,
 'yahoo': 322,
 'yellohvillage': 323,
 'yolikers': 324,
 'zoopla': 325,
 'bitsandcream': 326,
 'ebay': 327,
 'elements': 328,
 'iinet': 329,
 'mxtoolbox': 330,
 'rathena': 331,
 'uzayspor': 332
}


st.markdown(
    """
    <style>
    /* Thay đổi màu văn bản và kích thước của text_input */
    input[type="text"] {
        font-size: 20px; /* Kích thước font */
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <style>
    /* Thay đổi màu nền và màu văn bản của button */
    .stButton>button {
        background-color: MediumSeaGreen; /* Màu nền */
        opacity: 2;
        color: white; /* Màu văn bản */
        font-size: 20px; /* Kích thước font */
        width: 70%;
    }
    </style>
    """,
    unsafe_allow_html=True
)
st.markdown(
    """
    <style>
    .centered-text {
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <style>
    /* Căn giữa tiêu đề */
    .centered-title {
        text-align: center;
        color: MediumSeaGreen;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("<h1 class='centered-title'>Website Phishing And Security Checker</h1>", unsafe_allow_html=True)
st.write("<div class='centered-text'>Enter a URL </div>", unsafe_allow_html=True)

global url
source_url = st.text_input("").strip()
col1, col2, col3 = st.columns(3)

with col2:
    st.write("")
    st.write("")
    button = st.button("Scan Website")

@st.cache_resource
def Option():
    options = Options()
    options.add_argument("--window-size=1400,700")
    options.add_argument("--headless")
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument("--disable-gpu")
    options.add_argument("--private")
    options.set_preference("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0")
    options.set_preference("dom.webdriver.enabled", False)
    options.set_preference('useAutomationExtension', False)  
    options.set_preference("privacy.trackingprotection.enabled", False) 
    
    return webdriver.Firefox(options=options)
driver = Option()
driver.set_page_load_timeout(10)


@st.cache_resource
def Model_Dynamic():
    model_dynamic = YOLO("streamlit/YOLOv10.pt") 
    return (model_dynamic)
model_dynamic = Model_Dynamic()

@st.cache_resource
def Model_Static():
    model_static = torch.load("streamlit/transformer.pth")
    return model_static
model_static = Model_Static()

if button:
    url=""
    if source_url=="" :
        st.warning('Please enter a valid website URL.', icon="⚠️")
    else:    
        
        driver.set_page_load_timeout(10)
        try:  
            if source_url.startswith("http"):
                driver.get(source_url)
                url=driver.current_url
                page = driver.page_source
                state = True
            else:
                source_url = 'https' + '://' + source_url
                driver.get(source_url)
                url=driver.current_url
                page = driver.page_source
                state = True
        except:
                
                state = False     
        static()
        dynamic()
            
    if state==False:
        st.markdown(
                    """
                    <style>
                    .centered-title {
                        text-align: center;
                        color: Orange;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
        st.markdown(
                    """
                    <style>
                    .centered-Error {
                        text-align: center;
                        color: Orange;
                        font-size: 50px;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
        st.warning('Invalid URL', icon="⚠️")
        st.markdown("<div class='centered-Error'>Error</div>", unsafe_allow_html=True)

    elif sta < 0.38:
        st.markdown(
            """
            <style>
            .centered-title {
                text-align: center;
                color: MediumSeaGreen;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.markdown(
            """
            <style>
            .centered-Legitimate {
                text-align: center;
                color: MediumSeaGreen;
                font-size: 50px;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.success('Site is not Blacklisted', icon="✅")
        st.markdown("<div class='centered-Legitimate'>Legitimate</div>", unsafe_allow_html=True)
        
    elif sta > 0.75:
        st.markdown(
            """
            <style>
            .centered-title {
                text-align: center;
                color: Red;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.markdown(
            """
            <style>
            .centered-Phishing {
                text-align: center;
                color: Red;
                font-size: 50px;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.error('Site is Blacklisted', icon="🚨")
        st.markdown("<div class='centered-Phishing'>Phishing</div>", unsafe_allow_html=True)
    elif dy == "legitimate":
            st.markdown(
                    """
                    <style>
                    .centered-title {
                        text-align: center;
                        color: MediumSeaGreen;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown(
                    """
                    <style>
                    .centered-Legitimate {
                        text-align: center;
                        color: MediumSeaGreen;
                        font-size: 50px;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
            st.success('Site is not Blacklisted', icon="✅")
            st.markdown("<div class='centered-Legitimate'>Legitimate</div>", unsafe_allow_html=True)
    elif dy == "phishing":
        st.markdown(
            """
            <style>
            .centered-title {
                text-align: center;
                color: Red;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.markdown(
            """
            <style>
            .centered-Phishing {
                text-align: center;
                color: Red;
                font-size: 50px;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.error('Site is Blacklisted', icon="🚨")
        st.markdown("<div class='centered-Phishing'>Phishing</div>", unsafe_allow_html=True)
            

    else:
        if sta < 0.5:
            st.markdown(
                """
                <style>
                .centered-title {
                    text-align: center;
                    color: Red;
                }
                </style>
                """,
                unsafe_allow_html=True
            )
            st.markdown(
                """
                <style>
                .centered-Phishing {
                    text-align: center;
                    color: Red;
                    font-size: 50px;
                }
                </style>
                """,
                unsafe_allow_html=True
            )
            st.error('Site is Blacklisted', icon="🚨")
            st.markdown("<div class='centered-Phishing'>Phishing</div>", unsafe_allow_html=True)
        else:
            st.markdown(
                    """
                    <style>
                    .centered-title {
                        text-align: center;
                        color: MediumSeaGreen;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown(
                    """
                    <style>
                    .centered-Legitimate {
                        text-align: center;
                        color: MediumSeaGreen;
                        font-size: 50px;
                    }
                    </style>
                    """,
                    unsafe_allow_html=True
                )
            st.success('Site is not Blacklisted', icon="✅")
            st.markdown("<div class='centered-Legitimate'>Legitimate</div>", unsafe_allow_html=True)
    try:
        # Hiển thị hình ảnh ở giữa
        st.image(shot, use_container_width  = "always",caption = url)
    except:
        pass
