#!/usr/bin/env python

import argparse
import validators
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
import yaml

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer V 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help='Path to Configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'password_inputs': True}

if(args.config):
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    config_from_file = yaml.load(config_file)
    if(config_from_file):
        config = {**config, **config_from_file}
               

report = ''

url = args.url

if(validators.url(url)):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms            = parsed_html.find_all('form')
    comments         = parsed_html.find_all(string=lambda text:isinstance(text, Comment))
    password_inputs  = parsed_html.find_all('imput', {'name': 'password'})

    if(config['forms']):
        for form in forms:
            if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
                report += 'Form Issue: Insecure form action' + form.get('action') + 'found in document\n'
        
            

    

    if(config['comments']):
        for comment in comments:
            if(comment.find('key: ') > -1):
                report += 'Comment Issue: Key is found in the HTML comments, please remove\n'
        
            

    if(config['password_inputs']):
        for password_input in password_inputs:
            if(password_input.get('type') != 'password'):
                report += 'Input issue: plaintext password input found. please change to type input\n'
        
            
      
else:
    print("Invalid URL. Please include full URL")


if (report == ''):
    report += 'Nice job! Your HTML document is secure!\n'
else:
    header = 'Vulnerability report is as follows:\n'
    header = '===================================\n\n'

    report = header + report

print(report)
    
if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print('report saved to: ' + args.output)
