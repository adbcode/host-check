# %%
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

#%%
alexa = pd.read_csv('train/top-1m-alexa-210307.csv', usecols=[1], names=['hostname'])
print(alexa.head())

# %%
# cisco = pd.read_csv('train/top-1m-cisco-210307.csv', usecols=[1], names=['hostname'])
# print(cisco.head())

# %%
# find count of hostnames matching across list
#print (alexa[alexa['hostname'].isin(cisco['hostname'])].size)

# %%
malware_pd = pd.read_csv('train\hosts-210311.txt', delim_whitespace=True, usecols=[1], names=['hostname'], skiprows=39, skipfooter=11)
print(malware_pd.size)
print(malware_pd.head())
#print(malware_pd.tail())

# %%
# find count of hostnames matching across list
print (malware_pd[malware_pd['hostname'].isin(alexa['hostname'])].size)
#print (malware_pd[malware_pd['hostname'].isin(cisco['hostname'])].size)

# %%
#split hostnames by period into a list
#remove/extract "stop" words (e.g. www?, tld)

# malware_pd['hostname-stripped'] = malware_pd['hostname'].str.lstrip('www.')
# alexa['hostname-stripped'] = alexa['hostname'].str.lstrip('www.')
# cisco['hostname-stripped'] = cisco['hostname'].str.lstrip('www.')

# print (malware_pd[malware_pd['hostname-stripped'].isin(alexa['hostname-stripped'])].size)
# print (malware_pd[malware_pd['hostname-stripped'].isin(cisco['hostname-stripped'])].size)
# print (alexa[alexa['hostname-stripped'].isin(cisco['hostname-stripped'])].size)
# print (cisco[cisco['hostname-stripped'].isin(alexa['hostname-stripped'])].size)
# print (alexa[alexa['hostname'].isin(cisco['hostname'])].size)
# print (cisco[cisco['hostname'].isin(alexa['hostname'])].size)

#%%
tld_series = pd.read_csv('resources/tld_list.txt', names=['TLD'], squeeze=True, skip_blank_lines=True, comment='/')
print(tld_series.size)

# %%
# Source for tld_list.txt: https://publicsuffix.org/list/
def extract_tld(hostname):
    tld_list = [tld for tld in tld_series if hostname.endswith(tld)]
    if tld_list : return sorted(tld_list, key=len, reverse=True)[0]
    else : return hostname.split('.')[-1]

# demo
print(extract_tld('www.google.co.in'))

# %%
# mapper inspired (and optimized) by: https://github.com/lucasayres/url-feature-extractor
vowels = ['a', 'e', 'i', 'o', 'u']
counter = 0

def url_mapper(hostname):
    global counter
    if not hostname:
        print(counter)
    period_count = hostname.count('.')
    hypen_count = hostname.count('-')
    underscore_count = hostname.count('_')
    digit_count = sum(char.isdigit() for char in hostname)
    hostname_length = len(hostname)
    tld = extract_tld(hostname)
    hostname_without_tld = hostname.removesuffix('.'+tld)
    vowel_count = len([letter for letter in hostname if letter in vowels])
    server_exists = "server" in hostname.lower()
    client_exists = "client" in hostname.lower()
    hostname_split = hostname_without_tld.split('.')
    counter += 1
    return period_count,hypen_count,underscore_count,digit_count,hostname_length,tld,hostname_without_tld,vowel_count,server_exists,client_exists,hostname_split

# %%
print(url_mapper('www.google.com'))

# %%
print (malware_pd.size)
malware_pd = malware_pd[malware_pd['hostname'].str.count('.') > 0]
print (malware_pd.size)

# print (alexa.size)
# alexa = alexa[alexa['hostname'].str.count('.') > 0]
# print (alexa.size)

# %%
# df['a'], df['b], .. df['z'] = zip(df['x].map(url_mapper))
print(alexa.size)
alexa = alexa[~alexa['hostname'].isin(malware_pd['hostname'])]
print(alexa.size)

non_malicious_limit = 100000
alexa = alexa[:non_malicious_limit]
print(alexa.size)

# %%
alexa['malicious'] = False
malware_pd['malicious'] = True

df = alexa.append(malware_pd)
df = df.reset_index(drop=True)

print(df.size)
print(df.head())
print(df.tail())

# %%
df['period_count'],df['hypen_count'],df['underscore_count'],df['digit_count'],df['hostname_length'],df['tld'],df['hostname_without_tld'],df['vowel_count'],df['server_exists'],df['client_exists'],df['hostname_split'] = zip(*df['hostname'].map(url_mapper))
print(df.head())

# %%
# cisco = cisco[:non_malicious_limit]
# print(alexa.size, cisco.size)

# %%
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)


# %%
# TODO: shannon entropy for strings at character level pandas

# %%
# TODO: n-grams on hostname?