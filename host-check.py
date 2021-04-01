# %%
import math
import multiprocessing as mp
import numpy as np
import pandas as pd
import string
from sklearn.model_selection import train_test_split

# %%
# config
pd.set_option('display.max_columns', 100)
pd.set_option('display.max_rows', 20)

#%%
alexa = pd.read_csv('train/top-1m-alexa-210307.csv', usecols=[1], names=['hostname'])
print(alexa.head())

# %%
# cisco = pd.read_csv('train/top-1m-cisco-210307.csv', usecols=[1], names=['hostname'])
# print(cisco.head())

# find count of hostnames matching across list
#print (alexa[alexa['hostname'].isin(cisco['hostname'])].size)

# %%
malware_pd = pd.read_csv('train\hosts-210311.txt', delim_whitespace=True, usecols=[1], names=['hostname'], skiprows=39, skipfooter=11)
# print(malware_pd.size)
# print(malware_pd.head())
#print(malware_pd.tail())

# %%
# find count of hostnames matching across list
print (malware_pd[malware_pd['hostname'].isin(alexa['hostname'])].size)
#print (malware_pd[malware_pd['hostname'].isin(cisco['hostname'])].size)

# %%
print (malware_pd.shape)
malware_pd = malware_pd[malware_pd['hostname'].str.count('.') > 0]
print (malware_pd.shape)

# print (alexa.size)
# alexa = alexa[alexa['hostname'].str.count('.') > 0]
# print (alexa.size)

# %%
malware_pd['hostname'] = malware_pd['hostname'].str.lower()
alexa['hostname'] = alexa['hostname'].str.lower()

# %%
#split hostnames by period into a list
#remove/extract "stop" words (e.g. www?, tld)

malware_pd['hostname'] = malware_pd['hostname'].str.lstrip('www.')
alexa['hostname'] = alexa['hostname'].str.lstrip('www.')
# cisco['hostname-stripped'] = cisco['hostname'].str.lstrip('www.')

# print (malware_pd[malware_pd['hostname-stripped'].isin(alexa['hostname-stripped'])].size)
# print (malware_pd[malware_pd['hostname-stripped'].isin(cisco['hostname-stripped'])].size)
# print (alexa[alexa['hostname-stripped'].isin(cisco['hostname-stripped'])].size)
# print (cisco[cisco['hostname-stripped'].isin(alexa['hostname-stripped'])].size)
# print (alexa[alexa['hostname'].isin(cisco['hostname'])].size)
# print (cisco[cisco['hostname'].isin(alexa['hostname'])].size)

#%%
tld_series = pd.read_csv('resources/tld_list.txt', names=['TLD'], squeeze=True, skip_blank_lines=True, comment='/')
print(tld_series.shape)

# %%
# Source for tld_list.txt: https://publicsuffix.org/list/
def extract_tld(hostname):
    tld_list = [tld for tld in tld_series if hostname.endswith(tld)]
    if tld_list : return sorted(tld_list, key=len, reverse=True)[0]
    else : return hostname.split('.')[-1]

# demo
# print(extract_tld('google.co.in'))

# %%
# perform entropy calculation
def shannon_entropy(hostname_without_tld):
    hostname_without_period = hostname_without_tld.replace('.', '')
    # print(hostname_without_period)
    character_probabilities = [float(hostname_without_period.count(char)) / len(hostname_without_period) for char in dict.fromkeys(list(hostname_without_period))]
    entropy = sum([(probability * math.log(probability) / math.log(2.0)) for probability in character_probabilities])
    return entropy

# %%
# mapper inspired (and optimized) by: https://github.com/lucasayres/url-feature-extractor
vowels = ['a', 'e', 'i', 'o', 'u']
# counter = 0

def hostname_mapper(hostname):
    # global counter
    # if not hostname:
    #     print(counter)
    period_count = hostname.count('.')
    hypen_count = hostname.count('-')
    underscore_count = hostname.count('_')
    digit_count = sum(char.isdigit() for char in hostname)
    alphabet_count = sum(char.isalpha() for char in hostname)
    hostname_length = len(hostname)
    tld = extract_tld(hostname)
    hostname_without_tld = hostname.removesuffix('.'+tld)
    vowel_count = len([letter for letter in hostname if letter in vowels])
    server_exists = "server" in hostname.lower()
    client_exists = "client" in hostname.lower()
    hostname_split = hostname_without_tld.split('.')
    hostname_shannon = shannon_entropy(hostname_without_tld)
    # counter += 1
    return period_count,hypen_count,underscore_count,digit_count,alphabet_count,hostname_length,tld,hostname_without_tld,vowel_count,server_exists,client_exists,hostname_split,hostname_shannon

# %%
# print(hostname_mapper('maps.google.com'))

# %%
# df['a'], df['b], .. df['z'] = zip(df['x].map(url_mapper))
print(alexa.size)
alexa = alexa[~alexa['hostname'].isin(malware_pd['hostname'])]
print(alexa.shape)

non_malicious_limit = 100000
alexa = alexa[:non_malicious_limit]
print(alexa.shape)

# %%
alexa['malicious'] = False
malware_pd['malicious'] = True

df = alexa.append(malware_pd)
df = df.reset_index(drop=True)
print(df.shape)

# %%
# with mp.Pool(mp.cpu_count()) as pool:
#     df['period_count'],df['hypen_count'],df['underscore_count'],df['digit_count'],df['alphabet_count'],df['hostname_length'],df['tld'],df['hostname_without_tld'],df['vowel_count'],df['server_exists'],df['client_exists'],df['hostname_split'],df['hostname_shannon'] = zip(*pool.map(hostname_mapper, df['hostname']))
# print(df.head())

# %%
alphabet_list = [char for char in string.ascii_lowercase]
digit_list = [digits for digits in string.digits]
character_list = alphabet_list + character_list

# df['hostname_length'] = df['hostname'].apply(lambda x: len(x))
# df['tld'] = df['hostname'].apply(extract_tld)
# df['hostname_without_tld'] = df.apply(lambda x: x.hostname.removesuffix('.'+x.tld), axis=1)
# df['vowel_count'] = df['hostname_without_tld'].apply(lambda x: len([letter for letter in x if letter in vowels]))
# df['server_exists'] = df['hostname_without_tld'].apply(lambda x: "server" in x.lower())
# df['client_exists'] = df['hostname_without_tld'].apply(lambda x: "client" in x.lower())
# df['hostname_split'] = df['hostname_without_tld'].apply(lambda x: x.split('.'))
# df['hostname_shannon'] = df['hostname_without_tld'].apply(shannon_entropy)

# for character in character_list:
#     print('count-'+character)
#     df['count-'+character] = df['hostname_without_tld'].str.count(character)

# df['count-period'] = df['hostname_without_tld'].str.count('.')
# df['count-hyphen'] = df['hostname_without_tld'].str.count('-')
# df['count-underscore'] = df['hostname_without_tld'].str.count('_')
# df['digit_count'] = df[['count-'+digit for digit in digit_list]].sum(axis=1)
# df['alphabet_count'] = df[['count-'+alphabet for alphabet in alphabet_list]].sum(axis=1)

# print(df.head())

# %%
# df.to_pickle('resources/df_mapped.pickle')
df = pd.read_pickle('resources/df_mapped.pickle')
print(df.head())

# %%
# cisco = cisco[:non_malicious_limit]
# print(alexa.size, cisco.size)

# %%
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)
X = df.drop(['malicious'], axis=1)
y = df['malicious']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print (X_train.shape, X_test.shape)

# %%
print(X_train.isnull().mean().sort_values(ascending=False))

# %%
print(X_train.mean().sort_values(ascending=False))

# %%
print(X_train['tld'].value_counts)

# %%
print(X_train.describe())

# %%
# count-period has a wide range
X_train.boxplot(column=['count-period'])

# %%
def calculate_iqr(column):
    sorted(column)
    Q1,Q3 = column.quantile([0.25,0.75])
    IQR = Q3-Q1
    floor = Q1-(1.5*IQR)
    ceiling = Q3+(1.5*IQR)
    return floor,ceiling

# %%
# hostname_length vowel_count count-period count-hyphen count-underscore digit_count alphabet_count
scale_list = ['hostname_length','vowel_count','count-period','alphabet_count']
for column in scale_list:
    print(column)
    floor,ceiling=calculate_iqr(X_train[column])
    print(floor,ceiling)
    X_train[column]=np.where(X_train.loc[column]>ceiling,ceiling,X_train[column])
    X_train[column]=np.where(X_train[column]<floor,floor,X_train[column])

print(X_train[scale_list].describe())

# %%
