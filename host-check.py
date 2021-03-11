# %%
import numpy as np
import pandas as pd

#%%
alexa = pd.read_csv('train/top-1m-alexa-210307.csv', names=['rank','hostname'], index_col=0)
print(alexa.head())

# %%
cisco = pd.read_csv('train/top-1m-cisco-210307.csv', names=['rank','hostname'], index_col=0)
print(cisco.head())

# %%
non_malicious_limit = 100000
alexa = alexa[:non_malicious_limit]
cisco = cisco[:non_malicious_limit]
print(alexa.size, cisco.size)

# %%
# find count of hostnames matching across list
print (alexa[alexa['hostname'].isin(cisco['hostname'])].size)

# %%
malware_pd = pd.read_csv('train\hosts-210311.txt', delim_whitespace=True, usecols=[1], names=['hostname'], skiprows=39, skipfooter=11)
print(malware_pd.size)
print(malware_pd.head())
#print(malware_pd.tail())

# %%
# find count of hostnames matching across list
print (malware_pd[malware_pd['hostname'].isin(alexa['hostname'])].size)
print (malware_pd[malware_pd['hostname'].isin(cisco['hostname'])].size)

# %%
