# %%
import math
import multiprocessing as mp
import numpy as np
import pandas as pd
import pickle
import string

from sklearn.dummy import DummyClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import MinMaxScaler

# %%
# config
pd.set_option('display.max_columns', 50)
pd.set_option('display.max_rows', 50)

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

# def hostname_mapper(hostname):
#     # global counter
#     # if not hostname:
#     #     print(counter)
#     period_count = hostname.count('.')
#     hypen_count = hostname.count('-')
#     underscore_count = hostname.count('_')
#     digit_count = sum(char.isdigit() for char in hostname)
#     alphabet_count = sum(char.isalpha() for char in hostname)
#     hostname_length = len(hostname)
#     tld = extract_tld(hostname)
#     hostname_without_tld = hostname.removesuffix('.'+tld)
#     vowel_count = len([letter for letter in hostname if letter in vowels])
#     server_exists = "server" in hostname.lower()
#     client_exists = "client" in hostname.lower()
#     hostname_split = hostname_without_tld.split('.')
#     hostname_shannon = shannon_entropy(hostname_without_tld)
#     # counter += 1
#     return period_count,hypen_count,underscore_count,digit_count,alphabet_count,hostname_length,tld,hostname_without_tld,vowel_count,server_exists,client_exists,hostname_split,hostname_shannon

# %%
# print(hostname_mapper('maps.google.com'))

# %%
# limit entries to (top) 100k sites
print(alexa.size)
alexa = alexa[~alexa['hostname'].isin(malware_pd['hostname'])]
print(alexa.shape)

non_malicious_limit = 100000
alexa = alexa[:non_malicious_limit]
print(alexa.shape)

# %%
# label the data
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
character_list = alphabet_list + digit_list

df['hostname_length'] = df['hostname'].apply(lambda x: len(x))
df['tld'] = df['hostname'].apply(extract_tld)
df['hostname_without_tld'] = df.apply(lambda x: x.hostname.removesuffix('.'+x.tld), axis=1)
df['vowel_count'] = df['hostname_without_tld'].apply(lambda x: len([letter for letter in x if letter in vowels]))
df['server_exists'] = df['hostname_without_tld'].apply(lambda x: "server" in x.lower())
df['client_exists'] = df['hostname_without_tld'].apply(lambda x: "client" in x.lower())
df['hostname_split'] = df['hostname_without_tld'].apply(lambda x: x.split('.'))
df['hostname_shannon'] = df['hostname_without_tld'].apply(shannon_entropy)

for character in character_list:
    print('count-'+character)
    df['count-'+character] = df['hostname_without_tld'].str.count(character)

df['count-period'] = df['hostname_without_tld'].str.count('.')
df['count-hyphen'] = df['hostname_without_tld'].str.count('-')
df['count-underscore'] = df['hostname_without_tld'].str.count('_')
df['digit_count'] = df[['count-'+digit for digit in digit_list]].sum(axis=1)
df['alphabet_count'] = df[['count-'+alphabet for alphabet in alphabet_list]].sum(axis=1)

# print(df.head())

# %%
df.to_pickle('resources/df_mapped.pickle')
df = pd.read_pickle('resources/df_mapped.pickle')
print(df.head())

# %%
# cisco = cisco[:non_malicious_limit]
# print(alexa.size, cisco.size)

# %%
X = df.drop(['malicious'], axis=1)
y = df['malicious']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print (X_train.shape, X_test.shape)

# %%
print(X_train.isnull().mean().sort_values(ascending=False))

# %%
print(X_train['tld'].value_counts)

# %%
print(X_train.describe())

# %%
# count-period has a wide range
X_train.boxplot(column=['count-period'], grid=False)

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
X_train.boxplot(column=scale_list, grid=False, rot=45)

# %%
for column in scale_list:
    print(column)
    floor,ceiling=calculate_iqr(X_train[column])
    print(floor,ceiling)
    X_train[column]=np.where(X_train[column]>ceiling,ceiling,X_train[column])
    X_train[column]=np.where(X_train[column]<floor,floor,X_train[column])
    X_test[column]=np.where(X_test[column]>ceiling,ceiling,X_test[column])
    X_test[column]=np.where(X_test[column]<floor,floor,X_test[column])

print(X_train[scale_list].describe())
X_train.boxplot(column=scale_list, grid=False, rot=45, fontsize=4)

# %%
numeric_columns = X_train.columns[X_train.dtypes.apply(lambda c: np.issubdtype(c, np.number))]
scaler = MinMaxScaler()
scaler.fit(X_train[numeric_columns])
X_train[numeric_columns] = scaler.transform(X_train[numeric_columns])
X_test[numeric_columns] = scaler.transform(X_test[numeric_columns])


X_train[numeric_columns].boxplot(grid=False, rot=45, fontsize=4)

print(X_train.describe())

print(X_train.corr())

print(X_train.corrwith(y_train).sort_values(key=abs, ascending=False))

# %%
# remove count-period, alphabet_count as they have very high correlation with other features
# remove count-b, count-h, count-u, client_exists, count-underscore, count-q as very less correlation with target
high_feature_correlation_list = ['count-period', 'alphabet_count']
low_target_correlation_list = ['count-b', 'count-h', 'count-u', 'client_exists', 'count-underscore', 'count-q']
feature_drop_list = high_feature_correlation_list + low_target_correlation_list

X_train = X_train.drop(feature_drop_list, axis=1)
X_test = X_test.drop(feature_drop_list, axis=1)

print(X_train.shape)

# %%
X_train.boxplot(grid=False, rot=45, fontsize=4)

# %%
# Classification suite - early evaluation
#   Dummy classifier for baseline (very fast)
#   Logistic Regression  (slow)
#   Naïve Bayes (fast)
#   K-Nearest Neighbours (slow)
#   Random Forest (fast)
#   Stochastic Gradient Descent (fast)
dummy = DummyClassifier(random_state=42)
logistic = LogisticRegression(n_jobs=-1, random_state=42)
nbc = MultinomialNB()
knn = KNeighborsClassifier(n_jobs=-1)
random_forest = RandomForestClassifier(n_jobs=-1)
sgd = SGDClassifier(random_state=42, n_jobs=-1)

train_test_features = X_train.columns[X_train.dtypes.apply(lambda c: np.issubdtype(c, np.number))]

classifier_suite = [dummy, logistic, nbc, knn, random_forest, sgd]

for model in classifier_suite:
    model.fit(X_train[train_test_features], y_train)
    print(model.__class__.__name__ + " score: " + str(model.score(X_test[train_test_features], y_test)))

# Choosing RandomForestClassifier and SGDClassifier for model tuning and further testing

# %%
# Evaluation metrics
#   Classification accuracy
#   Confusion matrix => Precision and recall; Sensitivity and Specificity
#   F1 score
#   ROC curve and AUC

# %%
# RandomForestClassifier Tuning
# random_forest_grid = {'n_estimators': [10, 25, 50, 100, 250], 'max_depth': [5, 8, 15, 30], 'min_samples_leaf': [5, 10, 50, 100]}
# random_forest_grid = {'n_estimators': [100, 250, 500], 'max_depth': [25, 30, 45, 100], 'min_samples_leaf': [1, 3, 5, 7]}
# random_forest_grid = {'n_estimators': [400, 500, 600], 'max_depth': [45, 60], 'min_samples_leaf': [3, 5, 6]}
# random_forest_grid = {'n_estimators': [600, 1000], 'max_depth': [60, 150], 'min_samples_leaf': [1, 2]}
random_forest_grid = {'n_estimators': [100], 'max_depth': [45], 'min_samples_leaf': [1]}
random_forest_gscv = GridSearchCV(RandomForestClassifier(n_jobs=-1, random_state=42), random_forest_grid, n_jobs=-1, verbose=3, cv=3)
random_forest_gscv.fit(X_train[train_test_features], y_train)

print(random_forest_gscv.best_params_)
print('Training accuracy = ' + str(random_forest_gscv.score(X_train[train_test_features], y_train)))

random_forest_best_predictions = random_forest_gscv.predict(X_test[train_test_features])
print(classification_report(y_test, random_forest_best_predictions))

# to use 'max_depth': 45, 'min_samples_leaf': 1, 'n_estimators': 100

# %%
# SGDClassifier Tuning
# sgd_grid = {'alpha': [1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 0.25, 0.50, 0.75, 1.0], 'penalty': ['l1', 'l2']}
sgd_grid = {'alpha': [1e-5*i for i in range(1,10)], 'penalty': ['l1', 'l2']}
sgd_gscv = GridSearchCV(SGDClassifier(n_jobs=-1, random_state=42), sgd_grid, n_jobs=-1, verbose=3)
sgd_gscv.fit(X_train[train_test_features], y_train)

print(sgd_gscv.best_params_)
print('Training accuracy = ' + str(sgd_gscv.score(X_train[train_test_features], y_train)))

sgd_best_predictions = sgd_gscv.predict(X_test[train_test_features])
print(classification_report(y_test, sgd_best_predictions))

# using 'alpha': 0.0001, 'penalty': 'l2'

# %%
random_forest = RandomForestClassifier(n_jobs=-1, random_state=42, max_depth=45, min_samples_leaf=1, n_estimators=100)
random_forest.fit(X_train[train_test_features], y_train)
random_forest_predictions = random_forest.predict(X_test[train_test_features])
print(classification_report(y_test, random_forest_predictions))

weights = list(random_forest.feature_importances_)
random_forest_weight = {train_test_features[i]: weights[i] for i in range(len(weights))}
# for feature in sorted(random_forest_weight, reverse=True, key=lambda dict_key: abs(random_forest_weight[dict_key])):
#    print('Feature: %s, Score: %.5f' % (feature,random_forest_weight[feature]))

df_weight = pd.Series(random_forest_weight)
print(df_weight.sort_values(ascending=False).plot(kind='barh', fontsize=4))

# %%
sgd = SGDClassifier(n_jobs=-1, random_state=42, alpha=1e-4, penalty='l2')
sgd.fit(X_train[train_test_features], y_train)
sgd_predictions = sgd.predict(X_test[train_test_features])
print(classification_report(y_test, sgd_predictions))

weights = list(sgd.coef_[0])
sgd_weight = {train_test_features[i]: weights[i] for i in range(len(weights))}
for feature in sorted(sgd_weight, reverse=True, key=lambda dict_key: abs(sgd_weight[dict_key])):
    print('Feature: %s, Score: %.5f' % (feature,sgd_weight[feature]))

# %%
# calibrate sgd for use in votingclassifier
sgd_calibrate = CalibratedClassifierCV(sgd, n_jobs=-1)
sgd_calibrated = sgd_calibrate.fit(X_train[train_test_features], y_train)

# %%
# VotingClassifier
voting_classifier = VotingClassifier(estimators=[('random_forest', random_forest), ('sgd', sgd_calibrated)], voting='soft', n_jobs=-1, weights=[0.84, 0.73])
voting_classifier.fit(X_train[train_test_features], y_train)
voting_predictions = voting_classifier.predict(X_test[train_test_features])
print(classification_report(y_test, voting_predictions))
print('% non-matching between voting and SGD: ' + str((voting_predictions != sgd_predictions).mean()*100))
print('% non-matching between voting and random forest: ' + str((voting_predictions != random_forest_predictions).mean()*100))
print('% non-matching between random forest and SGD: ' + str((random_forest_predictions != sgd_predictions).mean()*100))

# %%
# further optimization for random_forest
random_forest_features = [feature for feature in random_forest_weight if random_forest_weight[feature] >= 0.01]
print(random_forest_features)

# %%
# Redoing tuning in-depth using fewer features
random_forest_grid = {'n_estimators': [100],
                        'min_samples_leaf': [1, 0.005, 0.05, 0.10],
                        'class_weight': [None, 'balanced'],
                        'max_features': ['auto', 'sqrt', 'log2'],
                        'max_depth': [8, 45],
                        'min_samples_split': [0.005, 0.05, 0.10],
                        'criterion' :['gini', 'entropy']
                        }
random_forest_gscv = GridSearchCV(RandomForestClassifier(n_jobs=-1, random_state=42), random_forest_grid, n_jobs=-1, verbose=3, cv=2)
random_forest_gscv.fit(X_train[random_forest_features], y_train)

print(random_forest_gscv.best_params_)
print('Training accuracy = ' + str(random_forest_gscv.score(X_train[random_forest_features], y_train)))

random_forest_best_predictions = random_forest_gscv.predict(X_test[random_forest_features])
print(classification_report(y_test, random_forest_best_predictions))

# result 'class_weight': None, 'criterion': 'entropy', 'max_depth': 45, 'max_features': 'auto', 'min_samples_leaf': 1, 'min_samples_split': 0.005, 'n_estimators': 100
# worse performance than found earlier!

# %%
# random_forest = RandomForestClassifier(n_jobs=-1,
#                                         random_state=42,
#                                         max_depth=45,
#                                         min_samples_leaf=1,
#                                         n_estimators=100,
#                                         class_weight=None,
#                                         criterion='entropy',
#                                         max_features='auto',
#                                         min_samples_split=0.005
#                                         )
random_forest = RandomForestClassifier(n_jobs=-1, random_state=42, max_depth=45, min_samples_leaf=1, n_estimators=100)
random_forest.fit(X_train[random_forest_features], y_train)
random_forest_predictions = random_forest.predict(X_test[random_forest_features])
print(classification_report(y_test, random_forest_predictions))

weights = list(random_forest.feature_importances_)
random_forest_weight = {train_test_features[i]: weights[i] for i in range(len(weights))}

df_weight = pd.Series(random_forest_weight)
print(df_weight.sort_values(ascending=False).plot(kind='barh', fontsize=4))

# losing features was not the problem. what we have before is as good as it gets
# stick with the previously tuned model and reduce the features

# %%
# what if only used the top three features
top_4_features = sorted(random_forest_weight, reverse=True, key=lambda dict_key: abs(random_forest_weight[dict_key]))[:3]
random_forest = RandomForestClassifier(n_jobs=-1, random_state=42, max_depth=45, min_samples_leaf=1, n_estimators=100)
random_forest.fit(X_train[top_4_features], y_train)
random_forest_predictions = random_forest.predict(X_test[top_4_features])
print(classification_report(y_test, random_forest_predictions))

weights = list(random_forest.feature_importances_)
df_weight = pd.Series({train_test_features[i]: weights[i] for i in range(len(weights))})
print(df_weight.sort_values(ascending=False).plot(kind='barh', fontsize=4))

# %%
# random_forest_features.append('malicious')
df[random_forest_features].to_pickle('resources/df_final.pickle')

# %%
with open('resources/random_forest_final.pickle', 'wb') as f:
    pickle.dump(random_forest, f)