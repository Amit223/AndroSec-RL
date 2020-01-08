from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn . metrics import classification_report
from sklearn.svm import SVC
import numpy as np
import pandas as pd
import os
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from joblib import dump, load

#get api calls and permissions
def get_features(file):
    try:
        features=""
        a = APK (file)
        d = dvm . DalvikVMFormat ( a. get_dex () )
        z = d . get_strings ()
        #api
        API_calls = ["getDeviceId","getCellLocation","setFlags","addFlags","setDataAndType","putExtra","init","query",
        "insert","update","writeBytes","write","append","indexOf","substring","startService","getFilesDir","openFileOutput","getApplicationInfo",
        "getRunningServices","getMemoryInfo","restartPackage","getInstalledPackages","sendTextMessage","getSubscriberId","getLine1Number","getSimSerialNumber","getNetworkOperator",
        "loadClass","loadLibrary","exec","getNetworkInfo","getExtraInfo","getTypeName","isConnected","getState","setWifiEnabled",
        "getWifiState","setRequestMethod","getInputStream","getOutputStream","sendMessage","obtainMessage","myPid","killProcess",
        "readLines","available","delete","exists","mkdir","ListFiles","getBytes","valueOf","replaceAll","schedule","cancel","read",
        "close","getNextEntry","closeEntry","getInstance","doFinal","DESKeySpec","getDocumentElement","getElementByTagName","getAttribute"]
        for i in range(len(z)):
            for j in range(len(API_calls)):
                if API_calls[j] == z[i]:
                    features = features + API_calls[j] + " "
        #permissions
        permissions=a.get_permissions()
        for p in permissions:
            features=features+p+" "
        return features
    except:
        return ""


def writeFeaturesToCsv():
    X=[]
    Y=[]
    #bening:
    print("............................bening..............................")
    for file in os.listdir('Files/benign'):
        features=get_features('Files/benign/'+file)
        if features !="":
            X.append(features)
            Y.append(0)#not malware
        print("V")
    print("............................malware..............................")
    for file in os.listdir('Files/malware'):
        features = get_features('Files/malware/'+file)
        if features!="":
            X.append(features)
            Y.append(1)  #malware
        print("V")
    #get x to bag of words model:
    vectorizer = CountVectorizer(analyzer="word",preprocessor=None,max_features=5000)
    X_bag = vectorizer.fit_transform(X)
    #write to file:
    dump(vectorizer,"SVMFeatures.joblib")
    X_bag = X_bag.toarray()
    #split to train and test
    X_train, X_test, y_train, y_test= train_test_split(X_bag, Y, test_size=0.2, random_state=1)
    #write to csv
    #write train:
    df_train=pd.DataFrame(X_train)
    df_train.insert(0,column='isMalware',value=y_train)
    df_train.to_csv("TrainSVM.csv")
    #write test:
    df_train=pd.DataFrame(X_test)
    df_train.insert(0,column='isMalware',value=y_test)
    df_train.to_csv("TestSVM.csv")

def train(train_file):#csv format
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=",")
    y_train = data_train[:, 1][1:]
    X_train = data_train[:, 2:][1:]
    clf = SVC()
    clf.fit(X_train, y_train)
    #write to file:
    dump(clf, 'SVMClassifier.joblib')

def Model_Accuracy(test_file):
    clf = load('SVMClassifier.joblib')
    data_test = np.genfromtxt(open(test_file, "r"), delimiter=",")
    y_test = data_test[:, 1][1:]
    X_test = data_test[:, 2:][1:]
    #predict
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    scores = cross_val_score(clf, X_test, y_test, cv=3)  # todo: change when we get more files
    print("Accuracy:" + str(scores.mean()))


def main():
    writeFeaturesToCsv()
    train("TrainSVM.csv")
    Model_Accuracy("TestSVM.csv")

main()
