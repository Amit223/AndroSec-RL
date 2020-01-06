from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.ensemble import ExtraTreesClassifier
import xgboost as xgb
from sklearn.feature_selection import SelectFromModel
from sklearn . metrics import classification_report
import numpy as np
import os
from sklearn.feature_extraction.text import CountVectorizer
import pandas as pd



def get_features(file):
    features=""
    a = APK (file)
    d = dvm . DalvikVMFormat ( a. get_dex () )
    z = d . get_strings ()
    #intents
    intentList=[]
    for i in range ( len( z )):
        if z [i ]. startswith ( "android.intent.action."):
            intents = z[i ]
            features=features+ intents+" "
    #cmd
    suspicious_cmds = ["su", "mount", "reboot", "mkdir"]
    cmdList=[]
    for i in range(len(z)):
        for j in range(len(suspicious_cmds)):
            if suspicious_cmds[j] == z[i]:
                features=features+suspicious_cmds[j]+" "
    #api
    API_calls = ["getDeviceId","getCellLocation","setFlags","addFlags","setDataAndType","putExtra","init","query",
    "insert","update","writeBytes","write","append","indexOf","substring","startService","getFilesDir","openFileOutput","getApplicationInfo",
    "getRunningServices","getMemoryInfo","restartPackage","getInstalledPackages","sendTextMessage","getSubscriberId","getLine1Number","getSimSerialNumber","getNetworkOperator",
    "loadClass","loadLibrary","exec","getNetworkInfo","getExtraInfo","getTypeName","isConnected","getState","setWifiEnabled",
    "getWifiState","setRequestMethod","getInputStream","getOutputStream","sendMessage","obtainMessage","myPid","killProcess",
    "readLines","available","delete","exists","mkdir","ListFiles","getBytes","valueOf","replaceAll","schedule","cancel","read",
    "close","getNextEntry","closeEntry","getInstance","doFinal","DESKeySpec","getDocumentElement","getElementByTagName","getAttribute"]
    APIsList=[]
    for i in range(len(z)):
        for j in range(len(API_calls)):
            if API_calls[j] == z[i]:
                features = features + API_calls[j] + " "

    #features=[]
    #features.extend(intentList)
    #features.extend(cmdList)
    #features.extend(APIsList)
    return features
def feature_selection(X_train,y_train):
    clf = ExtraTreesClassifier(n_estimators=600)
    clf = clf.fit(X_train, y_train)
    importances = clf.feature_importances_
    model = SelectFromModel(clf, prefit=True)
    X_train_new = model.transform(X_train)
    return X_train_new

def train(train_file,test_file):#csv format
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=" ,")
    y_train = data_train[:, 0]
    X_train = data_train[:, 1:]
    #xg_train = xgb.DMatrix(X_train, label=y_train)
    data_test = np.genfromtxt(open(test_file, " r"), delimiter=" ,")
    y_test = data_test[:, 0]
    X_test = data_test[:, 1:]
    #xg_test = xgb.DMatrix(X_test, label=y_test)
    param = {}
    param['objective'] = 'multi: softmax'
    param[ 'eta'] = 0.1
    param[ 'max_depth'] = 6
    param[ 'silent'] = 1
    param[ 'nthread'] = 4
    param[ 'num_class'] = 78  # Number of classes starting from 0
    #watchlist = [(xg_train, 'train'), (xg_test, 'test')]
    num_round = 260
    #bst = xgb.train(param, xg_train, num_round, watchlist);
    #get predictions
    #y_pred = bst.predict(xg_test);
    #print(classification_report(y_test, y_pred))

def main():
    X=[]
    Y=[]
    #bening:
    for file in os.listdir('Files/benign'):
        features=get_features('Files/benign/'+file)
        X.append(features)
        Y.append(0)#not malware
    for file in os.listdir('Files/malware'):
        features = get_features('Files/malware/'+file)
        X.append(features)
        Y.append(1)  #malware
    #get x to bag of words model:
    vectorizer = CountVectorizer(analyzer="word",preprocessor=None,max_features=5000)
    X_bag = vectorizer.fit_transform(X)
    X_bag = X_bag.toarray()
    X_bag_selected=feature_selection(X_bag,Y)
    #write to csv
    df=pd.DataFrame(X_bag_selected)
    #get the model:




main()