from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn . metrics import classification_report
import numpy as np
import pandas as pd
import os
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from joblib import dump, load

def Anastasia_Feature_Extraction(file):
    features=get_features(file)
    return feature_selection(features)

def get_features(file):
    try:
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
    except:
        return ""

def feature_train(X_train,y_train):
    clf = ExtraTreesClassifier(n_estimators=600)
    clf = clf.fit(X_train, y_train)
    importances = clf.feature_importances_
    dump(clf,'FeaturesSelected.joblib')


def feature_selection(X):
    clf=load('FeaturesSelected.joblib')
    model = SelectFromModel(clf, prefit=True)
    X_new = model.transform(X)
    return X_new

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
    X_bag = X_bag.toarray()
    feature_train(X_bag,Y)
    X_bag_selected=feature_selection(X_bag)
    #split to train and test
    X_train, X_test, y_train, y_test= train_test_split(X_bag_selected, Y, test_size=0.2, random_state=1)
    #write to csv
    #write train:
    df_train=pd.DataFrame(X_train)
    df_train.insert(0,column='isMalware',value=y_train)
    df_train.to_csv("Train.csv")
    #write test:
    df_train=pd.DataFrame(X_test)
    df_train.insert(0,column='isMalware',value=y_test)
    df_train.to_csv("Test.csv")


def train(train_file):#csv format
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=",")
    y_train = data_train[:, 1][1:]
    X_train = data_train[:, 2:][1:]
    clf = RandomForestClassifier(max_depth=8, n_estimators=600)#according to anastasia's article
    clf.fit(X_train, y_train)
    #write to file:
    dump(clf, 'RandomForestClassifier.joblib')

def test(test_file):
    clf = load('RandomForestClassifier.joblib')
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
    train("Train.csv")
    test("Test.csv")

main()