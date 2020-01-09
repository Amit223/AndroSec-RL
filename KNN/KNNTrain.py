from androguard . core . bytecodes . apk import *
import pandas as pd
import os
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from joblib import dump, load
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn . metrics import classification_report
#from KNN.FeatureExtraction import get_permission

# this method receive apk manifest as xml file and extract all permission from it
# then save the permissions found in a XXX file
def save_permissions_to_file():
    print("hello")


def get_permission(apkFilePath):
    permissions = ""
    try:
        a = APK(apkFilePath)
        requested_permissions = a.get_permissions()
        for i in requested_permissions:
            permissions = permissions + " " + i
    except:
        return ""
    return permissions



# this method receive path to directory and read all apk files in it
# from each file extract only the manifest as xml file
def read_dataset():
    print("Start reading")
    for file in os.listdir('Files/benign'):
       manifestxml = get_permission('Files/benign/'+file)
       print(manifestxml)

    for file in os.listdir('Files/malware'):
       manifestxml = get_permission('Files/malware/'+file)
       print(manifestxml)


# this method receive apk file and extract only requested permissions in it's manifest
# returns the permissions as string
def get_permission_with_type(apkFilePath , type):
    permissions = ""
    if type == "benign":
        print("benign")
        print(apkFilePath)
        try:
            a = APK(apkFilePath)
            # print("REQUESTED PERMISSIONS:")
            requested_permissions = a.get_permissions()
            for i in requested_permissions:
                permissions = permissions + " " + i
                #print("\t", i)
            print(permissions)
        except:
            print("exception in " + apkFilePath)
    if type == "malware":
        print("malware")
        print(apkFilePath)
        try:
            a = APK(apkFilePath)
            print("REQUESTED PERMISSIONS:")
            requested_permissions = a.get_permissions()
            for i in requested_permissions:
                permissions = permissions + " " + i
                #print("\t", i)
            print(permissions)
        except:
            print("exception in " + apkFilePath)


def train(train_file):#csv format
    data_train = np.genfromtxt(open(train_file, "r"), delimiter=",")
    y_train = data_train[:, 1][1:]
    x_train = data_train[:, 2:][1:]
    neigh = KNeighborsClassifier(n_neighbors=3)
    neigh.fit(x_train, y_train)
    # write to file:
    dump(neigh, "KNNClassifier.joblib")


# this method receive apk file and extract only requested permissions in it's manifest
# returns the permissions as string
# def get_permission(apkFilePath):
#     permissions = ""
#     print(apkFilePath)
#     try:
#         a = APK(apkFilePath)
#         # print("REQUESTED PERMISSIONS:")
#         requested_permissions = a.get_permissions()
#         for i in requested_permissions:
#             permissions = permissions + " " + i
#             #print("\t", i)
#         #print(permissions)
#     except:
#         print("exception in " + apkFilePath)
#     return permissions


def writeFeaturesToCsv():
    X=[]
    Y=[]
    #bening:
    print("............................bening..............................")
    for file in os.listdir('../Files/benign'):
        print(file)
        features = get_permission('../Files/benign/'+file)
        if features != "":
            X.append(features)
            Y.append(0)  # not malware
        print("V")
    print("............................malware..............................")
    for file in os.listdir('../Files/malware'):
        print(file)
        features = get_permission('../Files/malware/'+file)
        if features != "":
            X.append(features)
            Y.append(1)  # malware
        print("V")
        # get x to bag of words model:
    print(X)
    vectorizer = CountVectorizer(analyzer="word", preprocessor=None, max_features=5000)
    X_bag = vectorizer.fit_transform(X)
    # write to file:
    dump(vectorizer, "KNNFeatures.joblib")
    X_bag = X_bag.toarray()
    # split to train and test
    X_train, X_test, y_train, y_test = train_test_split(X_bag, Y, test_size=0.2, random_state=1)
    # write to csv
    # write train:
    df_train = pd.DataFrame(X_train)
    df_train.insert(0, column='isMalware', value=y_train)
    df_train.to_csv("Train.csv")
    # write test:
    df_train = pd.DataFrame(X_test)
    df_train.insert(0, column='isMalware', value=y_test)
    df_train.to_csv("Test.csv")


def main():
    writeFeaturesToCsv()
    train("Train.csv")
    Model_Accuracy("Test.csv")

def Model_Accuracy(test_file):
    neigh = load("KNNClassifier.joblib")
    data_test = np.genfromtxt(open(test_file, "r"), delimiter=",")
    y_test = data_test[:, 1][1:]
    X_test = data_test[:, 2:][1:]
    # predict
    y_pred = neigh.predict(X_test)
    print(classification_report(y_test, y_pred))
    scores = cross_val_score(neigh, X_test, y_test, cv=3)  # todo: change when we get more files
    print("Accuracy:" + str(scores.mean()))


if __name__ == '__main__':
    main()

