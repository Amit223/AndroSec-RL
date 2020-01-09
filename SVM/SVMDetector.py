from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.feature_selection import SelectFromModel
from joblib import  load

class SVMDetector:
    def __init__(self):
        self.vectorizer=load("SVM/SVMFeatures.joblib")
        self.clf = load('SVM/SVMClassifier.joblib')

    def get_features(self,file):
        try:
            features = ""
            a = APK(file)
            d = dvm.DalvikVMFormat(a.get_dex())
            z = d.get_strings()
            # api
            API_calls = ["getDeviceId", "getCellLocation", "setFlags", "addFlags", "setDataAndType", "putExtra", "init",
                         "query",
                         "insert", "update", "writeBytes", "write", "append", "indexOf", "substring", "startService",
                         "getFilesDir", "openFileOutput", "getApplicationInfo",
                         "getRunningServices", "getMemoryInfo", "restartPackage", "getInstalledPackages",
                         "sendTextMessage", "getSubscriberId", "getLine1Number", "getSimSerialNumber",
                         "getNetworkOperator",
                         "loadClass", "loadLibrary", "exec", "getNetworkInfo", "getExtraInfo", "getTypeName",
                         "isConnected", "getState", "setWifiEnabled",
                         "getWifiState", "setRequestMethod", "getInputStream", "getOutputStream", "sendMessage",
                         "obtainMessage", "myPid", "killProcess",
                         "readLines", "available", "delete", "exists", "mkdir", "ListFiles", "getBytes", "valueOf",
                         "replaceAll", "schedule", "cancel", "read",
                         "close", "getNextEntry", "closeEntry", "getInstance", "doFinal", "DESKeySpec",
                         "getDocumentElement", "getElementByTagName", "getAttribute"]
            for i in range(len(z)):
                for j in range(len(API_calls)):
                    if API_calls[j] == z[i]:
                        features = features + API_calls[j] + " "
            # permissions
            permissions = a.get_permissions()
            for p in permissions:
                features = features + p + " "
            return features
        except:
            return ""

    #this function return 1 if file is malware and 0 otherwise
    def detect(self,file):
        #feature extraction
        features=self.get_features(file)
        #vectorize:
        X=self.vectorizer.transform([features]).toarray()
        #predict:
        return int(self.clf.predict(X)[0])
