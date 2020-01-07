from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.feature_selection import SelectFromModel
from joblib import  load

class AnastasiaDetector():
    def get_features(self,file):
        try:
            features=""
            a = APK (file)
            d = dvm . DalvikVMFormat ( a. get_dex () )
            z = d . get_strings ()
            #intents
            for i in range ( len( z )):
                if z [i ]. startswith ( "android.intent.action."):
                    intents = z[i ]
                    features=features+ intents+" "
            #cmd
            suspicious_cmds = ["su", "mount", "reboot", "mkdir"]
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
            for i in range(len(z)):
                for j in range(len(API_calls)):
                    if API_calls[j] == z[i]:
                        features = features + API_calls[j] + " "

            return features
        except:
            return ""

    #this function return 1 if file is malware and 0 otherwise
    def detect(self,file):
        #feature extraction
        features=self.get_features(file)
        #vectorize:
        vectorizer=load("AnastasiaFeatures.joblib")
        X=vectorizer.transform([features]).toarray()
        #feature selection:
        feature_selector = load('AnastasiaFeaturesSelected.joblib')
        model = SelectFromModel(feature_selector, prefit=True)
        X_new = model.transform(X)
        #predict:
        clf = load('AnastasiaClassifier.joblib')
        return int(clf.predict(X_new)[0])

detector=AnastasiaDetector()
print(detector.detect("app.apk"))