from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.feature_selection import SelectFromModel
from joblib import load
from KNN.KNNTrain import get_permission

class KNNDetector:


    #this function return 1 if file is malware and 0 otherwise
    def detect(self,file):
        #feature extraction
        features = get_permission(file)
        # vectorize:
        vectorizer = load("KNNFeatures.joblib")
        X = vectorizer.transform([features]).toarray()
        # predict:
        clf = load("KNNClassifier.joblib")
        return int(clf.predict(X)[0])

detector=KNNDetector()
print(detector.detect("app.apk"))