from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from sklearn.feature_selection import SelectFromModel
from joblib import load
from KNN.KNNTrain import get_permission

class KNNDetector:
    def __init__(self):
        self.vectorizer=load("KNN/KNNFeatures.joblib")
        self.clf = load('KNN/KNNClassifier.joblib')


    #this function return 1 if file is malware and 0 otherwise
    def detect(self,file):
        #feature extraction
        features = get_permission(file)
        # vectorize:
        X = self.vectorizer.transform([features]).toarray()
        # predict:
        return int(self.clf.predict(X)[0])
