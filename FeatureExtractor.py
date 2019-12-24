#mport androguard.androguard.session


#this class extract features from android file
class FeatureExtractor:

    def __init__(self,url):
        a, d, dx = misc.AnalyzeAPK(url)
        self.file =a


    def extractFeatures(self):
        #files=self.file.show()
        print(self.file.get_permissions())

fe=FeatureExtractor("/Files/app1.apk")
fe.extractFeatures()