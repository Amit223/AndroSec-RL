import os
from Anastasia.AnastasiaDetector import AnastasiaDetector
from SVM.SVMDetector import SVMDetector

detectors=[AnastasiaDetector(),SVMDetector()]

def mainSystem():
    file = input("Enter file path: ")
    detection=detect(file)
    return detection



def mainTestingSystem():
    list_detections=[]
    for file in os.listdir('Files'):
        list_detections.append(detect(file))
    return list_detections


'''
this function detect file by all the detectors.
returns 1 if malware and 0 otherwise
'''
def detect(file):
    detections=[detector.detect(file) for detector in detectors]
    counter_malware=0
    for detection in detections:
        if detection==1:
            counter_malware+=1
    if counter_malware>=len(detectors)/2:
        return 1
    else:
        return 0

if __name__=='__main__':
    print(mainSystem())

