import simplejson
import urllib
import androguard.core.bytecodes.apk
from androguard.core.analysis import auto
from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from androguard.misc import AnalyzeAPK


def get_features(file):
    a = APK (file)
    d = dvm . DalvikVMFormat ( a. get_dex () )
    z = d . get_strings ()
    #intents
    intentList=[]
    for i in range ( len( z )):
        if z [i ]. startswith ( "android.intent.action."):
            intents = z[i ]
            intentList . append ( intents )
    #perrmissions
    permissions=a.permissions()
    #cmd
    suspicious_cmds = [" su ", " mount ", " reboot ", " mkdir "]
    cmdList=[]
    for i in range(len(z)):
        for j in range(len(suspicious_cmds)):
            if suspicious_cmds[j] == z[i]:
                cmdList.append(suspicious_cmds[j])
    #api
    suspicious_APIs = [" getSimSerialNumber ", " getSubscriberId ", " getDeviceId "]
    APIsList=[]
    for i in range(len(z)):
        for j in range(len(suspicious_APIs)):
            if suspicious_APIs[j] == z[i]:
                APIsList.append(suspicious_APIs[j])

    features=[]
    features.append(intentList)
    features.append(permissions)
    features.append(cmdList)
    features.append(APIsList)
    return features
