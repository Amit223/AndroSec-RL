import simplejson
import urllib
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from androguard . core . analysis . analysis import *

def getIntents(url):
    a = APK ("Files/app1.apk")
    d = dvm . DalvikVMFormat ( a. get_dex () )
    z = d . get_strings ()
    intentList=[]
    for i in range ( len( z )):
        if z [i ]. startswith ( "android.intent.action."):
            intents = z[i ]
            intentList . append ( intents )
    return intentList
