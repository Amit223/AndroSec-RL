import simplejson
import urllib
import androguard.core.bytecodes.apk
from androguard.core import analysis
from androguard.core.bytecodes import dvm
from androguard . core . bytecodes . dvm import *
from androguard . core . bytecodes . apk import *
from androguard.misc import AnalyzeAPK


def getIntents(url):
    a = APK (url)
    d = dvm . DalvikVMFormat ( a. get_dex () )
    z = d . get_strings ()
    intentList=[]
    for i in range ( len( z )):
        if z [i ]. startswith ( "android.intent.action."):
            intents = z[i ]
            intentList . append ( intents )
    return intentList
def getPermissions(file):
    a, d, dx = AnalyzeAPK(file)
    print("hi")
    return a.get_permissions()


def getByteCode(url):
    a,d,dx = AnalyzeAPK(url)
    for method in dx.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        if m.get_code():
            print(m.get_code().get_bc().get_raw())
print(getPermissions("Files/app1.apk"))