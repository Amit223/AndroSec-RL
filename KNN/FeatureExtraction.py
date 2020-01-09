from androguard . core . bytecodes . apk import *

# this method receive apk file and extract only requested permissions in it's manifest
# returns the permissions as string
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

