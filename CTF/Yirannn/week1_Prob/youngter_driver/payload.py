trans = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"

targt = "TOiZiZtOrYaToUwPnToBsOaOapsyS"

ans = ""
for i in range(0, len(targt)) :
    if i & 1 :
        pos = trans.find(targt[i])
        if targt[i].isupper() :
            ans = ans + chr(pos+96)
        else :
            ans = ans + chr(pos+38)
    else :
        ans = ans + targt[i]
print(ans)