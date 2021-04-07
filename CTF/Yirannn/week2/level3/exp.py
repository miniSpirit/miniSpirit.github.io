base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
for i in range(10) :
    tmp = base64_table[i]
    base64_table[i] = base64_table[19-i]
    base64_table[19-i] = tmp;
print(base64_table)