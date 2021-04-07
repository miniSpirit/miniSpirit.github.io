tar = "MSAWB~FXZ:J:`tQJ\"N@ bpdd}8g"
ans = ""
for i in range(0, 0x1B) :
    ans += chr(ord(tar[i])^i)
print(ans)