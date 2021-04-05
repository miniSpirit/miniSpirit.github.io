这题实在是没啥东西，怎么BUU刷到中间还比前面简单了

直接script:

```python
arr = [ 0, 198, 232, 816, 200, 1536, 300, 6144, 984, 51200, 570, 92160, 1200, 565248, 756, 1474560, 800, 6291456, 1782, 65536000 ]
ans = ""
for i in range(1, len(arr)) :
    if(i&1) :
        ans += chr(arr[i] >> i)
    else :
        ans += chr(arr[i] // i)
print(ans)
```

### flag :ctf2020{d9-dE6-20c}