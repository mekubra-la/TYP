from pycvesearch import CVESearch

cve=CVESearch('https://cve.circl.lu')
print(cve.id('CVE-2019-1942'))
