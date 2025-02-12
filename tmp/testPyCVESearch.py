from pycvesearch import CVESearch

cve=CVESearch('https://cve.circl.lu')
# CWE 89 -> CVE-2019-1942
print(cve.id('CVE-2019-1942'))
# Doesn't appear to like to find anything using the CWE number
# Appears to be a dead end
