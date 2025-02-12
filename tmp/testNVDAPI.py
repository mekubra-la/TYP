# CWE 89 -> CVE-2019-1942
import datetime
import requests
# Testing the use of the NVD API
url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


# Max allowed range is 120 days!!!

def maxRange():
    paramaters2={
        "pubStartDate": "2009-01-01T00:00:00.000",
        "pubEndDate":"2019-12-31T23:59:59.999",
        "resultsPerPage":10
    }
    response=requests.get(url,params=paramaters2)
    print(response.status_code)
    # Above will always return 404 as the range is too big
    return
def smallRange():
    paramaters2={
        "cweId": "CWE-89",   
        "pubStartDate": "2020-01-01T00:00:00.000-05:00",
        "pubEndDate":"2020-01-14T23:59:59.999-05:00",
        "resultsPerPage":10
    }
    response=requests.get(url,params=paramaters2)
    cve_data = response.json()
    print(cve_data)
    return



# finding the Cwe and manually extracting those that exist in the correct time, This doesn't work as their is over the max amount of data in the range
def manualExtraction():
    paramaters = {
        "cweId": "CWE-89"
    }
    print(paramaters)
    response = requests.get(url, params=paramaters)
    cve_data = response.json()

    # print(cve_data)

    for vuln in cve_data['vulnerabilities']:
        print(vuln['cve']['published'])
    return
def iterateThrough():
    start = datetime.datetime(2009,1,1)
    end = datetime.datetime(2019,12,31)
    print(start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])
    while start<=end:
        range=min(start+datetime.timedelta(days=100),end)

        parameters={
            "cveId": "CWE-89",
            "pubStartDate" : start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
            "pubEndDate" : range.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        }
        response = requests.get(url,params=parameters)
        start = range + datetime.timedelta(days=1)

        print(response.status_code)
        print("Moving On")

    return

if __name__ == "__main__":
    # smallRange()
    iterateThrough()