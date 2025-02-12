import json
import os
# Currently returns in a tuple but doesn't like accessing files like that
# This method of searching CVE is ineffective and makes the program extremely large.



# for filename in os.walk('datasets/cves'):
#     # print(filename)
#     if filename[2][0].endswith(".json"):
#         print(filename[1][0])
#         data=json.load(open(filename))
#         CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
#         for problem in CVEs:
#             for description in problem.get("descriptions",[]):
#                     cveID = data.get("cveMetadata",{}).get("cveId",[])
#                     print(cveID)


for root, dirs, files in os.walk("datasets/cves"):
    for name in files:
        
        pathInfo = os.path.join(root,name)
        # print(pathInfo)
        if (pathInfo).endswith(".json"):
            data=json.load(open(pathInfo))
            CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            for problem in CVEs:
                for description in problem.get("descriptions",[]):
                        print(data.get("cveMetadata",{}).get("cveId",[]))
                        print(description.get("description", "")[4:])
                        if description.get("description", "")[4:] == '84':
                            cveID = data.get("cveMetadata",{}).get("cveId",[])
                            print(cveID)



# data = json.load(open("datasets/cves/2019/1xxx/CVE-2019-1942.json",'r',encoding='utf-8'))
#   CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
#   for problem in CVEs:
#     for description in problem.get("descriptions",[]):
#       if description.get("description", "")[4:] == CWE:
#         print("Found CVE")
#         cveID = data.get("cveMetadata",{}).get("cveId",[])
#         print(cveID)
#         break