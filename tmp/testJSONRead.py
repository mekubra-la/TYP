import json
import os
# Currently returns in a tuple but doesn't like accessing files like that
# This method of searching CVE is ineffective and makes the program extremely large.

# CWE 89 -> CVE-2019-1942


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
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2019, 2020)):
            print(pathInfo)
            data=json.load(open(pathInfo, encoding='utf-8'))
            CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            for problem in CVEs:
                for cweId in problem.get("descriptions",[]):
                        # print(data.get("cveMetadata",{}).get("cveId",[]))
                        print(cweId.get("cweId", "")[4:])
                        if cweId.get("cweId", "")[4:] == '89':
                            print("IM A THING!!!")
                            cveID = data.get("cveMetadata",{}).get("cveId",[])
                            print(cveID)

# NOTE THAT IS IT ALSO LISTED UNDER VALUE sometimes