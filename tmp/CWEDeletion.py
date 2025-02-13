# This script is a one time use script to delete CWE's between 2009-2019
# that do not have any CWE data attached to them
import json
import os



for root, dirs, files in os.walk("datasets/cves"):
    for name in files:
        
        pathInfo = os.path.join(root,name)
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2009, 2020)):
            print(pathInfo)
            data=json.load(open(pathInfo, encoding='utf-8'))
            CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            for problem in CVEs:
                for cweId in problem.get("descriptions",[]):
                        # print(data.get("cveMetadata",{}).get("cveId",[]))
                        if cweId.get("cweId", "") == '':
                            print("Deleting")
                            os.remove(pathInfo)
                            break
                        break
                break
                        
                        
                             
