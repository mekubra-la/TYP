# This script is a one time use script to delete CWE's between 2009-2019
# that do not have any CWE data attached to them
import json
import os

def contains_cwe(json_file,pathInfo):
    try:        
        # Convert the entire JSON structure to a string and check for "CWE"
        if( "CWE" in json.dumps(data)  ):
            
            return True
        else:
            os.remove(pathInfo)
            return False
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading file: {e}")
        return False

for root, dirs, files in os.walk("datasets/cves"):
    for name in files:
        pathInfo = os.path.join(root,name)
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2008, 2025)):
            data=json.load(open(pathInfo, encoding='utf-8'))
            print(pathInfo)
            print(contains_cwe(data,pathInfo))





# Below code didn't take out any time CWE wasn't mentioned at all. It also didn't check the legacy information, above is a simplier way to extract the information
            # CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            # for problem in CVEs:
            #     for cweId in problem.get("descriptions",[]):
            #             # print(data.get("cveMetadata",{}).get("cveId",[]))
            #             if cweId.get("cweId", "") == '':
            #                 print("Deleting")
            #                 os.remove(pathInfo)
            #                 break
            #             break
            #     break
                        
                        
                             
