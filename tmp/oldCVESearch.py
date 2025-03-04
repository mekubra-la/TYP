import os
import json
from collections import defaultdict

def cveSearch():
  cveDict = defaultdict(list)
  cveReverseDict = defaultdict(list)
  for root, _, files in os.walk("datasets/cves"):
      for name in files:
        pathInfo = os.path.join(root,name)
        # Should be between 2008-2025 [excludes 2025]
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2008, 2025)):
            data=json.load(open(pathInfo, encoding='utf-8'))
            CVECNA = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            for problem in CVECNA:
                for cweId in problem.get("descriptions",[]):
                    cveDict[str(cweId.get("cweId", "")[4:])].append(data.get("cveMetadata",{}).get("cveId",[])) 
                    cveReverseDict[str(data.get("cveMetadata",{}).get("cveId",[]))].append(cweId.get("cweId", ""))
            CVEADP=data.get("containers",{}).get("adp",[])
            for entry in CVEADP:
              problemTypes = entry.get("problemTypes",[]) 
              for problem in problemTypes:
                  for cweId in problem.get("descriptions",[]):
                    cveDict[str(cweId.get("cweId", "")[4:])].append(data.get("cveMetadata",{}).get("cveId",[])) 
                    cveReverseDict[str(data.get("cveMetadata",{}).get("cveId",[]))].append(cweId.get("cweId", ""))