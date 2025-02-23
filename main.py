# All required libraries are listed in the requirements.txt file
# To install the required libraries, run the following command in the terminal:
# pip install -r requirements.txt

# Imports:
from datetime import datetime
import numpy as np
import pandas as pd
from mitreattack.stix20 import MitreAttackData
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score
import json
import os
from collections import defaultdict
# Setup:

# For Att&ck:
mitreAttack = MitreAttackData("datasets/enterprise-attack.json")

# Documentation for the mitreattack lib https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/examples.html



# ______

# Plot function for Line of Best Fit and R^2 value
def plotLineOBF(x,y):
  plt.scatter(x,y)
  m,c=np.polyfit(x,y,1)
  plt.plot(x,c+m*x)
  print(r2_score(y,c+m*x))
  plt.show()
  return


def CWEtoATTACK(cveDict, AttackDict):
  store = []
  #  This function will take the CWEs and use it to find the CVE then the TTP, this results in very little mapping
  for cweId, cveList in cveDict.items():
    tempAttack = []
    for cveId in cveList:
        tempAttack.append(AttackDict[cveId])
    store.append([cweId,cveList,tempAttack])
  df = pd.DataFrame(store, columns=['CWE ID', 'Attributed CVEs','Attributed Tactics'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/CWEtoTTP " + timeString + ".xlsx"
  df.to_excel(title, index=False)
  return

def CVEtoATTACKCWE(cveDict,AttackDict):
  # This function uses CVE as the Join between CWES and tactics. This provides the right data needed for further analysis
  store = []
  for cveId, tactics in AttackDict.items():
    store.append([cveId,cveDict[cveId],tactics])

  # below will create two files, one with all the information and one with only data that has all three bits of information attributed to it
  reducedStore = []

  for set in store:
     if set[-1]!=[] and set[-2]!= [] and set[-2]!= ['','']:
        if set[-2][0]=='':
           set[-2].pop(0)
        reducedStore.append(set)
  df = pd.DataFrame(store, columns=['CVE ID', 'Attributed CWES','Attributed Tactics'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/CVEtoATTACKCWE " + timeString + ".xlsx"
  df.to_excel(title, index=False)
  dfReduced = pd.DataFrame(reducedStore, columns=['CVE ID', 'Attributed CWES','Attributed Tactics'])
  title = "generated/CVEtoATTACKCWE[Reduced] " + timeString + ".xlsx"
  dfReduced.to_excel(title,index=False)
  return


def getCWEsAttack():
# This function maps all the CWE's to Tactics from ATT&CK, however, the mappings between CVE to ATT&CK are lacking in amount, resulting in large amounts of CVE's with no assocaited Tactics

# For speed, this set of code reads all the cves into a dictionary with the key being the CWE Id associatied with it.
  cveDict = defaultdict(list)
  # The below dictionary is the CVE as the key and the CWE as the items while the above dictionary is the CWE as the key and the CVE as the items
  cveReverseDict = defaultdict(list)

  for root, dirs, files in os.walk("datasets/cves"):
      for name in files:
        pathInfo = os.path.join(root,name)
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2008, 2021)):
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
                
  # Below extracts the CVE-ATT&CK Mapping into a dictionary to make it easier for analysis
  AttackDict = defaultdict(list)
  data = json.load(open("datasets/cve-10.21.2021_attack-9.0-enterprise_json.json",'r',encoding='utf-8'))
  objects = data.get("mapping_objects",[])
  for object in objects:
      AttackDict[str(object.get("capability_id",[]))].append(object.get('attack_object_id',[]))

  # CWEtoATTACK(cveDict, AttackDict)
  CVEtoATTACKCWE(cveReverseDict,AttackDict)
  return

  

if __name__ == "__main__":
  # Below will create a 'generated' folder if one doesn't already exist
  os.makedirs("generated", exist_ok=True)

  getCWEsAttack()