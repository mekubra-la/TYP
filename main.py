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


# StructureEnumeration - can be simple, Composite, or Chain
# StatusEnumeration - Deprecated, Obsolete, Incomplete, Draft, Usable, Stable

# Get all CWEs that are simple and stable or draft
def getCWESimpleStableDraft():
  tree = ET.parse('datasets/cwec_v4.16.xml')
  root = tree.getroot()
  for child in root:
      if 'Weaknesses' in child.tag:
        for child2 in child:
            if child2.attrib['Structure'] == 'Simple' and (child2.attrib['Status']=='Stable' or child2.attrib['Status']=='Draft'):
              print(child2.attrib['ID'], ": ",child2.attrib['Name'])    
  return



# Get all MITRE ATTACK Threat actor groups and how many Techniques associated with each
def threatsXgroups():
  store=[]
  x = np.array([])
  y=np.array([])
  groups = mitreAttack.get_groups() #Produces all the groups
  # Produces all the techniques a group may use
  techniques = mitreAttack.get_all_techniques_used_by_all_groups() 
  for id, technique in techniques.items():
    # Finds the software associated with each group
    software = mitreAttack.get_software_used_by_group(id)

    #Finds the group id, [the next will pick the first item found or it will return none]
    group = next((g for g in groups if g['id'] == id), None) 
    name = group['name'] if group else "*UNKNOWN GROUP NAME*"
    # Gets the external ID which relates to the ID on the website rather than the long hex string
    externalID = group['external_references']if group else "*UNKNOWN GROUP ID*"
    externalID = externalID[0]['external_id']
    print(f"ID: {id}, External ID: {externalID}, Group Name: {name}, Amount of Techniques associated: {len(technique)}, Amount of Software associated: {len(software)}")
    # Below is code for writing to an excel file
    store.append([id, externalID,name, len(technique),len(software)])
    x = np.append(x,len(technique))
    y = np.append(y,len(software))
    plt.annotate(externalID, (len(technique),len(software)))

  df = pd.DataFrame(store, columns=['ID','External ID', 'Group Name', 'Amount of Techniques','Amount of Software'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/ThreatActorGroups " + timeString + ".xlsx"
  df.to_excel(title, index=False)

  plotLineOBF(x,y)
  return


def campaignsXtechniques():
  store = []
  campaigns = mitreAttack.get_campaigns()
  techniques = mitreAttack.get_all_techniques_used_by_all_campaigns()
  for id, technique in techniques.items():
    campaign = next((c for c in campaigns if c['id'] == id), None)
    name = campaign['name'] if campaign else "*UNKNOWN CAMPAIGN NAME*"
    groups = mitreAttack.get_groups_attributing_to_campaign(id)

    print(f"ID: {id}, Campaign Name: {name}, Amount of Techniques: {len(technique)}, Assoicatated with a group?:",end=' ')    
    if len(groups)!=0:
      print("Yes")

      store.append([id, name, len(technique), groups[0]['object'].name ])

    else:
      print("No")
      store.append([id, name, len(technique), "*NOT ASSOCIATED WITH GROUP*"])
      # print(f"Group: {group['object'].name}") 
  df = pd.DataFrame(store, columns=['ID', 'Campaign Name', 'Amount of Techniques', 'Group Name'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/Campaigns " + timeString + ".xlsx"
  df.to_excel(title, index=False)
  return



# Potential to look at groups associated with countries using a word algorithm to scan through the descriptions


def getSpecificAttackFromCWE(CWE):
  # tree = ET.parse('datasets/cwec_v4.16.xml')
  # root = tree.getroot()
  # # Firstly grabs the name of the CWE from the given ID
  # for child in root:
  #     if 'Weaknesses' in child.tag:
  #       for child2 in child:
  #           if child2.attrib['ID'] == CWE:
  #             print(child2.attrib['Name'])

  # This program only work on CVES between 2009 and 2019 
  # Next it moves on to finding the associated CVE
  cveList=[]
  for root, dirs, files in os.walk("datasets/cves"):
    for name in files:
        pathInfo = os.path.join(root,name)
        if (pathInfo).endswith(".json") and any(f"\\{year}\\" in pathInfo for year in range(2008, 2021)):
            data=json.load(open(pathInfo, encoding='utf-8'))
            CVEs = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
            for problem in CVEs:
                for cweId in problem.get("descriptions",[]):
                        if cweId.get("cweId", "")[4:] == CWE:
                            cveList.append(data.get("cveMetadata",{}).get("cveId",[]))
  print(cveList)

# Once it has found the related CVE, it will search the CVE - MITRE Mapping 
  tactics = []
  for cveId in cveList:
    data = json.load(open("datasets/cve-10.21.2021_attack-9.0-enterprise_json.json",'r',encoding='utf-8'))
    objects = data.get("mapping_objects",[])
    for object in objects:
      if cveId == object.get("capability_id",[]):
        if object.get("attack_object_id",[]) not in tactics:
          tactics.append(object.get("attack_object_id",[]))
  
  print(tactics)  
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
  store = []
  for cveId, tactics in AttackDict.items():
    store.append([cveId,cveDict[cveId],tactics])
  df = pd.DataFrame(store, columns=['CVE ID', 'Attributed CWES','Attributed Tactics'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/CVEtoATTACKCWE " + timeString + ".xlsx"
  df.to_excel(title, index=False)
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

  CWEtoATTACK(cveDict, AttackDict)
  CVEtoATTACKCWE(cveReverseDict,AttackDict)
  return

  

if __name__ == "__main__":
  # Below will create a 'generated' folder if one doesn't already exist
  os.makedirs("generated", exist_ok=True)
  # threatsXgroups()
  # campaignsXtechniques()
  # CWE = '121' #This is for specific CWE searching
  # getSpecificAttackFromCWE(CWE)

  getCWEsAttack()