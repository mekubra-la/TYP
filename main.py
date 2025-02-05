# Imports:
from datetime import datetime
import numpy as np
import pandas as pd
from mitreattack.stix20 import MitreAttackData
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score

# Setup:

# For Att&ck:
mitreAttack = MitreAttackData("datasets/enterprise-attack.json")

# Documentation for the mitreattack lib https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/examples.html

# For CWE:
tree = ET.parse('datasets/cwec_v4.16.xml')
root = tree.getroot()


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
  campaigns = mitreAttack.get_campaigns()
  techniques = mitreAttack.get_all_techniques_used_by_all_campaigns()
  for id, technique in techniques.items():
    campaign = next((c for c in campaigns if c['id'] == id), None)
    name = campaign['name'] if campaign else "*UNKNOWN CAMPAIGN NAME*"
    groups = mitreAttack.get_groups_attributing_to_campaign(id)

    print(f"ID: {id}, Campaign Name: {name}, Amount of Techniques: {len(technique)}")    
    for group in groups:
      print(f"Group: {group['object'].name}")  



  return







if __name__ == "__main__":
  # threatsXgroups()
  campaignsXtechniques()

