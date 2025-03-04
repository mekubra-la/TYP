from datetime import datetime
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score
from mitreattack.stix20 import MitreAttackData

mitreAttack = MitreAttackData("datasets/enterprise-attack.json")

# Plot function for Line of Best Fit and R^2 value
def plotLineOBF(x,y):
  plt.scatter(x,y)
  plt.xlabel("Amount of Techniques")
  plt.ylabel("Amount of Software")
  m,c=np.polyfit(x,y,1)
  plt.plot(x,c+m*x)
  print(r2_score(y,c+m*x))
  plt.show()
  return
def threatXmitigation(tactic):
  stixId = mitreAttack.get_object_by_attack_id(str(tactic).strip(),"attack-pattern")
  mitigations = mitreAttack.get_mitigations_mitigating_technique(stixId.id)
  print(mitigations)
  for mitigation in mitigations:
    print(mitigation['object'].name)
  return

def threatsXgroups():
  # Get all MITRE ATTACK Threat actor groups and how many Techniques associated with each

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
if __name__ == "__main__":
  # threatsXgroups()
  # campaignsXtechniques()
  threatXmitigation("T1083")