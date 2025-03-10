# All required libraries are listed in the requirements.txt file
# To install the required libraries, run the following command in the terminal:
# pip install -r requirements.txt

# To generate new requirements.txt use:
# python -m pigar generate

# Imports:
from datetime import datetime
import numpy as np
import pandas as pd
from mitreattack.stix20 import MitreAttackData
import networkx as nx
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score
import json
import os
from collections import defaultdict
from collections import Counter
# Setup:
# For Att&ck:
mitreAttack = MitreAttackData("datasets/enterprise-attack.json")

# Documentation for the mitreattack lib https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/examples.html



# ______


def statisticalAnalysis(data):
  x=[]
  y=[]
  tacticList=[]
  _, ax = plt.subplots(layout='constrained')
  for cve, cwes, tactics,mitigations in data:
     tacticList.extend(tactics)
    
  cve = [cve for cve,_,_,_ in data]
  tactics = [len(tactics) for _,_,tactics,_ in data]
  cwes = [len(cwes) for _,cwes,_,_ in data]
  mitigations= [sum(len(mitigation) for mitigation in mitigations )for  _,_,_,mitigations in data]
  x = np.arange(len(data))
  
  ax.bar(x-.25,tactics,0.25,label='Tactics')
  ax.bar(x,cwes,0.25,label='CWES')
  ax.bar(x+.25,mitigations,.25,label='Mitigations')
  ax.set_xticks(x)
  ax.set_xticklabels(cve, rotation =45, ha="right")
  ax.set_ylabel("Amount")
  ax.legend()
  plt.show()


  #  Find the most common tactic
  # print(Counter(tacticList).most_common(1)[0])
  
  # Below plots mitigations over tactics per cve
  

  x=np.array(tactics)
  y=np.array(mitigations)
  plt.scatter(x,y)
  plt.xlabel("Tactics")
  plt.ylabel("Mitigations")
  # The line of best fit must pass through c
  m=np.sum(x*y)/np.sum(x**2)
  plt.plot(x,m*x)
  print(r2_score(y,m*x))
  print(f"The Line of best fit for Mitigations over Tactics per CVE is: {m}x=y")
  plt.show()
  return





# Function to create the undirected Graph
def unDirectGraph(data):
  G=nx.DiGraph()
    # Subset put the nodes into three sections, left, middle, and right
  for cve, cwes, tactics,mitigations in data:
    G.add_node(cve, subset=1)  
    

    for cwe in cwes:
        G.add_edge(cve, cwe)  
        G.nodes[cwe]["subset"] = 0  
        
    tacticNum=0
    for tactic in tactics:
        G.add_edge(cve, tactic)  
        G.nodes[tactic]["subset"] = 2
        for mitigation in mitigations[tacticNum]:
            G.add_edge(tactic,mitigation)
            G.nodes[mitigation]["subset"]=3
        tacticNum =+ 1
            

  # This bit is for the layout, subset refers to the left, middle, and right of the diagram
  pos = nx.multipartite_layout(G, subset_key="subset")
  # pos = nx.spring_layout(G, seed=42) 
  # pos = nx.kamada_kawai_layout(G,pos = pos)

  node_colors = {}
  for node in G.nodes():
      if "CVE" in node:
          node_colors[node] = "blue"
      elif "CWE" in node:
          node_colors[node] = "orange"
      elif "Mitigation" in node:
         node_colors[node] = "black"
      else:
          node_colors[node] = "red"

# This bit will make sure it's slightly more visible 
  node_hover_text=[]
  for node, (x, y) in pos.items():
    if G.nodes[node]["subset"] == 0: 
        pos[node] = (x, y * 3)  
    elif G.nodes[node]["subset"] == 2: 
        pos[node] = (x, y * 5)  
    elif G.nodes[node]["subset"]==3:
       pos[node] = (x,y * 5)


  edge_x, edge_y = [], []
  for edge in G.edges():
      x0, y0 = pos[edge[0]]
      x1, y1 = pos[edge[1]]
      edge_x.extend([x0, x1, None])
      edge_y.extend([y0, y1, None])

  edge_trace = go.Scatter(
      x=edge_x, y=edge_y,
      line=dict(width=1, color="black"),
      hoverinfo="text",
      mode="lines"
  )

  node_x, node_y, node_text, node_color = [], [], [], []
  for node in G.nodes():
      x, y = pos[node]
      node_x.append(x)
      node_y.append(y)
      node_text.append(node)
      node_color.append(node_colors[node])
      outgoing = list(G.successors(node))  
      incoming = list(G.predecessors(node))  
      hover_info = f"{node}:\n"
      if outgoing:
          hover_info += f"<br>{'<br>'.join(outgoing)}"
      if incoming:
          hover_info += f"<br>{'<br>'.join(incoming)}"

      node_hover_text.append(hover_info)
  node_trace = go.Scatter(
      x=node_x, y=node_y,
      mode="markers+text",
      marker=dict(size=12, color=node_color, line=dict(width=2)),
      text=node_text,
      textposition='top right',
      hoverinfo="text",
      hovertext=node_hover_text
  )
  fig = go.Figure(
      data=[edge_trace, node_trace],
      layout=go.Layout(
          title="CWE <- CVE -> Tactics -> Mitigations",
          showlegend=False,
          hovermode="closest",
          margin=dict(b=0, l=0, r=0, t=40),
          xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
      )
  )
  fig.show()
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
  # Now get all the mitiagtions for each of the tactics
  tacticDict = defaultdict(list)
  tacticErrorList = []


  reducedStoreMitigation=[]
  for cve,cwe, tactics in reducedStore:
    overallMitigations=[]
    for tactic in tactics:
        stixId = mitreAttack.get_object_by_attack_id(str(tactic).strip(),"attack-pattern")
        try:
          if tactic not in tacticDict:
            mitigations = mitreAttack.get_mitigations_mitigating_technique(stixId.id)
            for mitigation in mitigations:
              tacticDict[tactic].append(mitigation['object'].name)
        except AttributeError:
          # Errors appear to be Tactics that exist in the other matrices (Not enterprise)
          if str(tactic).strip() not in tacticErrorList:
             tacticErrorList.append(tactic)
        overallMitigations.append(tacticDict[tactic])
    reducedStoreMitigation.append((cve,cwe,tactics,overallMitigations))
  print(f"Errors occured with tacitcs: {tacticErrorList}")




  df = pd.DataFrame(store, columns=['CVE ID', 'Attributed CWES','Attributed Tactics'])
  timeString = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
  title = "generated/CVEtoATTACKCWE " + timeString + ".xlsx"
  df.to_excel(title, index=False)
  dfReduced = pd.DataFrame(reducedStoreMitigation, columns=['CVE ID', 'Attributed CWES','Attributed Tactics','Mitigations'])
  title = "generated/CVEtoATTACKCWE[Reduced] " + timeString + ".xlsx"
  dfReduced.to_excel(title,index=False)
  unDirectGraph(reducedStoreMitigation)
  statisticalAnalysis(reducedStoreMitigation)


  return


def getCWEsAttack():
# This function maps all the CWE's to Tactics from ATT&CK, however, the mappings between CVE to ATT&CK are lacking in amount, resulting in large amounts of CVE's with no assocaited Tactics
  # The below dictionary is the CVE as the key and the CWE as the items while the above dictionary is the CWE as the key and the CVE as the items
  cveReverseDict = defaultdict(list)
  # Below extracts the CVE-ATT&CK Mapping into a dictionary to make it easier for analysis
  AttackDict = defaultdict(list)
  # data = json.load(open("datasets/cve-10.21.2021_attack-9.0-enterprise_json.json",'r',encoding='utf-8'))
  data = json.load(open("datasets\kev-02.13.2025_attack-15.1-enterprise_json.json",'r',encoding='utf-8'))
  cveErrorList=[]
  objects = data.get("mapping_objects",[])
  for object in objects:
      AttackDict[str(object.get("capability_id",[]))].append(object.get('attack_object_id',[]))
# below if an efficent way to find the cve json file by the name and extract only that from the files rather than iterating through everything
  for key in AttackDict.keys():
    year = key.split("-")[1]
    arbit = key.split("-")[2][:-3]
    path = f"datasets/cves/{year}/{arbit}xxx/{key}.json"
    try:
          data = json.load(open(path, encoding='utf-8'))
          CVECNA = data.get("containers", {}).get("cna",{}).get("problemTypes",[])
          for problem in CVECNA:
              for cweId in problem.get("descriptions",[]):
                  cveReverseDict[str(data.get("cveMetadata",{}).get("cveId",[]))].append(cweId.get("cweId", ""))
          CVEADP=data.get("containers",{}).get("adp",[])
          for entry in CVEADP:
            problemTypes = entry.get("problemTypes",[]) 
            for problem in problemTypes:
                for cweId in problem.get("descriptions",[]):
                  cveReverseDict[str(data.get("cveMetadata",{}).get("cveId",[]))].append(cweId.get("cweId", ""))
    except FileNotFoundError:
        cveErrorList.append(key)   

  print(f"CVE's without CWE: {cveErrorList}")      
  CVEtoATTACKCWE(cveReverseDict,AttackDict)
  return

  

if __name__ == "__main__":
  # Below will create a 'generated' folder if one doesn't already exist
  os.makedirs("generated", exist_ok=True)

  getCWEsAttack()