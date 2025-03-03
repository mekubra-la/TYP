import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
from sklearn.metrics import r2_score

from collections import defaultdict

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

if __name__ == "__main__":
  getCWESimpleStableDraft()