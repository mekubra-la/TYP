import xml.etree.ElementTree as ET

tree = ET.parse('cwec_v4.16.xml')
root = tree.getroot()

for child in root:
    if 'Weaknesses' in child.tag:
      for child2 in child:
          if child2.attrib['ID'] == '1045':
            print(child2.tag,child2.attrib)
            for child3 in child2:
               print(child3.attrib) #for description only as it's text

