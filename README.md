The project is split into different files and folders for ease of
understanding.

main.py  
is the primary file which runs through the datasets, maps them, and
analyses them. Simply run the program to create the mapping, including
two spreadsheets \[stored in **generated**\] and a visual network map.
It also outputs the most common tactic and the amount of times it is
referenced.

requirements.txt  
is a text file containing all the required libraries for the whole
project including any libraries used in the **tmp** or
**non-useful-analysis** files.

.gitignore  
this is primarily for my use, used when deciding what dataset I should
be ignoring without having to delete them from my computer in case I
would need to refer to other data. It also prevents the generated
outputs from **main.py** from being push to GitHub.

datasets  
This folder contains all the datasets used in the mapping, it includes
the MITRE ATT&CK framework, the CVE framework \[Between 2008 and 2021\],
the CWE dataset and the CVE to ATT&CK Mapping.

non-useful-analysis  
This folder separates out some analysis I did initially with the two
datasets I was interested in mapping. It is separated into ATT&CK
analysis and CWE Analysis.

tmp  
This folder contains a number of Python scripts that were either used
once to tidy data or to test different libraries or
methods of searching before deciding on a particular method.
