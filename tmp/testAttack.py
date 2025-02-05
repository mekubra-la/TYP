import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf

# download and parse ATT&CK STIX data
attackdata = attackToExcel.get_stix_data("enterprise-attack")
techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")

# show T1102 and sub-techniques of T1102
techniques_df = techniques_data["techniques"]
print(techniques_df[techniques_df["ID"].str.contains("T1102")]["name"])
# 512                                 Web Service
# 38     Web Service: Bidirectional Communication
# 121             Web Service: Dead Drop Resolver
# 323          Web Service: One-Way Communication
# Name: name, dtype: object