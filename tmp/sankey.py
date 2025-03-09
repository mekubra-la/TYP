import plotly.graph_objects as go


def sankey():
    fig = go.Figure(data=[go.Sankey(
        node = dict(
            pad =10,
            thickness =25,
            line = dict(color= 'black', width =0.5),
            label = ["CVE Dataset <br>284577", "CVEs within Valid Years <br>248618", "CVEs with CWE Links<br>117284", "CVEs Exist in KEV<br>1289","Discarded CVEs", "Kept but Currently Unmapped CVES"],
            color = ["black","black","black","black","red","black"],

        ),
        link = dict(
            arrowlen=100,
            source = [0,1,2,0,1,2],
            target = [1,2,3,4,4,5],
            value = [248618, 117284,1289,35959,131334,115995],
            color=["rgba(0,0,0,0.2)", "rgba(0,0,0,0.2)", "rgba(0,0,0,0.2)", "rgba(255, 0, 0, 0.3)", "rgba(255, 0, 0, 0.3)", "rgba(0, 0, 0, 0.2)"] 
        )
    )])
    fig.update_layout(title_text="", font_size=25)
    fig.show()

if __name__ == '__main__':
    sankey()