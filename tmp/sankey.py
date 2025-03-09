import plotly.graph_objects as go


def sankey():
    fig = go.Figure(data=[go.Sankey(
        node = dict(
            pad =15,
            thickness =20,
            line = dict(color= 'black', width =0.5),
            label = ["CVE Dataset", "CVEs within Valid Years", "CVEs with CWE Links", "CVEs that have a KEV Mapping"],
            color = "blue"
        ),
        link = dict(
            source = [0,1,2],
            target = [1,2,3],
            value = [284577,248618, 117284,1289],
        )
    )])
    fig.update_layout(title_text="CVE Sankey Diagram", font_size=10)
    fig.show()

if __name__ == '__main__':
    sankey()