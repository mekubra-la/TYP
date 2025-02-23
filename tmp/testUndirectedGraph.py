import networkx as nx
import plotly.graph_objects as go

CVEtoCWE = [['CVE-2999-2','CWE2'],['CVE-2999-2','CWE3'],['CVE-0000-1','CWE6']]
CWEtoTactic = [['CWE2','T9'], ['CWE3','T9'],['CWE3','T10']]
G=nx.DiGraph()
# Subset put the nodes into three sections, left, middle, and right
for cve, cwe in CVEtoCWE:
    G.add_edge(cve, cwe)
    G.nodes[cve]["section"] = 0
    G.nodes[cwe]["section"] = 1 

for cwe, tactic in CWEtoTactic:
    G.add_edge(cwe, tactic)
    G.nodes[tactic]["section"] = 2
# This layout allows for the left right positions
pos = nx.multipartite_layout(G, subset_key="section")
#   pos = nx.spring_layout(G, seed=42)  # Random ish layout, comes out from the middle

node_colors = {}
for node in G.nodes():
    if "CVE" in node:
        node_colors[node] = "blue"
    elif "CWE" in node:
        node_colors[node] = "orange"
    else:
        node_colors[node] = "red"


edge_x, edge_y = [], []
for edge in G.edges():
    x0, y0 = pos[edge[0]]
    x1, y1 = pos[edge[1]]
    edge_x.extend([x0, x1, None])
    edge_y.extend([y0, y1, None])

edge_trace = go.Scatter(
    x=edge_x, y=edge_y,
    line=dict(width=1, color="black"),
    hoverinfo="none",
    mode="lines"
)

node_x, node_y, node_text, node_color = [], [], [], []
for node in G.nodes():
    x, y = pos[node]
    node_x.append(x)
    node_y.append(y)
    node_text.append(node)
    node_color.append(node_colors[node])
node_trace = go.Scatter(
    x=node_x, y=node_y,
    mode="markers+text",
    marker=dict(size=12, color=node_color, line=dict(width=2)),
    text=node_text,
    textposition='top right',
    hoverinfo="text"
)
fig = go.Figure(
    data=[edge_trace, node_trace],
    layout=go.Layout(
        title="CVE - CWE - Tactics",
        showlegend=False,
        hovermode="closest",
        margin=dict(b=0, l=0, r=0, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
)
fig.show()

