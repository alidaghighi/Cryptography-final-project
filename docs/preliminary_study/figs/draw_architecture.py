"""System architecture diagram for AI malware detection in smart grid."""

from pathlib import Path
import graphviz

OUT_DIR = Path(__file__).parent

def main():
    dot = graphviz.Digraph(
        "architecture",
        format="png",
        graph_attr={
            "dpi": "300",
            "rankdir": "LR",
            "fontname": "Helvetica",
            "fontsize": "10",
            "splines": "ortho",
            "nodesep": "0.5",
            "ranksep": "0.8",
            "bgcolor": "white",
        },
        node_attr={"fontname": "Helvetica", "fontsize": "10"},
        edge_attr={"fontname": "Helvetica", "fontsize": "9"},
    )

    with dot.subgraph(name="cluster_ot") as sg:
        sg.attr(label="OT Network (Purdue L1-L2)", style="filled", fillcolor="#E8F4FD", color="#2980B9")
        sg.node("rtu", "RTU-CTRL\n(L1)", shape="box", style="filled", fillcolor="#AED6F1")
        sg.node("hmi", "SCADA-HMI\n(L2)", shape="box", style="filled", fillcolor="#AED6F1")
        sg.node("eng", "Eng Station\n(L2)", shape="box", style="filled", fillcolor="#AED6F1")

    with dot.subgraph(name="cluster_it") as sg:
        sg.attr(label="IT Network (Purdue L3)", style="filled", fillcolor="#E9F7EF", color="#27AE60")
        sg.node("historian", "Historian\n(L3)", shape="box", style="filled", fillcolor="#A9DFBF")
        sg.node("dc", "Domain\nController", shape="box", style="filled", fillcolor="#A9DFBF")

    with dot.subgraph(name="cluster_detection") as sg:
        sg.attr(label="Detection Pipeline", style="filled", fillcolor="#FEF9E7", color="#F39C12")
        sg.node("evtlog", "Windows\nEvent Logs", shape="cylinder", style="filled", fillcolor="#FAD7A0")
        sg.node("feat", "Feature\nExtraction", shape="diamond", style="filled", fillcolor="#F9E79F")
        sg.node("rf", "Random\nForest", shape="ellipse", style="filled", fillcolor="#F0B27A")
        sg.node("alert", "ALERT", shape="doubleoctagon", style="filled", fillcolor="#EC7063", fontcolor="white")

    dot.node("attacker", "Adversary", shape="invtriangle", style="filled", fillcolor="#E74C3C", fontcolor="white")

    dot.edges([("rtu", "hmi"), ("hmi", "historian"), ("eng", "dc")])
    dot.edge("attacker", "hmi", label="attack vector", style="dashed", color="#E74C3C")
    dot.edge("hmi", "evtlog", label="audit events")
    dot.edge("dc", "evtlog")
    dot.edge("evtlog", "feat")
    dot.edge("feat", "rf")
    dot.edge("rf", "alert", label="malicious")

    out = OUT_DIR / "architecture"
    dot.render(str(out), cleanup=True)
    print(f"Saved {out}.png")

if __name__ == "__main__":
    main()
