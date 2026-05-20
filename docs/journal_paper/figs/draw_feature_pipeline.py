"""Detailed feature pipeline diagram for journal paper."""

from pathlib import Path

import graphviz

OUT_DIR = Path(__file__).parent


def main():
    dot = graphviz.Digraph(
        "feature_pipeline",
        format="png",
        graph_attr={
            "dpi": "300",
            "rankdir": "LR",
            "fontname": "Helvetica",
            "fontsize": "10",
            "nodesep": "0.5",
            "ranksep": "0.9",
            "bgcolor": "white",
        },
        node_attr={"fontname": "Helvetica", "fontsize": "9", "shape": "box", "style": "filled"},
        edge_attr={"fontname": "Helvetica", "fontsize": "8"},
    )

    dot.node("raw", "Raw Event\nStream\n(CSV)", fillcolor="#D6EAF8")
    dot.node("sess", "Session\nGrouping\n(30 min idle)", fillcolor="#AED6F1")

    with dot.subgraph(name="cluster_features") as sg:
        sg.attr(label="Feature Groups", style="filled", fillcolor="#FEF9E7", color="#F39C12")
        sg.node("f1", "Group 1\nEvent ID\nFrequency Counts\n(13 IDs + total)", fillcolor="#FAD7A0")
        sg.node("f2", "Group 2\nTime-Delta Stats\n(mean, std, min, max)", fillcolor="#FAD7A0")
        sg.node("f3", "Group 3\nCardinality\n(sources, users, hosts)", fillcolor="#FAD7A0")
        sg.node("f4", "Group 4\nRare-Event Flags\n(<5% benign sessions)", fillcolor="#FAD7A0")
        sg.node("f5", "Group 5\nShannon\nSequence Entropy", fillcolor="#FAD7A0")

    dot.node("vec", "Feature Vector\n(24-dim)", shape="cylinder", fillcolor="#F9E79F")
    dot.node(
        "label", "Session Label\n(0=benign, 1=malicious)", shape="diamond", fillcolor="#E8DAEF"
    )
    dot.node("train", "Random Forest\nTraining", fillcolor="#EC7063", fontcolor="white")

    dot.edge("raw", "sess")
    dot.edge("sess", "f1")
    dot.edge("sess", "f2")
    dot.edge("sess", "f3")
    dot.edge("sess", "f4")
    dot.edge("sess", "f5")
    dot.edges([("f1", "vec"), ("f2", "vec"), ("f3", "vec"), ("f4", "vec"), ("f5", "vec")])
    dot.edge("vec", "train")
    dot.edge("label", "train")

    out = OUT_DIR / "feature_pipeline"
    dot.render(str(out), cleanup=True)
    print(f"Saved {out}.png")


if __name__ == "__main__":
    main()
