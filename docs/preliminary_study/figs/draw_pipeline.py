"""Data pipeline / ML workflow diagram for preliminary study."""

from pathlib import Path
import graphviz

OUT_DIR = Path(__file__).parent

def main():
    dot = graphviz.Digraph(
        "pipeline",
        format="png",
        graph_attr={
            "dpi": "300",
            "rankdir": "TB",
            "fontname": "Helvetica",
            "fontsize": "10",
            "splines": "ortho",
            "nodesep": "0.4",
            "ranksep": "0.6",
            "bgcolor": "white",
        },
        node_attr={"fontname": "Helvetica", "fontsize": "10", "shape": "box", "style": "filled"},
        edge_attr={"fontname": "Helvetica", "fontsize": "9"},
    )

    with dot.subgraph(name="cluster_data") as sg:
        sg.attr(label="Data Generation", style="filled", fillcolor="#EBF5FB", color="#2980B9")
        sg.node("gen", "Synthetic Event\nLog Generator", fillcolor="#AED6F1")
        sg.node("raw", "Raw CSV\n(timestamped events)", shape="cylinder", fillcolor="#D6EAF8")

    with dot.subgraph(name="cluster_prep") as sg:
        sg.attr(label="Preprocessing", style="filled", fillcolor="#E9F7EF", color="#27AE60")
        sg.node("clean", "Clean +\nNull Drop", fillcolor="#A9DFBF")
        sg.node("split", "Session-Stratified\nSplit 70/15/15", fillcolor="#A9DFBF")

    with dot.subgraph(name="cluster_feat") as sg:
        sg.attr(label="Feature Engineering", style="filled", fillcolor="#FEF9E7", color="#F39C12")
        sg.node("count", "Event Frequency\nCounts", fillcolor="#FAD7A0")
        sg.node("td", "Time-Delta\nStatistics", fillcolor="#FAD7A0")
        sg.node("card", "Cardinality\n+ Rare Flags", fillcolor="#FAD7A0")
        sg.node("ent", "Sequence\nEntropy", fillcolor="#FAD7A0")
        sg.node("feat_vec", "Feature\nMatrix", shape="cylinder", fillcolor="#F9E79F")

    with dot.subgraph(name="cluster_model") as sg:
        sg.attr(label="Modelling & Evaluation", style="filled", fillcolor="#FDEDEC", color="#E74C3C")
        sg.node("cv", "5-Fold\nStratified CV", fillcolor="#FADBD8")
        sg.node("search", "RandomizedSearchCV\n(hyperparameter tuning)", fillcolor="#FADBD8")
        sg.node("rf", "Random Forest\n(class_weight=balanced)", fillcolor="#EC7063", fontcolor="white")
        sg.node("metrics", "Accuracy / F1 /\nROC-AUC / CM", fillcolor="#FADBD8")

    dot.edge("gen", "raw")
    dot.edge("raw", "clean")
    dot.edge("clean", "split")
    dot.edge("split", "count")
    dot.edge("split", "td")
    dot.edge("split", "card")
    dot.edge("split", "ent")
    dot.edges([("count", "feat_vec"), ("td", "feat_vec"), ("card", "feat_vec"), ("ent", "feat_vec")])
    dot.edge("feat_vec", "cv")
    dot.edge("cv", "search")
    dot.edge("search", "rf")
    dot.edge("rf", "metrics")

    out = OUT_DIR / "pipeline"
    dot.render(str(out), cleanup=True)
    print(f"Saved {out}.png")

if __name__ == "__main__":
    main()
