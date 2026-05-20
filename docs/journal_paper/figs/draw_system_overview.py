"""System overview diagram for journal paper — full Purdue model mapping."""

from pathlib import Path

import graphviz

OUT_DIR = Path(__file__).parent


def main():
    dot = graphviz.Digraph(
        "system_overview",
        format="png",
        graph_attr={
            "dpi": "300",
            "rankdir": "TB",
            "fontname": "Helvetica",
            "fontsize": "10",
            "nodesep": "0.4",
            "ranksep": "0.6",
            "bgcolor": "white",
        },
        node_attr={"fontname": "Helvetica", "fontsize": "9"},
        edge_attr={"fontname": "Helvetica", "fontsize": "8"},
    )

    with dot.subgraph(name="cluster_l0") as sg:
        sg.attr(
            label="Level 0 — Field Devices", style="filled", fillcolor="#EBF5FB", color="#1A5276"
        )
        sg.node("plc1", "PLC/RTU\nUnit 1", shape="box", style="filled", fillcolor="#AED6F1")
        sg.node("plc2", "PLC/RTU\nUnit 2", shape="box", style="filled", fillcolor="#AED6F1")
        sg.node("sensor", "Smart\nSensors", shape="box", style="filled", fillcolor="#AED6F1")

    with dot.subgraph(name="cluster_l1") as sg:
        sg.attr(
            label="Level 1 — Basic Control", style="filled", fillcolor="#E9F7EF", color="#1E8449"
        )
        sg.node("rtu", "RTU-CTRL-03\n(Windows)", shape="box", style="filled", fillcolor="#A9DFBF")

    with dot.subgraph(name="cluster_l2") as sg:
        sg.attr(
            label="Level 2 — Supervisory Control",
            style="filled",
            fillcolor="#FEF9E7",
            color="#B7950B",
        )
        sg.node("hmi1", "SCADA-HMI-01\n(Windows)", shape="box", style="filled", fillcolor="#FAD7A0")
        sg.node("hmi2", "SCADA-HMI-02\n(Windows)", shape="box", style="filled", fillcolor="#FAD7A0")
        sg.node("eng", "eng_station\n(Windows)", shape="box", style="filled", fillcolor="#FAD7A0")

    with dot.subgraph(name="cluster_l3") as sg:
        sg.attr(
            label="Level 3 — Operations Management",
            style="filled",
            fillcolor="#FDEDEC",
            color="#922B21",
        )
        sg.node("hist", "historian\n(Windows)", shape="box", style="filled", fillcolor="#FADBD8")
        sg.node("dc", "Domain\nController", shape="box", style="filled", fillcolor="#FADBD8")

    with dot.subgraph(name="cluster_detect") as sg:
        sg.attr(label="Detection Layer", style="filled", fillcolor="#F5EEF8", color="#6C3483")
        sg.node(
            "winlog",
            "Windows\nEvent Log\nCollector",
            shape="cylinder",
            style="filled",
            fillcolor="#D7BDE2",
        )
        sg.node(
            "feat_eng",
            "Feature\nExtraction\nEngine",
            shape="diamond",
            style="filled",
            fillcolor="#C39BD3",
        )
        sg.node(
            "clf",
            "Random\nForest\nClassifier",
            shape="ellipse",
            style="filled",
            fillcolor="#A569BD",
            fontcolor="white",
        )
        sg.node(
            "siem",
            "SIEM /\nAlert",
            shape="doubleoctagon",
            style="filled",
            fillcolor="#6C3483",
            fontcolor="white",
        )

    dot.node(
        "attacker",
        "Adversary\n(APT)",
        shape="invtriangle",
        style="filled",
        fillcolor="#E74C3C",
        fontcolor="white",
        fontname="Helvetica",
        fontsize="9",
    )

    dot.edges([("plc1", "rtu"), ("plc2", "rtu"), ("sensor", "rtu")])
    dot.edges([("rtu", "hmi1"), ("rtu", "hmi2")])
    dot.edges([("hmi1", "hist"), ("hmi2", "hist"), ("eng", "dc")])
    dot.edge("attacker", "hmi1", label="lateral\nmovement", style="dashed", color="#E74C3C")
    dot.edge("hmi1", "winlog", label="audit\nevents")
    dot.edge("dc", "winlog")
    dot.edge("hist", "winlog")
    dot.edge("winlog", "feat_eng")
    dot.edge("feat_eng", "clf")
    dot.edge("clf", "siem", label="malicious")

    out = OUT_DIR / "system_overview"
    dot.render(str(out), cleanup=True)
    print(f"Saved {out}.png")


if __name__ == "__main__":
    main()
