"""Interactive intelligence graph using QGraphicsView (PySide6)."""
from __future__ import annotations

import math
from typing import Any

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QBrush, QColor, QPen
    from PySide6.QtWidgets import (
        QGraphicsEllipseItem,
        QGraphicsLineItem,
        QGraphicsScene,
        QGraphicsTextItem,
        QGraphicsView,
        QVBoxLayout,
        QWidget,
        QLabel,
        QLineEdit,
        QHBoxLayout,
        QPushButton,
    )
    HAS_QT = True
except ImportError:
    HAS_QT = False


TYPE_COLORS = {
    "domain": "#39FF14",
    "ip": "#4FC3F7",
    "certificate": "#FFD54F",
    "asn": "#CE93D8",
    "finding": "#EF5350",
    "host": "#80CBC4",
    "interface": "#A5D6A7",
}


if HAS_QT:

    class NodeItem(QGraphicsEllipseItem):
        def __init__(self, node_id: str, label: str, ntype: str, x: float, y: float):
            super().__init__(-18, -18, 36, 36)
            self.node_id = node_id
            self.label = label
            self.ntype = ntype
            color = QColor(TYPE_COLORS.get(ntype, "#9aa0a6"))
            self.setBrush(QBrush(color))
            self.setPen(QPen(QColor("#111"), 1))
            self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable, True)
            self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable, True)
            self.setPos(x, y)
            self.text = QGraphicsTextItem(label[:24], self)
            self.text.setDefaultTextColor(QColor("#e8e8e8"))
            self.text.setPos(-20, 20)

    class GraphCanvas(QGraphicsView):
        node_selected = Signal(dict)

        def __init__(self):
            super().__init__()
            self.scene = QGraphicsScene(self)
            self.setScene(self.scene)
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
            self._nodes: dict[str, NodeItem] = {}
            self._raw: dict[str, Any] = {"nodes": [], "edges": []}

        def wheelEvent(self, event):  # noqa: N802
            factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
            self.scale(factor, factor)

        def load_graph(self, payload: dict[str, Any], filter_text: str = "") -> None:
            self.scene.clear()
            self._nodes.clear()
            self._raw = payload
            nodes = payload.get("nodes") or []
            edges = payload.get("edges") or []
            ft = filter_text.strip().lower()
            if ft:
                nodes = [n for n in nodes if ft in str(n.get("label", "")).lower() or ft in str(n.get("type", "")).lower()]
                ids = {n["id"] for n in nodes}
                edges = [e for e in edges if e.get("source") in ids and e.get("target") in ids]
            n = max(len(nodes), 1)
            for i, node in enumerate(nodes):
                ang = 2 * math.pi * i / n
                x, y = 220 * math.cos(ang), 220 * math.sin(ang)
                item = NodeItem(node["id"], str(node.get("label") or node["id"]), str(node.get("type") or ""), x, y)
                self.scene.addItem(item)
                self._nodes[node["id"]] = item
            for e in edges:
                a, b = self._nodes.get(e.get("source")), self._nodes.get(e.get("target"))
                if not a or not b:
                    continue
                conf = float(e.get("confidence") or 0.5)
                pen = QPen(QColor("#39FF14" if conf >= 0.75 else "#888888"))
                pen.setWidth(2 if conf >= 0.75 else 1)
                line = QGraphicsLineItem(a.pos().x(), a.pos().y(), b.pos().x(), b.pos().y())
                line.setPen(pen)
                line.setZValue(-1)
                self.scene.addItem(line)
            self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-80, -80, 80, 80))

        def selected_node_data(self) -> dict[str, Any] | None:
            for item in self.scene.selectedItems():
                if isinstance(item, NodeItem):
                    return {"id": item.node_id, "label": item.label, "type": item.ntype}
            return None

    class InteractiveGraphPage(QWidget):
        def __init__(self):
            super().__init__()
            from app.services.correlation import graph_payload

            self._payload_fn = graph_payload
            lay = QVBoxLayout(self)
            row = QHBoxLayout()
            self.filter = QLineEdit()
            self.filter.setPlaceholderText("Filter entities…")
            btn = QPushButton("Reload")
            btn.setObjectName("Primary")
            btn.clicked.connect(self.reload)
            row.addWidget(self.filter, 1)
            row.addWidget(btn)
            lay.addLayout(row)
            self.canvas = GraphCanvas()
            lay.addWidget(self.canvas, 1)
            self.info = QLabel("Select a node for details")
            self.info.setObjectName("Subtitle")
            lay.addWidget(self.info)
            self.canvas.scene.selectionChanged.connect(self._on_sel)

        def on_show(self):
            self.reload()

        def reload(self):
            data = self._payload_fn(limit=200)
            self.canvas.load_graph(data, self.filter.text())
            self.info.setText(f"Nodes={len(data.get('nodes') or [])} Edges={len(data.get('edges') or [])}")

        def _on_sel(self):
            d = self.canvas.selected_node_data()
            self.info.setText(str(d) if d else "Select a node for details")

else:

    class InteractiveGraphPage:  # type: ignore
        """Placeholder when PySide6 missing — logic tests use services only."""

        pass
