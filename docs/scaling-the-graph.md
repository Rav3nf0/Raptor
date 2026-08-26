# Scaling the context graph

The [Security Context Graph](../README.md#-architecture) visualization in this repo is
tuned for the **demo dataset** (a few dozen nodes). It renders the whole graph because,
at that size, the whole graph *is* readable. On production volume — thousands of
entities, tens of thousands of alerts — rendering everything is the wrong design, for
two independent reasons. This doc covers where it breaks and how a real deployment
scopes it.

## Where "draw everything" breaks

**1. Performance.**
- The demo endpoint (`/api/memory/graph`) loads each collection with a fixed cap
  (`.to_list(500)`) and builds every node/edge in memory. On real volume that cap
  **silently truncates** to a non-representative slice — fine for a demo, wrong for an
  operator.
- The client force-simulation is **O(n²)** (every node repels every other, per frame).
  ~30 nodes is free; a few hundred gets sluggish; ~1,000+ will freeze the tab. The
  canvas also repaints every node, edge, and label each frame.

**2. Readability (the harder limit).**
Even with infinite compute, a few hundred nodes on one screen is an unreadable
*hairball*. This is a property of node-link diagrams in general, not of this
implementation — past ~150 nodes a full graph stops communicating anything.

## The production approach: draw a *query*, not the database

Operator-grade graph UIs never render the whole graph. They render a **scoped subset**,
computed server-side and small enough to stay both fast and legible:

- **Ego-graph** — "everything connected to *this* device/user, 1–2 hops out." The most
  useful mode: an analyst starts from one entity and sees its blast radius.
- **Time window** — last 24–48h by default.
- **Signal filter** — only alerts that escalated, or where the AI and the analyst
  **disagreed** (the ones worth looking at).
- **Top-N by risk**, always with a **"showing 150 of 8,432"** indicator — never a
  silent cap.

The backend does the filtering with indexed queries and aggregation; the client only
ever lays out the scoped result, so cost tracks what's on screen, not what's in the DB.

## If a large graph is genuinely required

When a scoped view still needs many hundreds of nodes:

- **Barnes-Hut** quadtree approximation for the repulsion step — O(n log n) instead of
  O(n²).
- **WebGL** rendering (e.g. a instanced-point renderer) instead of 2D canvas.
- **Server-side layout** precomputed and streamed, with **level-of-detail** clustering
  (collapse low-signal entities into aggregate nodes that expand on click).

In practice, scoping removes the need for most of these — the right graph for an analyst
is small by construction.

## Status in this repo

The open-source demo ships the **draw-everything** version deliberately: the synthetic
dataset is small, so it stays snappy and legible, and it shows the mechanism clearly.
The scoping layer above is the path to production volume, not something the demo needs.
