package consequence

import (
	"fmt"
	"strconv"
	"strings"
)

type edge struct {
	weight float64
	height int64
	time   int64
}

// Graph holds node and edge data.
type Graph struct {
	index map[string]uint32
	nodes map[uint32]string
	edges map[uint32]map[uint32]*edge
}

// NewGraph initializes and returns a new graph.
func NewGraph() *Graph {
	return &Graph{
		edges: make(map[uint32](map[uint32]*edge)),
		nodes: make(map[uint32]string),
		index: make(map[string]uint32),
	}
}

// Link creates a weighted edge between a source-target node pair.
// If the edge already exists, the weight is incremented.
func (graph *Graph) Link(src, tgt string, weight float64, height int64, time int64) float64 {
	source := pad44(src)
	target := pad44(tgt)

	if _, ok := graph.index[source]; !ok {
		index := uint32(len(graph.index))
		graph.index[source] = index
		graph.nodes[index] = source
	}

	if _, ok := graph.index[target]; !ok {
		index := uint32(len(graph.index))
		graph.index[target] = index
		graph.nodes[index] = target
	}

	sIndex := graph.index[source]
	tIndex := graph.index[target]

	if _, ok := graph.edges[sIndex]; !ok {
		graph.edges[sIndex] = map[uint32]*edge{}
	}

	if _, ok := graph.edges[sIndex][tIndex]; !ok {
		graph.edges[sIndex][tIndex] = &edge{}
	}
	graph.edges[sIndex][tIndex].weight += weight
	graph.edges[sIndex][tIndex].height = height
	graph.edges[sIndex][tIndex].time = time

	return weight
}

func (g *Graph) ToDOT(pubKey string, states map[string]*KeyState) string {

	pkIndex := g.index[pubKey] //defaults to zero- the root

	var builder strings.Builder
	builder.WriteString("digraph G {\n")

	includedNodes := []uint32{}

	for from, edge := range g.edges {
		for to, e := range edge {
			if (from == pkIndex || to == pkIndex) && e.weight > 0 {

				builder.WriteString(fmt.Sprintf(
					"  \"%d\" -> \"%d\" [weight=\"%f\", height=\"%d\", time=\"%d\"];\n",
					from, to, e.weight, e.height, e.time,
				))

				if !containsInt(includedNodes, from) {
					includedNodes = append(includedNodes, from)
				}

				if !containsInt(includedNodes, to) {
					includedNodes = append(includedNodes, to)
				}
			}
		}
	}

	// Add nodes with ranks
	for _, id := range includedNodes {
		pubkey := g.nodes[id]
		label := fmt.Sprintf("%.*s", 12, strings.TrimRight(pubkey, "0="))
		memo := ""
		locale := ""
		namespace := ""

		if ok, locl, _ := localeFromPubKey(pubkey); ok {
			locale = locl		
		}

		if st, ok := states[pubkey]; ok {
			memo = st.memo
			namespace = st.namespace

			if st.label != "" {
				label = st.label
			}

			if st.time != 0 {
				label = label + "/+" + strconv.Itoa(int(st.revision)) + " (" + timeAgo(st.time) + ") "
			}			
		}
		

		builder.WriteString(fmt.Sprintf(
			"  \"%d\" [label=\"%s\", pubkey=\"%s\", memo=\"%s\", locale=\"%s\", namespace=\"%s\"];\n",
			id, label, pubkey, memo, locale, namespace,
		))
	}

	builder.WriteString("}\n")
	return builder.String()
}

func containsInt(slice []uint32, value uint32) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// Checks for relationship to prevent cycles.
func (g *Graph) IsParentDescendant(parent, descendant string) bool {
	parentIndex, pok := g.index[parent]
	descendantIndex, dok := g.index[descendant]

	if !pok || !dok {
		return false
	}

	if parentIndex == 0 || descendantIndex == 0 {
		return false
	}

	visited := make(map[uint32]bool)
	return g.dfs(parentIndex, descendantIndex, visited)
}

func (g *Graph) dfs(current, target uint32, visited map[uint32]bool) bool {
	if current == target {
		return true
	}

	visited[current] = true

	for edge := range g.edges[current] {
		if edge == 0 { // Skip the root node
			continue
		}

		if !visited[edge] {
			if g.dfs(edge, target, visited) {
				return true
			}
		}
	}

	return false
}

// Reset clears all the current graph data.
func (graph *Graph) Reset() {
	graph.edges = make(map[uint32](map[uint32]*edge))
	graph.nodes = make(map[uint32]string)
	graph.index = make(map[string]uint32)
}
