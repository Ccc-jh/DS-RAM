package partition

type Vertex struct {
	Addr string
}

type Graph struct {
	VertexSet map[Vertex]bool
	EdgeSet   map[Vertex][]Vertex
}

func (v *Vertex) ConstructVertex(s string) {
	v.Addr = s
}

func (g *Graph) AddVertex(v Vertex) {
	if g.VertexSet == nil {
		g.VertexSet = make(map[Vertex]bool)
	}
	g.VertexSet[v] = true
}

func (g *Graph) AddEdge(u, v Vertex) {

	if _, ok := g.VertexSet[u]; !ok {
		g.AddVertex(u)
	}
	if _, ok := g.VertexSet[v]; !ok {
		g.AddVertex(v)
	}
	if g.EdgeSet == nil {
		g.EdgeSet = make(map[Vertex][]Vertex)
	}
	g.EdgeSet[u] = append(g.EdgeSet[u], v)
	g.EdgeSet[v] = append(g.EdgeSet[v], u)
}

func (dst *Graph) CopyGraph(src Graph) {
	dst.VertexSet = make(map[Vertex]bool)
	for v := range src.VertexSet {
		dst.VertexSet[v] = true
	}
	if src.EdgeSet != nil {
		dst.EdgeSet = make(map[Vertex][]Vertex)
		for v := range src.VertexSet {
			dst.EdgeSet[v] = make([]Vertex, len(src.EdgeSet[v]))
			copy(dst.EdgeSet[v], src.EdgeSet[v])
		}
	}
}

func (g Graph) PrintGraph() {
	for v := range g.VertexSet {
		print(v.Addr, " ")
		print("edge:")
		for _, u := range g.EdgeSet[v] {
			print(" ", u.Addr, "\t")
		}
		println()
	}
	println()
}
