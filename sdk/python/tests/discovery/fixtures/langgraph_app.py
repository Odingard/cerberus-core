"""Fixture: LangGraph StateGraph."""
from langgraph.graph import StateGraph

graph = StateGraph(dict)
graph.add_node("start", lambda s: s)
graph.set_entry_point("start")
