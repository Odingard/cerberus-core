"""Fixture: LlamaIndex query engine."""
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents([])
query_engine = index.as_query_engine()
