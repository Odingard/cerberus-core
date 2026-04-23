"""Fixture: LangChain agent with two tools."""
from langchain_openai import ChatOpenAI
from langchain_core.tools import Tool

llm = ChatOpenAI(model="gpt-4o")

search = Tool(name="search_kb", func=lambda q: q, description="Search the KB")
email = Tool(name="send_email", func=lambda to, body: None, description="Send an email")
