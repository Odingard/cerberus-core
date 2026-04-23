"""Fixture: AutoGen multi-agent team."""
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(name="assistant")
user = UserProxyAgent(name="user")
