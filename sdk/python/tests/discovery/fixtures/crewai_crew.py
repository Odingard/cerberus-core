"""Fixture: CrewAI crew — wrapped by Cerberus."""
from cerberus_ai import Cerberus
from crewai import Agent, Crew

cerberus = Cerberus()

analyst = Agent(role="analyst", goal="analyse", backstory="x")
crew = Crew(agents=[analyst])
