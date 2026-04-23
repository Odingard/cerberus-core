"""Fixture: direct OpenAI client."""
from openai import OpenAI

client = OpenAI(api_key="sk-test")


def chat(prompt: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
