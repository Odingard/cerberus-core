"""Fixture: direct Anthropic client (unwrapped)."""
import anthropic

client = anthropic.Anthropic()


def chat(prompt: str) -> str:
    msg = client.messages.create(
        model="claude-4-sonnet",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
