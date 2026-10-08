from tools.tool_registry import ToolRegistry


def fake_tool(value: str):
    return {
        "status": "success",
        "value": value,
    }


registry = ToolRegistry()

registry.register(
    name="fake_tool",
    description="Test tool for registry validation.",
    execute=fake_tool,
)

print()
print("======================================")
print(" TOOL REGISTRY TEST")
print("======================================")

print("Registered tools:")
print(registry.list_tools())

result = registry.execute(
    name="fake_tool",
    value="registry-working",
)

print("Execution result:")
print(result)

assert registry.has("fake_tool")
assert result["status"] == "success"
assert result["value"] == "registry-working"

print()
print("Tool registry test PASSED.")