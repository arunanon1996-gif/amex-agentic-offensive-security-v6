from tools.register_tools import build_tool_registry


registry = build_tool_registry()

print()
print("======================================")
print(" REAL TOOL REGISTRY TEST")
print("======================================")

print("Registered tools:")

for tool in registry.list_tools():
    print(f"- {tool['name']}: {tool['description']}")

assert registry.has("nmap")
assert registry.has("http_probe")

print()
print("Nmap registered:", registry.has("nmap"))
print("HTTP probe registered:", registry.has("http_probe"))

print()
print("Real tool registry test PASSED.")