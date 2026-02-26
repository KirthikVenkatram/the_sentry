import mcp
import mcp.server
import inspect

print(f"✅ MCP Version: {mcp.__version__}")
print(f"📂 MCP Location: {mcp.__file__}")

print("\n🔍 Inspecting mcp.server:")
print(dir(mcp.server))

try:
    from mcp.server.fastapi import FastMCP
    print("\n✅ SUCCESS: 'from mcp.server.fastapi import FastMCP' works!")
except ImportError:
    print("\n❌ FAILED: 'mcp.server.fastapi' not found.")
    
try:
    from mcp.server.fastmcp import FastMCP
    print("✅ FOUND IT: It moved to 'mcp.server.fastmcp'!")
except ImportError:
    pass

try:
    from mcp.fastmcp import FastMCP
    print("✅ FOUND IT: It moved to 'mcp.fastmcp'!")
except ImportError:
    pass