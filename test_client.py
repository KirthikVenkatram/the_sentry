"""
Simple script to manually call your MCP tools and verify they work.
"""
import requests
import json

SERVER_URL = "http://127.0.0.1:8000/sse"  # FastMCP default

def call_tool(tool_name, arguments):
    # This is a mock of how an LLM would call your tool via HTTP
    # FastMCP exposes tools via JSON-RPC over HTTP/SSE, but for testing
    # we can often hit endpoints directly if configured, or just use python to import.
    
    # EASIER METHOD FOR TESTING: Import functions directly
    from mcp_server.tools import identity, network, elastic_integrations
    
    print(f"\n--- 🧪 Testing Tool: {tool_name} ---")
    try:
        if tool_name == "check_ip":
            result = network.get_ip_reputation(arguments['ip'])
        elif tool_name == "block_ip":
            result = network.block_ip(arguments['ip'])
        elif tool_name == "search_logs":
            result = elastic_integrations.search_logs(arguments['query'])
        else:
            result = "Unknown tool"
        
        print(f"✅ Result:\n{result}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    # Test 1: Search for the attacks happening right now
    call_tool("search_logs", {"query": "event.outcome:failure"})

    # Test 2: Check an IP reputation
    call_tool("check_ip", {"ip": "45.33.22.11"})
    
    # Test 3: Block that IP
    call_tool("block_ip", {"ip": "45.33.22.11"})