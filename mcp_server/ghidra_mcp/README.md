## this mcp is from [here](https://github.com/bethington/ghidra-mcp)



* `git clone https://github.com/bethington/ghidra-mcp`
* `cd ghidra-mcp`
* `docker build -t ghidra-mcp-headless:latest -f docker/Dockerfile .`
* `mcp.json`

```

{

 "ghidra-mcp"
   "command": "python3
   "args": \["path\\\\to\\\\bridge\_mcp\_ghidra.py","--transport","stdio","--no-lazy"
   "env"
     "GHIDRA\_DEBUGGER\_URL":"http://127.0.0.1:8099
     "GHIDRA\_MCP\_URL":"http://127.0.0.1:8089
     "PYTHONIOENCODING":"utf-8
 }

}

```



### NB

* For binding on 0.0.0.0 , the use of a AUTH\_TOKEN variable is needed. THIS TOKEN IS HARDCODED IN THE DOCKER-COMPOSE AND THE BRIDGE\_MCP\_GHIDRA\_PY. (for now)
