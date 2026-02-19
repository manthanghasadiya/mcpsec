import subprocess
import sys
import threading
import time

def run_test():
    print("\n--- Test 6: cmd /c shell=False ---")
    
    cmd = ["cmd", "/c", "npx", "-y", "@modelcontextprotocol/server-everything"]
    print(f"Executing: {cmd}")
    
    try:
        proc = subprocess.Popen(
            cmd,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        def read_stream(stream, name):
            for line in stream:
                print(f"[{name}] {line.strip()}")
                
        t1 = threading.Thread(target=read_stream, args=(proc.stdout, "stdout"))
        t1.start()
        t2 = threading.Thread(target=read_stream, args=(proc.stderr, "stderr"))
        t2.start()
        
        # Send
        time.sleep(2)
        print("Writing to stdin...")
        payload = '{"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}}'
        content_len = len(payload.encode('utf-8'))
        msg = f"Content-Length: {content_len}\r\n\r\n{payload}"
        
        proc.stdin.write(msg)
        proc.stdin.flush()
        print(f"Written to stdin.")
            
        time.sleep(5)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"Process error: {e}")

if __name__ == "__main__":
    run_test()
