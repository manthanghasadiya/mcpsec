import subprocess
import sys
import threading
import time

def run_test():
    print("\n--- Test 5: Simple Echo Python ---")
    
    cmd = [sys.executable, "tests/simple_echo.py"]
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
        time.sleep(1)
        print("Writing to stdin...")
        msg = "Hello World\n"
        proc.stdin.write(msg)
        proc.stdin.flush()
        print(f"Written: {msg.strip()}")
            
        time.sleep(2)
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
