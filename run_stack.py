import os
import sys
import time
import subprocess
import signal

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
GATEWAY_JAR = os.path.join(ROOT_DIR, "gateway", "target", "sentinel-gateway-1.0.0.jar")
ML_SERVICE_MAIN = os.path.join(ROOT_DIR, "ml-service", "main.py")
ADDON_SCRIPT = os.path.join(ROOT_DIR, "mitmproxy-addon", "sentinel_addon.py")
DASHBOARD_DIR = os.path.join(ROOT_DIR, "dashboard")

PYTHON_EXE = sys.executable
MITMDUMP_EXE = r"C:\Users\Anish Nilajkar\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe"
JAVA_EXE = "java"

processes = []

def log(msg, color="\033[96m"):
    reset = "\033[0m"
    print(f"{color}[Sentinel Stack Launcher] {msg}{reset}")

def cleanup(signum=None, frame=None):
    log("\nStopping all Sentinel-JVM services...", "\033[93m")
    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    log("All services stopped successfully.", "\033[92m")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def main():
    print("=" * 80)
    log("Starting Sentinel-JVM Full System Stack", "\033[94m")
    print("=" * 80)

    # 1. Start Python ML Anomaly Service
    log("1/4 Launching ML Anomaly Service (FastAPI) on http://localhost:5000 ...", "\033[96m")
    ml_env = os.environ.copy()
    ml_proc = subprocess.Popen(
        [PYTHON_EXE, "main.py"],
        cwd=os.path.join(ROOT_DIR, "ml-service"),
        env=ml_env
    )
    processes.append(ml_proc)
    time.sleep(2)

    # 2. Start Spring Boot Inspection Gateway
    log("2/4 Launching Inspection Gateway (Java 21) on http://localhost:8080 ...", "\033[96m")
    gw_env = os.environ.copy()
    gw_env["SPRING_DATA_MONGODB_URI"] = "mongodb+srv://anishsnilajkar_db_user:pubg1234@cluster0.tkv4bqk.mongodb.net/sentinel_db?retryWrites=true&w=majority"
    gw_env["ML_SERVICE_URL"] = "http://localhost:5000"
    
    gw_proc = subprocess.Popen(
        [JAVA_EXE, "-jar", GATEWAY_JAR],
        cwd=os.path.join(ROOT_DIR, "gateway"),
        env=gw_env
    )
    processes.append(gw_proc)
    time.sleep(3)

    # 3. Start mitmproxy Interceptor Addon
    log("3/4 Launching mitmproxy Interceptor Addon on port 8082 ...", "\033[96m")
    proxy_env = os.environ.copy()
    proxy_env["SENTINEL_GATEWAY_URL"] = "http://localhost:8080/api/inspect"
    
    proxy_cmd = [MITMDUMP_EXE, "-s", ADDON_SCRIPT, "--listen-port", "8082"] if os.path.exists(MITMDUMP_EXE) else [PYTHON_EXE, "-m", "mitmproxy.tools.main", "mitmdump", "-s", ADDON_SCRIPT, "--listen-port", "8082"]
    
    proxy_proc = subprocess.Popen(
        proxy_cmd,
        cwd=os.path.join(ROOT_DIR, "mitmproxy-addon"),
        env=proxy_env
    )
    processes.append(proxy_proc)
    time.sleep(2)

    # 4. Start React Governance Dashboard
    log("4/4 Launching Governance Dashboard (Vite + React) on http://localhost:3000 ...", "\033[96m")
    dash_cmd = "npm run dev"
    dash_proc = subprocess.Popen(
        dash_cmd,
        cwd=DASHBOARD_DIR,
        shell=True
    )
    processes.append(dash_proc)

    print("\n" + "=" * 80)
    log("ALL SENTINEL-JVM SERVICES ARE LIVE & RUNNING!", "\033[92m")
    log(" - Dashboard:   http://localhost:3000", "\033[97m")
    log(" - Gateway API: http://localhost:8080", "\033[97m")
    log(" - ML Service:  http://localhost:5000", "\033[97m")
    log(" - Proxy:       http://localhost:8082", "\033[97m")
    log("Press Ctrl+C in this terminal to stop all services at once.", "\033[93m")
    print("=" * 80 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
