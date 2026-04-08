"""
VSec API — Entry point

Usage:
    python -m vsec.api
    python -m vsec.api --host 0.0.0.0 --port 8000
"""
import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="VSec API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════╗
║                                                      ║
║   ██╗   ██╗███████╗███████╗ ██████╗                 ║
║   ██║   ██║██╔════╝██╔════╝██╔════╝                 ║
║   ██║   ██║███████╗█████╗  ██║                      ║
║   ╚██╗ ██╔╝╚════██║██╔══╝  ██║                      ║
║    ╚████╔╝ ███████║███████╗╚██████╗                 ║
║     ╚═══╝  ╚══════╝╚══════╝ ╚═════╝                 ║
║                                                      ║
║   AI-Powered Penetration Testing API                 ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

Server starting at: http://{args.host}:{args.port}
API Documentation:  http://{args.host}:{args.port}/docs
""")

    uvicorn.run(
        "vsec.api.routes:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
