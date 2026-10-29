"""
ChronosHunt Launcher Script
Starts the DFIR Threat Hunter Console on port 8080.
"""

import uvicorn

if __name__ == "__main__":
    print("=" * 65)
    print("  CHRONOSHUNT - DFIR Threat Hunting & Timeline Reconstructor")
    print("  Console launching on: http://localhost:8080")
    print("  API Documentation at: http://localhost:8080/docs")
    print("=" * 65)
    uvicorn.run("app.main:app", host="0.0.0.0", port=8080, reload=True)
