import sys

from trustvault.web import app, create_demo_accounts, setup_demo_viewers

__all__ = ["app"]


if __name__ == "__main__":
    if sys.argv[1:] == ["seed-demo"]:
        for role, credential in create_demo_accounts().items():
            print(f"{role}: {credential}")
    elif sys.argv[1:] == ["setup-demo-viewers"]:
        for user, credential in setup_demo_viewers().items():
            print(f"{user}: {credential}")
    else:
        print(
            "Run the web server with: uvicorn main:app --reload\n"
            "Seed a fresh demo: python main.py seed-demo\n"
            "Provision/reset four viewers: python main.py setup-demo-viewers"
        )
