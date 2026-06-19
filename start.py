import os
import sys
from gunicorn.app.wsgiapp import run


def main():
    port = os.environ.get("PORT", "8000")
    sys.argv = [
        "gunicorn",
        "app:app",
        "--bind",
        f"0.0.0.0:{port}",
        "--workers",
        "2",
        "--threads",
        "4",
        "--timeout",
        "120",
    ]
    run()


if __name__ == "__main__":
    main()
