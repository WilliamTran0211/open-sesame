import argparse

import uvicorn


def run(https_on: bool) -> None:
    if https_on:
        uvicorn.run(
            "app.main:app",
            host="localhost",
            port=8000,
            ssl_keyfile="./localhost-key.pem",
            ssl_certfile="./localhost.pem",
            reload=True,
        )
    else:
        uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Open Sesame API server")
    parser.add_argument("--https", action="store_true", help="Serve over HTTPS using the local dev cert")
    args = parser.parse_args()

    run(args.https)
