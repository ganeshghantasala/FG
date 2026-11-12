
from unittest.mock import patch
import app

cases = [
    (
        "Ordinary page",
        "https://example.com/",
        """
        <html>
        <head><title>Example</title></head>
        <body><h1>Welcome</h1><p>Example content.</p></body>
        </html>
        """,
    ),
    (
        "Suspicious login page",
        "https://example.com/login",
        """
        <html>
        <head><title>Account Login</title></head>
        <body>
        <h1>Login to your account</h1>
        <form action="https://collector.example.net/submit" method="post">
            <input type="password" name="password">
            <button type="submit">Sign in</button>
        </form>
        </body>
        </html>
        """,
    ),
]

for name, url, html in cases:
    with (
        patch("app.socket.gethostbyname", return_value="93.184.216.34"),
        patch("app.fetch_page", return_value=(url, html, 200)),
    ):
        result = app.analyze(url)

    print(f"\n=== {name} ===")
    print("Label:", result["label"])
    print("Final risk score:", result["score"], "%")
    print("ML phishing score:", result["ml"], "%")
    print("HTML risk:", result["html"], "%")
    print("Identity risk:", result["identity"], "%")
    print("Reasons:")
    for reason in result["reasons"]:
        print("-", reason)
