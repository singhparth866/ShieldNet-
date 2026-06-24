from flask import Flask
from views import views

app = Flask(__name__)
app.register_blueprint(views, url_prefix="/")

if __name__ == '__main__':
    # Use a non-privileged port to avoid Windows socket permission issues on port 80
    # Bind to localhost by default for development
    app.run(host="127.0.0.1", port=5000, debug=True)