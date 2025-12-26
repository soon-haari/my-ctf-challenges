from flask import Flask, request, render_template, abort
import random, json, logging

logging.basicConfig(level=logging.DEBUG)

from datetime import datetime, timezone, timedelta
KST = timezone(timedelta(hours=9))
T1 = datetime(2025, 12, 24, 10, 0, tzinfo=KST)
T2 = T1 + timedelta(days=2)
now = lambda: datetime.now(KST)

class NoStaticFilter(logging.Filter):
    def filter(self, record):
        return "/static/" not in record.getMessage()

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.addFilter(NoStaticFilter())

N = 10**7

@app.route("/load", methods=["GET"])
def load():
    try:
        with open("best.json", "r") as f:
            return json.load(f)
    except:
        save({"score": "-"})
        return load()

def save(best):
    with open("best.json", "w") as f:
        json.dump(best, f)

@app.route("/", methods=["GET", "POST"])
def challenge():
    if now() < T1:
        return render_template("ready.html", t=T1.isoformat())
    if now() >= T2:
        return render_template("end.html")
    if request.method == "POST":
        try:
            seed = int(request.form.get("input"), 16)
            score = random.Random(seed).getrandbits(N).bit_count()
        except:
            return "Try again!", 403

        inp = f"{score}: {hex(seed)}"
        if username := request.form.get("username"):
            inp = f"{username}: " + inp
            
            prev = load()["score"]
            if prev == "-" or prev > score:
                save({"score": score, "username": username})
        log.info(inp)

        msg = f"{score = }"
        if score < 0.16 * N:
            with open("flag.txt", "r") as f:
                msg += "\n\n" + f.read()
        return msg

    return render_template("index.html", t=T2.isoformat())

@app.route("/source")
def source():
    if now() < T1:
        abort(404)
    with open(__file__, "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
