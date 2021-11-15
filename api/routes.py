from flask import Flask, jsonify, make_response

from controllers.add_item import add_item

app = Flask(__name__)

# welcome


@app.route("/")
def hello():
    response = make_response(
        jsonify({"message": "holla"}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response


# fetch items
@app.route("/fetch")
def fetch_items():
    response = make_response(
        jsonify({
            "items": [{
                "id": 1,
                "name": "item1"
            }, {
                "id": 2,
                "name": "item2"
            }]
        }),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response


# add item
@app.route("/add<item>")
def add_item(item):
    response = make_response(
        jsonify({"items": ["item1", "item2", "item3", item]}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response


# update item
@app.route("/update<int:id>&<state>")
def update_item(id, state):
    response = make_response(
        jsonify({"message": id}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response


# delete item
@app.route("/delete<int:id>")
def delete_item(id):
    response = make_response(
        jsonify({"message": id}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response


# app.add_url_rule("/add<name>", "add", add_item)
# app.add_url_rule("/fetch", "fetch", add_item)
# app.add_url_rule("/update", "update", add_item)
# app.add_url_rule("/delete", "delete", add_item)


# 404 Not Found
@app.errorhandler(404)
def not_found(error):
    response = make_response(
        jsonify({"message": "Not Found"}),
        404,
    )
    response.headers["Content-Type"] = "application/json"
    return response
