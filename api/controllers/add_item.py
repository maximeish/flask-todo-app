from flask import Flask, jsonify, make_response


def add_item(name):
    response = make_response(
        jsonify({"message": "I will add an item", "name": name}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response
