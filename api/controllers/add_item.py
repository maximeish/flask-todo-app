from flask import Flask, jsonify, make_response


def add_item(item):
    response = make_response(
        jsonify({"items": ["item1", "item2", "item3", item]}),
        200,
    )
    response.headers["Content-Type"] = "application/json"
    return response
