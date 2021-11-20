# 2Do REST API

An API for a **to-do list application** in Postman. It provides endpoints for user authentication (login/signup), retrieveing user tasks, adding a new task, editing the task as well as
deleting a task.

> The API is built using Flask micro web framework, with a Postgresql database and hosted on Heroku deployment platform.

## Getting Started

- **Welcome route**

```
GET /
or
GET /api
```

This is a welcome route containing a welcome message

- **Auth routes**

1.

```
POST /api/signup
{
    "email": "your@email",
    "password": "your-password"
}
```

This is a sign up route to save a new user to the database.
After signing up you receive an auth token which can be used for the CRUD operations of the user's tasks

2.

```
POST /api/login
{
	"email": "your@email",
	"password: "your-password"
}
```

This is a login route for the new user to log in.
A token is also provided used for the CRUD operations of the user's tasks

3.

```
GET /api/status
```

Provide user's auth token as Bearer Token in Authorization header

- **Todo tasks routes**

_Route to get all logged in user's tasks_

1.

```
POST /api/get-all
```

Provide user's auth token as Bearer Token in Authorization header

_Route to add a new task for a logged in user_ 2.

```
POST /api/add-task
{
    "task_description": "my-task",
    "task_status": "incomplete"
}

```

and
Provide user's auth token as Bearer Token in Authorization header

_Route to update a task for a logged in user_ 3.

```
POST /api/update-task
{
	"task_id": <id>
	"task_description": "my-task",
	"task_status": "incomplete"
}
```

and
Provide user's auth token as Bearer Token in Authorization header.
**In this case you can provide only task_description or task_status as the field to update**

_Route to delete a ask for a logged in user_ 4.

```
POST /api/delete
{
    "task_id": <id>
}
```

and
Provide user's auth token as Bearer Token in Authorization header.
