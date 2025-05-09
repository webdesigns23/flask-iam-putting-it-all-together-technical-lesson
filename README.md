# Technical Lesson: Putting it all Together - Flask IAM API

## Introduction

Over the past few lessons, you’ve built the individual pieces of a secure identity
and access management (IAM) system—handling sessions, cookies, authentication,
authorization, and password protection. Now it’s time to combine all of those elements
into a single, full-featured Flask API.

In this lesson, you’ll build a complete user-posting application that supports sign up,
login, session management, and protected resource access. You’ll implement secure
password hashing, enforce authorization rules to prevent unauthorized deletions or
edits, and restrict route access using Flask’s @before_request lifecycle hook.

This lesson mirrors a real-world use case: a multi-user platform with account registration
and role-based behavior. You’ll also apply relational database modeling to connect users
and their posts, and return nested data via Marshmallow schemas.

By the end of this lesson, you’ll have built a fully operational backend authentication
and authorization system—laying the groundwork for any project that requires secure user
login, session handling, and content ownership.

## Tools & Resources

- [GitHub Repo](https://github.com/learn-co-curriculum/flask-iam-putting-it-all-together-technical-lesson)
- [API - Flask: `class flask.session`](https://flask.palletsprojects.com/en/2.2.x/api/#flask.session)
- [User's Guide - Flask RESTful](https://flask-restful.readthedocs.io/en/latest/)
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/en/1.0.1/)

## Set Up

As with other lessons in this section, there is some starter code in place for a
Flask API backend. To get set up, run:

```bash
pipenv install && pipenv shell
cd server
```

You can run the Flask server with:

```bash
python app.py
```

## Instructions

### Task 1: Define the Problem

You’ve already learned how to register users, hash passwords, authenticate credentials, and restrict access to resources using sessions. Now, you need to build a complete, secure backend that brings all those elements together in a single Flask API.

This API must:
* Let users sign up with a unique username and password (securely hashed).
* Allow users to log in and begin a session.
* Maintain login state across page reloads and route changes via Flask’s session cookie.
* Enable logged-in users to create and view posts.
* Restrict post creation, deletion, and viewing to authenticated users only.
* Ensure that only the owner of a post can delete it.
* Block unauthenticated users from accessing protected routes (like /posts) using Flask’s @before_request hook.

### Task 2: Determine the Design

To solve the problem, you’ll design a Flask API that implements the following core components:

* Authentication Layer
    * Use Flask-Bcrypt to hash passwords during sign up and verify them during login.
    * Store user sessions using Flask’s session object and an encrypted cookie.

* Authorization Checks
    * Use @before_request to protect routes globally.
    * Check if session['user_id'] exists before allowing access to authenticated routes.
    * Verify ownership of posts by comparing session['user_id'] to post.user_id before allowing deletion.

* Relational Data Models
    * Create User and Post models with a one-to-many relationship (a user has many posts).
    * Enforce constraints: unique usernames, post content ≤ 400 characters, content required.

* Routes and Endpoints
    * POST `/signup`: Create a new user and log them in.
    * POST `/login`: Authenticate and log in a user.
    * DELETE `/logout`: Log out the current user.
    * GET `/check_session`: Verify login state.
    * GET `/posts`: Return all posts (only for authenticated users).
    * POST `/posts`: Create a new post tied to the logged-in user.
    * DELETE `/posts/<id>`: Allow deletion only if the post belongs to the logged-in user.

* Error Handling and Edge Cases
    * Return 401 Unauthorized if a user is not logged in.
    * Return 403 Forbidden if a user tries to delete a post they don’t own.
    * Return 422 Unprocessable Entity if a signup attempt fails due to duplicate usernames or invalid data.

This design gives you a full-featured Flask IAM backend that’s secure, testable, and scalable for future features like roles, comments, or tokens.

### Task 3: Develop, Test, and Refine the Code

#### Step 1: Build the Models

Let's start with the User model. In models.py, build the User class:

```python
class User(db.Model):
    __tablename__ = 'users'
```

Let's add columns for id, username, and password_hash along with a simple `__repr__` method:

```python
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String)

    def __repr__(self):
        return f'<User {self.username}>'
```

Next let's add our auth methods:

```python
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String)

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'
```

Then, let's build out the Post model:

```python
class Post(db.Model):
    __tablename__ = 'posts'
```

Let's add columns for id and content along with a `__repr__` method:

```python
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String)

    def __repr__(self):
        return f'<Post {self.id}: {self.content}>'
```

Finally let's establish the relationship between our tables. 

On Post, add a foreign key and the belongs_to:

```python
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates="posts")

    def __repr__(self):
        return f'<Post {self.id}: {self.content}>'
```

On User, add the has many relationship:

```python
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    _password_hash = db.Column(db.String)

    posts = db.relationship('Post', back_populates='user')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'
```


#### Step 2: Add Validations and Serialization to Models

Next, we'll add some contraints to our models.

In User, we need to ensure all users have a username and that they are unique in order
for our auth flow to work properly.

```python
username = db.Column(db.String, unique=True, nullable=False)
```

For Post, we'll set a contraint that requires content to be present and 400 characters
or less:

```python
class Post(db.Model):
    __tablename__ = 'posts'
    __table_args__ = (
        db.CheckConstraint('length(content) <= 400'),
    )

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String, nullable=False)
```

Finally, let's create Schemas for both models so we can easily serialize:

```python
class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()

    posts = fields.List(fields.Nested(lambda: PostSchema(exclude=("user",))))

class PostSchema(Schema):
    id = fields.Int()
    content = fields.String()

    user = fields.Nested(UserSchema(exclude=("posts",)))
```

#### Step 3: Migrate and Update the Database

Run the migrations after creating your models. You'll need to run
`flask db init` before running `flask db migrate -m "initial migration"` and
`flask db upgrade head`.

#### Step 4: Verify your Code

Use flask shell to create some Users and Posts. Assign posts to users to verify the
relationships are set up properly.

#### Step 5: Sign Up Route

Create the sign up route and establish the user object.

```python
class Signup(Resource):
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User(
            username=username
        )
        user.password_hash = password
```

Next we need to save the user to the database if they are valid. If not, we'll want to return an error.

One way we can do this with a try/except block:

```python
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return UserSchema().dump(user), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422
```

Finally, add the route to the API:

```python
api.add_resource(Signup, '/signup', endpoint='signup')
```

#### Step 6: Check Session Route

Create the /check_session route.

```python
class CheckSession(Resource):
    def get(self):

        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return UserSchema().dump(user), 200

        return {}, 401
```

Add the route to the API:

```python
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
```

#### Step 7: Login Route

Build out the /login route.

```python
class Login(Resource):
    def post(self):

        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        return {'error': '401 Unauthorized'}, 401
```

Add the route to the API:

```python
api.add_resource(Login, '/login', endpoint='login')
```

#### Step 8: Logout Route

Build the /logout route.

```python
class Logout(Resource):
    def delete(self):

        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {}, 401
```

Add the route to the API:

```python
api.add_resource(Logout, '/logout', endpoint='logout')
```

#### Step 9: Post List Feature

Build out the GET /posts route.

```python
class PostIndex(Resource):
    def get(self):
        posts = [PostSchema().dump(post) for post in Post.query.all()]

        return posts, 200
```

Add the route to the API:

```python
api.add_resource(PostIndex, '/posts', endpoint='posts')
```

#### Step 10: Post Creation Feature

Build out the POST /posts route. Be sure to assign the created post to a logged in user.

```python
def post(self):
    request_json = request.get_json()

    post = Post(
        content=request_json.get('content'),
        user_id=session['user_id']
    )

    try:
        db.session.add(post)
        db.session.commit()
        return PostSchema().dump(post), 201

    except IntegrityError:
        return {'error': '422 Unprocessable Entity'}, 422
```

#### Step 11: Post Deletion Feature

Build out the DELETE `/posts/<id>` route. We'll want to verify the post is owned by
the currently logged-in user before deleting.

```python
class Post(Resource):
    def delete(self, id):
        post = Post.query.filter(Post.id == id).first()

        if post.user_id == session['user_id']:
            db.session.delete(post)
            db.session.commit()
            return {}, 204
        else:
            return {'error': '403 Forbidden'}, 403
```

Add the route to the API:

```python
api.add_resource(Post, '/post/<int:id>', , endpoint='post')
```

#### Step 12: Protect Routes

We want to protect our /posts routes to ensure users can only access them when logged in.

Let's add a before request at the top of app.py after the imports:

```python
# imports

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

# routes
```

Here we created a list of routes that should not be protected. Then we chack if the current route
is not in that list and the user is not authenticated, then we return a 401.

#### Step 13: Verify and Refine your Code

Final Solution:

```python
# models.py
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)

    posts = db.relationship('Post', back_populates='user')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    __tablename__ = 'posts'
    __table_args__ = (
        db.CheckConstraint('length(content) <= 400'),
    )

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String, nullable=False)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates="posts")

    def __repr__(self):
        return f'<Post {self.id}: {self.content}>'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()

    posts = fields.List(fields.Nested(lambda: PostSchema(exclude=("user",))))

class PostSchema(Schema):
    id = fields.Int()
    content = fields.String()

    user = fields.Nested(UserSchema(exclude=("posts",)))
```

```python
# app.py
#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Post, UserSchema, PostSchema

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

class Signup(Resource):
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User(
            username=username
        )
        user.password_hash = password
        
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return UserSchema().dump(user), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):

        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return UserSchema().dump(user), 200

        return {}, 401

class Login(Resource):
    def post(self):

        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):

        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {}, 401

class PostIndex(Resource):
    def get(self):
        posts = [PostSchema().dump(r) for r in Post.query.all()]

        return posts, 200

    def post(self):
        request_json = request.get_json()

        post = Post(
            content=request_json.get('content'),
            user_id=session['user_id']
        )

        try:
            db.session.add(post)
            db.session.commit()
            return PostSchema().dump(post), 201

        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

class Post(Resource):
    def delete(self, id):
        post = Post.query.filter(Post.id == id).first()

        if post.user_id == session['user_id']:
            db.session.delete(post)
            db.session.commit()
            return {}, 204
        else:
            return {'error': '403 Forbidden'}, 403

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(PostIndex, '/posts', endpoint='posts')
api.add_resource(Post, '/posts/<int:id>', endpoint='post')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
```

#### Step 14: Commit and Push Git History

* Commit and push your code:

```bash
git add .
git commit -m "final solution"
git push
```

* If you created a separate feature branch, remember to open a PR on main and merge.

### Task 4: Document and Maintain

Best Practice documentation steps:
* Add comments to the code to explain purpose and logic, clarifying intent and functionality of your code to other developers.
* Update README text to reflect the functionality of the application following https://makeareadme.com. 
  * Add screenshot of completed work included in Markdown in README.
* Delete any stale branches on GitHub
* Remove unnecessary/commented out code
* If needed, update git ignore to remove sensitive data

## Considerations

### All Security Layers Must Work Together

IAM systems are only as strong as their weakest link. Storing secure password
hashes is critical—but so is preventing unauthorized access to protected
resources. Make sure passwords, sessions, and route protection all work together
consistently.

### Always Check for Ownership

It’s not enough to check if a user is logged in. You must also check that they
own the resource before allowing edits or deletions. For example, only the user
who created a post should be allowed to delete it.

### Protect Your Routes with Before Hooks

Use Flask’s @before_request hook to prevent unauthorized users from reaching
sensitive routes. But make sure to exclude public or auth-related routes like
/login and /signup, or you’ll block access to them too.

### Nested Relationships Can Get Tricky

Be careful when serializing relationships with Marshmallow. Avoid circular references
by excluding fields like user.posts when serializing posts, and vice versa.

### Handle Unique Constraints Gracefully

Username uniqueness is enforced at the database level, but it's your job to catch
and handle IntegrityErrors in the signup flow. Return a clear 422 error instead of
letting the app crash.

### Modular Structure Prevents Circular Imports

As your app grows, make sure to isolate configuration logic (like instantiating
bcrypt, db, or app) in a shared file like config.py to avoid circular dependencies
between models.py and app.py.