#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import jinja2
import os
import re
from google.appengine.ext import db
from string import letters
import random
import hashlib
import hmac
import utils

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str(
            "post.html",
            p=self,
            user_id=utils.get_userID(self))

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


class Comment(db.Model):
    post_id = db.StringProperty()
    content = db.TextProperty(required=True)
    user_name = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)


class Likes(db.Model):
    post_id = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = utils.make_pw_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and utils.valid_pw(name, pw, u.pw_hash):
            return u


def get_username(self):
    if utils.is_loggedIn(self):
        key = db.Key.from_path('User', long(utils.get_userID(self)))
        user = db.get(key)
        user_name = user.name
        return user_name


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        #params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainHandler(Handler):

    def get(self):
        if utils.is_loggedIn(self):
            posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
            comments = db.GqlQuery("SELECT * FROM Comment")
            likes = db.GqlQuery("SELECT * FROM Likes")
            self.render("front.html", is_logged_in=True, posts=posts,
                        comments=comments, user_id=utils.get_userID(self),
                        likes=likes)
        else:
            self.redirect('/welcome')

    def post(self):
        if utils.is_loggedIn(self):
            content = self.request.get('content')
            post_id = self.request.get('post-id')
            like = self.request.get('like')
            unlike = self.request.get('unlike')
            del_post = self.request.get('delete-post')
            del_comment = self.request.get('delete-comment')
            post_userid = self.request.get('post-userid')
            comment_userid = self.request.get('comment-userid')
            comment_id = self.request.get('comment-id')

            if content:
                comment = Comment(
                    post_id=post_id,
                    content=content,
                    user_name=get_username(self),
                    user_id=utils.get_userID(self))
                comment.put()
                self.redirect('/blog')
            elif like and post_userid != utils.get_userID(self):
                like = Likes(post_id=post_id, user_id=utils.get_userID(self))
                like.put()
                self.redirect('/blog')
            elif unlike and post_userid != utils.get_userID(self):
                likes = db.GqlQuery(
                    "SELECT * FROM Likes WHERE post_id =:1", post_id)
                for like in likes:
                    if like.user_id == utils.get_userID(self):
                        like.delete()
                self.redirect('/blog')

            elif del_post and post_userid == utils.get_userID(self):
                key = db.Key.from_path('Post', long(post_id))
                old_post = db.get(key)
                comments = db.GqlQuery(
                    "SELECT * FROM Comment WHERE post_id =:1", post_id)
                likes = db.GqlQuery(
                    "SELECT * FROM Likes WHERE post_id =:1", post_id)
                if old_post:
                    db.delete(comments)
                    db.delete(likes)
                    db.delete(old_post)
                self.redirect('/blog')
            elif del_comment and comment_userid == utils.get_userID(self):
                key = db.Key.from_path('Comment', long(comment_id))
                comment = db.get(key)
                if comment:
                    db.delete(comment)
                self.redirect('/blog')

            else:
                self.response.out.write(post_userid)


    def set_secure_cookie(self, name, val, remember):
        cookie_val = utils.create_secure_cookie_val(val)
        if remember:
            self.response.headers.add_header('Set-Cookie',
                                             '%s=%s; Expires=Wed, '
                                             '4 Nov 2020 00:00:01 '
                                             'GMT Path=/' % (
                                                 name, cookie_val))
        else:
            self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utils.check_cookie_val(cookie_val)

    def login(self, user, remember=False):
        self.set_secure_cookie('user_id', str(user.key().id()), remember)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class EditComment(Handler):

    def get(self):
        self.render("edit-comment.html")

    def post(self):
        if utils.is_loggedIn(self):
            edit_comment = self.request.get('edit-comment')
            comment_userid = self.request.get('comment-userid')
            comment_id = self.request.get('comment-id')
            comment_editted = self.request.get('comment_editted')
            commentedit_userid = self.request.get('commentedit_userid')
            commentedit_key = self.request.get('commentedit_key')
            comment_content = self.request.get('comment_content')
            if edit_comment and comment_userid == utils.get_userID(self):
                key = db.Key.from_path('Comment', long(comment_id))
                comment = db.get(key)
                if comment:
                    self.render(
                        "edit-comment.html",
                        comment=comment.content,
                        is_logged_in=True,
                        comment_userid=comment_userid,
                        key=key)

            elif comment_editted and commentedit_userid == utils.get_userID(self):
                comment = db.get(commentedit_key)
                if comment and comment_content:
                    comment.content = comment_content
                    comment.put()
                    self.redirect('/blog')
                else:
                    self.render(
                        "edit-comment.html",
                        comment=comment.content,
                        is_logged_in=True,
                        comment_userid=commentedit_userid,
                        key=commentedit_key,
                        error="comment can't be empty")
            else:
                self.response.out.write("in else")

class EditPost(Handler):

    def get(self):
        self.render("edit-post.html")

    def post(self):
        if utils.is_loggedIn(self):
            post_userid = self.request.get('post-userid')
            post_id = self.request.get('post-id')
            post_editted = self.request.get('post-editted')
            posteditted_userid = self.request.get('post_userid')
            post_subject = self.request.get('post_subject')
            post_content = self.request.get('post_content')
            post_key = self.request.get('key')
            edit_post = self.request.get('edit-post')

            if edit_post and post_userid == utils.get_userID(self):
                key = db.Key.from_path('Post', long(post_id))
                post = db.get(key)
                if post:
                    self.render(
                        "edit-post.html",
                        subject=post.subject,
                        content=post.content,
                        is_logged_in=True,
                        post_userid=post_userid,
                        key=key)
            elif post_editted and posteditted_userid == utils.get_userID(self):
                post = db.get(post_key)
                if post and post_subject and post_content:
                    post.subject = post_subject
                    post.content = post_content
                    post.put()
                    self.redirect('/blog')
                else:
                    self.render(
                        "edit-post.html",
                        subject=post_subject,
                        content=post_content,
                        is_logged_in=True,
                        post_userid=posteditted_userid,
                        key=post_key,
                        error="something is missing!")
        else:
            self.response.out.write("in edit-post post method")


class Signup(MainHandler):
    def get(self):
        if not utils.is_loggedIn(self):
            self.render("signup-form.html")
        else:
            self.redirect('/welcome')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not utils.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not utils.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not utils.valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'This user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(MainHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        remember = self.request.get('remember')

        u = User.login(username, password)
        if u:
            self.login(u, remember)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/welcome')


class WelcomeHandler(MainHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name,
                        is_logged_in=True)
        else:
            self.redirect('/login')


class PostHandler(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPostHandler(Handler):
    def get(self):
        if utils.is_loggedIn(self):
            self.render("newpost.html", is_logged_in=True)
        else:
            self.redirect('/login')

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def post(self):
        if utils.is_loggedIn(self):
            subject = self.request.get("subject")
            content = self.request.get("content")
            if subject and content:
                post = Post(subject=subject, content=content,
                            user_id=utils.get_userID(self))
                post.put()
                self.redirect('/blog')
            else:
                message = "something is missing!"
                self.render("newpost.html", subject=subject,
                            content=content, error=message, is_logged_in=True)


app = webapp2.WSGIApplication([
    ('/blog/?', MainHandler),
    ('/blog/([0-9]+)', PostHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/edit-comment', EditComment),
    ('/blog/edit-post', EditPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', WelcomeHandler),
], debug=True)
