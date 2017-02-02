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
import webapp2;
import re;
import cgi;

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$");
def validUsername(username):
    return USER_RE.match(username);

PASSWORD_RE = re.compile(r"^.{3,20}$");
def validPassword(password):
    return PASSWORD_RE.match(password);

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$");
def validEmail(email):
    return EMAIL_RE.match(email);

def buildPage(usernameError="", passwordError="", verifyError="", emailError=""):
    content = '''
        <!DOCTYPE html>
        <html>
            <head>
                <title>User Signup</title>
                <style>
                    .error{{
                        color: red;
                        font-weight: bold;
                    }}
                </style>
            </head>
            <body>
                <h1>User Signup Page</h1>
                <form method="post">
                    <table>
                        <tr>
                            <td><label for="username">Username</label></td>
                            <td><input type="text" name="username" required><span class="error">{u}</span></td>
                        </tr>
                        <tr>
                            <td><label for="password">Password</label></td>
                            <td><input type="password" name="password" required><span class="error">{p}</span></td>
                        </tr>
                        <tr>
                            <td><label for="verifypassword">Verify Password</label></td>
                            <td><input type="password" name="verify" required><span class="error">{v}</span></td>
                        </tr>
                        <tr>
                            <td><label for="email">Email</label></td>
                            <td><input type="text" name="email" value=""><span class="error">{e}</span></td>
                        </tr>
                    </table>
                        <input type="submit">
                </form>
            </body>
        </html>
    '''.format(u=usernameError, p=passwordError, v=verifyError, e=emailError);
    return content;

class MainHandler(webapp2.RequestHandler):
    def get(self):

        self.response.write(buildPage());

    def post(self):
        username = self.request.get('username');
        password = self.request.get('password');
        verify = self.request.get('verify');
        email = self.request.get('email');

        if (validUsername(username) and validPassword(password) and validPassword(verify) and password == verify):
            self.redirect('/success?username=' + username);

        if not validUsername(username):
            usernameError = 'Invalid username';
        else:
            usernameError = '';

        if validPassword(password):
            if password != verify:
                verifyError = "Passwords do not match";
                passwordError = "";
            else:
                verifyError = "";
                passwordError = "Invalid password";
        elif not validPassword(password):
            verifyError = "";
            passwordError = "Invalid password";

        if email:
            if not validEmail(email):
                emailError = "Invalid email";
            else:
                emailError = "";
        else:
            emailError = "";

        self.response.write(buildPage(usernameError=usernameError, passwordError=passwordError, verifyError=verifyError, emailError=emailError));

class SuccessHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username');

        content = '''
        <h1>Thanks for signing up, {u}! You're my best friend</h1>
        '''.format(u=username);

        self.response.write(content);

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/success', SuccessHandler)
], debug=True)
