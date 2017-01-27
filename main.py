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

def buildPage():
    content = '''
        <!DOCTYPE html>
        <html>
            <head>
                <title>User Signup</title>
                <style media="screen">
                    .error{
                        color: red;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <h1>User Signup Page</h1>
                <form method="post">
                    <table>
                        <tr>
                            <td><label for="username">Username</label></td>
                            <td><input type="text" name="username" required><span class="error"></span></td>
                        </tr>
                        <tr>
                            <td><label for="password">Password</label></td>
                            <td><input type="password" name="password" required><span class="error"></span></td>
                        </tr>
                        <tr>
                            <td><label for="verifypassword">Verify Password</label></td>
                            <td><input type="password" name="verifypassword" required><span class="error"></span></td>
                        </tr>
                        <tr>
                            <td><label for="email">Email</label></td>
                            <td><input type="email" name="email" value=""><span class="error"></span></td>
                        </tr>
                    </table>
                        <input type="submit">
                </form>
            </body>
        </html>
    '''
    return content;

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(buildPage());

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
