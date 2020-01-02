# ItemCatalog

## About The Project:
The Project is an application(Website) that show items and their corresponding categories and allows users to  manage (add,edit,delete..) these items and categories.
OAuth 2.0 is used as an authentication system. Registered users will have the ability to post, edit and delete their own items only.

## Instructions

### Clone the repository <br>


### Getting Google Credentials
The Google sign in needs to be enabled by following these steps :

1-Go to [Google Dev Console](https://console.developers.google.com) <br>
2-Sign up or Login in.<br>
3-Go to Credentials.<br>
4-Select Create Crendentials -> OAuth Client ID.<br>
5-Select Web application. <br>
6-Enter name 'My Project'.<br>
7-Authorized JavaScript origins = 'http://localhost:8000' .<br>
8-Create.<br>
9-Copy the Client ID and paste it in clientid in login.html in the templates folder .<br>
10-Authorized redirect URIs = 'http://localhost:8000/login' and 'http://localhost:8000/gconnect' and save it.<br>
11-On the Dev Console Select Download JSON .<br>
12-Rename JSON file to client_secrets.json .<br>
13-Place JSON file in your directory where project.py is located.<br>
14-Run project.py from terminal <br>
15-Go to localhost:8000/ <br>
16-Enjoy :) <br>

![](gif.gif)





